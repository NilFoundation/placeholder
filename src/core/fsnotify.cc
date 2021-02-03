/*
 * This file is open source software, licensed to you under the terms
 * of the Apache License, Version 2.0 (the "License").  See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership.  You may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/*
 * Copyright 2020 ScyllaDB Ltd.
 */

#include <nil/actor/core/posix.hh>
#include <nil/actor/core/reactor.hh>

#include <nil/actor/core/detail/pollable_fd.hh>
#include <nil/actor/core/detail/fsnotify.hh>

class nil::actor::fsnotifier::impl : public enable_shared_from_this<impl> {
    class my_poll_fd : public pollable_fd {
    public:
        using pollable_fd::get_fd;
        using pollable_fd::pollable_fd;

        operator int() const {
            return get_fd();
        }
    };
    my_poll_fd _fd;
    watch_token _close_dummy = -1;

public:
    impl() : _fd(file_desc::inotify_init(IN_NONBLOCK | IN_CLOEXEC)) {
    }
    void remove_watch(watch_token);
    future<watch_token> create_watch(const sstring &path, flags events);
    future<std::vector<event>> wait();
    void shutdown();
    bool active() const {
        return bool(_fd);
    }
};

void nil::actor::fsnotifier::impl::remove_watch(watch_token token) {
    if (active()) {
        auto res = ::inotify_rm_watch(_fd, token);
        // throw if any other error than EINVAL.
        throw_system_error_on(res == -1 && errno != EINVAL, "could not remove inotify watch");
    }
}

nil::actor::future<nil::actor::fsnotifier::watch_token> nil::actor::fsnotifier::impl::create_watch(const sstring &path,
                                                                                          flags events) {
    if (!active()) {
        throw std::runtime_error("attempting to use closed notifier");
    }
    return engine().inotify_add_watch(_fd, path, uint32_t(events));
}

nil::actor::future<std::vector<nil::actor::fsnotifier::event>> nil::actor::fsnotifier::impl::wait() {
    // be paranoid about buffer alignment
    auto buf = temporary_buffer<char>::aligned(std::max(alignof(::inotify_event), alignof(int64_t)), 4096);
    auto f = _fd.read_some(buf.get_write(), buf.size());
    return f.then([me = shared_from_this(), buf = std::move(buf)](size_t n) {
        auto p = buf.get();
        auto e = buf.get() + n;

        std::vector<event> events;

        while (p < e) {
            auto ev = reinterpret_cast<const ::inotify_event *>(p);
            if (ev->wd == me->_close_dummy && me->_close_dummy != -1) {
                me->_fd.close();
            } else {
                events.emplace_back(
                    event {ev->wd, flags(ev->mask), ev->cookie, ev->len != 0 ? sstring(ev->name) : sstring {}});
            }
            p += sizeof(::inotify_event) + ev->len;
        }

        return events;
    });
}

void nil::actor::fsnotifier::impl::shutdown() {
    // reactor does not yet have
    // any means of "shutting down" a non-socket read,
    // so we work around this by creating a watch for something ubiquitous,
    // then removing the watch while adding a mark.
    // This will cause any event waiter to wake up, but ignore the event for our
    // dummy.
    (void)create_watch("/", flags::delete_self).then([me = shared_from_this()](watch_token t) {
        me->_close_dummy = t;
        me->remove_watch(t);
    });
}

nil::actor::fsnotifier::watch::~watch() {
    if (_impl) {
        _impl->remove_watch(_token);
    }
}

nil::actor::fsnotifier::watch::watch(watch &&) noexcept = default;
nil::actor::fsnotifier::watch &nil::actor::fsnotifier::watch::operator=(watch &&) noexcept = default;

nil::actor::fsnotifier::watch_token nil::actor::fsnotifier::watch::release() {
    _impl = {};
    return _token;
}

nil::actor::fsnotifier::watch::watch(shared_ptr<impl> impl, watch_token token) : _token(token), _impl(std::move(impl)) {
}

nil::actor::fsnotifier::fsnotifier() : _impl(make_shared<impl>()) {
}

nil::actor::fsnotifier::~fsnotifier() = default;

nil::actor::fsnotifier::fsnotifier(fsnotifier &&) = default;
nil::actor::fsnotifier &nil::actor::fsnotifier::operator=(fsnotifier &&) = default;

nil::actor::future<nil::actor::fsnotifier::watch> nil::actor::fsnotifier::create_watch(const sstring &path, flags events) {
    return _impl->create_watch(path, events).then([this](watch_token token) { return watch(_impl, token); });
}

nil::actor::future<std::vector<nil::actor::fsnotifier::event>> nil::actor::fsnotifier::wait() const {
    return _impl->wait();
}

void nil::actor::fsnotifier::shutdown() {
    _impl->shutdown();
}

bool nil::actor::fsnotifier::active() const {
    return _impl->active();
}
