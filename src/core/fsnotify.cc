//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the Server Side Public License, version 1,
// as published by the author.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// Server Side Public License for more details.
//
// You should have received a copy of the Server Side Public License
// along with this program. If not, see
// <https://github.com/NilFoundation/dbms/blob/master/LICENSE_1_0.txt>.
//---------------------------------------------------------------------------//

#include <nil/actor/core/posix.hh>
#include <nil/actor/core/reactor.hh>

#include <nil/actor/core/detail/pollable_fd.hh>
#include <nil/actor/core/detail/fsnotify.hh>

namespace nil {
    namespace actor {
        class fsnotifier::impl : public enable_shared_from_this<impl> {
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

        void fsnotifier::impl::remove_watch(watch_token token) {
            if (active()) {
                auto res = ::inotify_rm_watch(_fd, token);
                // throw if any other error than EINVAL.
                throw_system_error_on(res == -1 && errno != EINVAL, "could not remove inotify watch");
            }
        }

        future<fsnotifier::watch_token> fsnotifier::impl::create_watch(const sstring &path, flags events) {
            if (!active()) {
                throw std::runtime_error("attempting to use closed notifier");
            }
            return engine().inotify_add_watch(_fd, path, uint32_t(events));
        }

        future<std::vector<fsnotifier::event>> fsnotifier::impl::wait() {
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

        void fsnotifier::impl::shutdown() {
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

        fsnotifier::watch::~watch() {
            if (_impl) {
                _impl->remove_watch(_token);
            }
        }

        fsnotifier::watch::watch(watch &&) noexcept = default;
        fsnotifier::watch &fsnotifier::watch::operator=(watch &&) noexcept = default;

        fsnotifier::watch_token fsnotifier::watch::release() {
            _impl = {};
            return _token;
        }

        fsnotifier::watch::watch(shared_ptr<impl> impl, watch_token token) : _token(token), _impl(std::move(impl)) {
        }

        fsnotifier::fsnotifier() : _impl(make_shared<impl>()) {
        }

        fsnotifier::~fsnotifier() = default;

        fsnotifier::fsnotifier(fsnotifier &&) = default;
        fsnotifier &fsnotifier::operator=(fsnotifier &&) = default;

        future<fsnotifier::watch> fsnotifier::create_watch(const sstring &path, flags events) {
            return _impl->create_watch(path, events).then([this](watch_token token) { return watch(_impl, token); });
        }

        future<std::vector<fsnotifier::event>> fsnotifier::wait() const {
            return _impl->wait();
        }

        void fsnotifier::shutdown() {
            _impl->shutdown();
        }

        bool fsnotifier::active() const {
            return _impl->active();
        }
    }    // namespace actor
}    // namespace nil
