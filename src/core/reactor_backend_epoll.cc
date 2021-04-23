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

#include <nil/actor/core/detail/reactor_backend_epoll.hh>
#include <nil/actor/core/detail/thread_pool.hh>
#include <nil/actor/core/detail/syscall_result.hh>
#include <nil/actor/core/print.hh>
#include <nil/actor/core/reactor.hh>
#include <nil/actor/core/detail/buffer_allocator.hh>

#include <nil/actor/detail/defer.hh>
#include <nil/actor/detail/read_first_line.hh>

#include <chrono>

namespace nil {
    namespace actor {

        using namespace std::chrono_literals;
        using namespace detail;
        using namespace detail::linux_abi;

        reactor_backend_epoll::reactor_backend_epoll(reactor *r) :
            _r(r), _epollfd(file_desc::epoll_create(EPOLL_CLOEXEC))
#if BOOST_OS_LINUX
            ,
            _storage_context(_r)
#endif

        {
            ::epoll_event event;
            event.events = EPOLLIN;
            event.data.ptr = nullptr;
            auto ret = ::epoll_ctl(_epollfd.get(), EPOLL_CTL_ADD, _r->_notify_eventfd.get(), &event);
            throw_system_error_on(ret == -1);

#if BOOST_OS_LINUX
            struct sigevent sev { };
            sev.sigev_notify = SIGEV_THREAD_ID;
            sev._sigev_un._tid = syscall(SYS_gettid);
            sev.sigev_signo = hrtimer_signal();
            ret = timer_create(CLOCK_MONOTONIC, &sev, &_steady_clock_timer);
            assert(ret >= 0);
#elif BOOST_OS_MACOS || BOOST_OS_IOS
            _steady_clock_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
            if (_steady_clock_timer) {
                dispatch_source_set_timer(_steady_clock_timer, dispatch_walltime(NULL, 0), 1ull * NSEC_PER_SEC, 0);
                dispatch_source_set_event_handler(_steady_clock_timer, ^{
                    raise(hrtimer_signal());
                });
                dispatch_resume(_steady_clock_timer);
            }

#endif

            _r->_signals.handle_signal(hrtimer_signal(), [r = _r] { r->service_highres_timer(); });
        }

        reactor_backend_epoll::~reactor_backend_epoll() {
#if BOOST_OS_LINUX
            timer_delete(_steady_clock_timer);
#elif BOOST_OS_MACOS || BOOST_OS_IOS
            dispatch_source_cancel(_steady_clock_timer);
#endif
        }

        void reactor_backend_epoll::start_tick() {
            _task_quota_timer_thread = std::thread(&reactor::task_quota_timer_thread_fn, _r);

            ::sched_param sp;
            sp.sched_priority = 1;
            auto sched_ok = pthread_setschedparam(_task_quota_timer_thread.native_handle(), SCHED_FIFO, &sp);
            if (sched_ok != 0 && _r->_id == 0) {
                seastar_logger.warn(
                    "Unable to set SCHED_FIFO scheduling policy for timer thread; latency impact possible. Try adding "
                    "CAP_SYS_NICE");
            }
        }

        void reactor_backend_epoll::stop_tick() {
            _r->_dying.store(true, std::memory_order_relaxed);
            _r->_task_quota_timer.timerfd_settime(
                0, nil::actor::posix::to_relative_itimerspec(1ns, 1ms));    // Make the timer fire soon
            _task_quota_timer_thread.join();
        }

        void reactor_backend_epoll::arm_highres_timer(const ::itimerspec &its) {
#if BOOST_OS_LINUX
            auto ret = timer_settime(_steady_clock_timer, TIMER_ABSTIME, &its, NULL);
            throw_system_error_on(ret == -1);
#elif BOOST_OS_MACOS || BOOST_OS_IOS

#endif
        }

        bool reactor_backend_epoll::wait_and_process(int timeout, const sigset_t *active_sigmask) {
            std::array<epoll_event, 128> eevt;
            int nr = ::epoll_pwait(_epollfd.get(), eevt.data(), eevt.size(), timeout, active_sigmask);
            if (nr == -1 && errno == EINTR) {
                return false;    // gdb can cause this
            }
            assert(nr != -1);
            for (int i = 0; i < nr; ++i) {
                auto &evt = eevt[i];
                auto pfd = reinterpret_cast<pollable_fd_state *>(evt.data.ptr);
                if (!pfd) {
                    char dummy[8];
                    _r->_notify_eventfd.read(dummy, 8);
                    continue;
                }
                if (evt.events & (EPOLLHUP | EPOLLERR)) {
                    // treat the events as required events when error occurs, let
                    // send/recv/accept/connect handle the specific error.
                    evt.events = pfd->events_requested;
                }
                auto events = evt.events & (EPOLLIN | EPOLLOUT);
                auto events_to_remove = events & ~pfd->events_requested;
                if (pfd->events_rw) {
                    // accept() signals normal completions via EPOLLIN, but errors (due to shutdown())
                    // via EPOLLOUT|EPOLLHUP, so we have to wait for both EPOLLIN and EPOLLOUT with the
                    // same future
                    complete_epoll_event(*pfd, events, EPOLLIN | EPOLLOUT);
                } else {
                    // Normal processing where EPOLLIN and EPOLLOUT are waited for via different
                    // futures.
                    complete_epoll_event(*pfd, events, EPOLLIN);
                    complete_epoll_event(*pfd, events, EPOLLOUT);
                }
                if (events_to_remove) {
                    pfd->events_epoll &= ~events_to_remove;
                    evt.events = pfd->events_epoll;
                    auto op = evt.events ? EPOLL_CTL_MOD : EPOLL_CTL_DEL;
                    ::epoll_ctl(_epollfd.get(), op, pfd->fd.get(), &evt);
                }
            }
            return nr;
        }

        bool reactor_backend_epoll::reap_kernel_completions() {
#if BOOST_OS_LINUX
            // epoll does not have a separate submission stage, and just
            // calls epoll_ctl everytime it needs, so this method and
            // kernel_submit_work are essentially the same. Ordering also
            // doesn't matter much. wait_and_process is actually completing,
            // but we prefer to call it in kernel_submit_work because the
            // reactor register two pollers for completions and one for submission,
            // since completion is cheaper for other backends like aio. This avoids
            // calling epoll_wait twice.
            //
            // We will only reap the io completions
            return _storage_context.reap_completions();
#endif
            return true;
        }

        bool reactor_backend_epoll::kernel_submit_work() {
#if BOOST_OS_LINUX
            _storage_context.submit_work();
#endif
            if (_need_epoll_events) {
                return wait_and_process(0, nullptr);
            }
            return false;
        }

        bool reactor_backend_epoll::kernel_events_can_sleep() const {
#if BOOST_OS_LINUX
            return _storage_context.can_sleep();
#endif
            return true;
        }

        void reactor_backend_epoll::wait_and_process_events(const sigset_t *active_sigmask) {
            wait_and_process(-1, active_sigmask);
        }

        void reactor_backend_epoll::complete_epoll_event(pollable_fd_state &pfd, int events, int event) {
            if (pfd.events_requested & events & event) {
                pfd.events_requested &= ~event;
                pfd.events_known &= ~event;
                auto *fd = static_cast<epoll_pollable_fd_state *>(&pfd);
                return fd->complete_with(event);
            }
        }

        void reactor_backend_epoll::signal_received(int signo, siginfo_t *siginfo, void *ignore) {
            if (engine_is_ready()) {
                engine()._signals.action(signo, siginfo, ignore);
            } else {
                reactor::signals::failed_to_handle(signo);
            }
        }

        future<> reactor_backend_epoll::get_epoll_future(pollable_fd_state &pfd, int event) {
            if (pfd.events_known & event) {
                pfd.events_known &= ~event;
                return make_ready_future();
            }
            pfd.events_rw = event == (EPOLLIN | EPOLLOUT);
            pfd.events_requested |= event;
            if ((pfd.events_epoll & event) != event) {
                auto ctl = pfd.events_epoll ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
                pfd.events_epoll |= event;
                ::epoll_event eevt;
                eevt.events = pfd.events_epoll;
                eevt.data.ptr = &pfd;
                int r = ::epoll_ctl(_epollfd.get(), ctl, pfd.fd.get(), &eevt);
                assert(r == 0);
                _need_epoll_events = true;
            }

            auto *fd = static_cast<epoll_pollable_fd_state *>(&pfd);
            return fd->get_completion_future(event);
        }

        future<> reactor_backend_epoll::readable(pollable_fd_state &fd) {
            return get_epoll_future(fd, EPOLLIN);
        }

        future<> reactor_backend_epoll::writeable(pollable_fd_state &fd) {
            return get_epoll_future(fd, EPOLLOUT);
        }

        future<> reactor_backend_epoll::readable_or_writeable(pollable_fd_state &fd) {
            return get_epoll_future(fd, EPOLLIN | EPOLLOUT);
        }

        void reactor_backend_epoll::forget(pollable_fd_state &fd) noexcept {
            if (fd.events_epoll) {
                ::epoll_ctl(_epollfd.get(), EPOLL_CTL_DEL, fd.fd.get(), nullptr);
            }
            auto *efd = static_cast<epoll_pollable_fd_state *>(&fd);
            delete efd;
        }

        future<std::tuple<pollable_fd, socket_address>> reactor_backend_epoll::accept(pollable_fd_state &listenfd) {
            return engine().do_accept(listenfd);
        }

        future<> reactor_backend_epoll::connect(pollable_fd_state &fd, socket_address &sa) {
            return engine().do_connect(fd, sa);
        }

        void reactor_backend_epoll::shutdown(pollable_fd_state &fd, int how) {
            fd.fd.shutdown(how);
        }

        future<size_t> reactor_backend_epoll::read_some(pollable_fd_state &fd, void *buffer, size_t len) {
            return engine().do_read_some(fd, buffer, len);
        }

        future<size_t> reactor_backend_epoll::read_some(pollable_fd_state &fd, const std::vector<iovec> &iov) {
            return engine().do_read_some(fd, iov);
        }

        future<temporary_buffer<char>> reactor_backend_epoll::read_some(pollable_fd_state &fd,
                                                                        detail::buffer_allocator *ba) {
            return engine().do_read_some(fd, ba);
        }

        future<size_t> reactor_backend_epoll::write_some(pollable_fd_state &fd, const void *buffer, size_t len) {
            return engine().do_write_some(fd, buffer, len);
        }

        future<size_t> reactor_backend_epoll::write_some(pollable_fd_state &fd, net::packet &p) {
            return engine().do_write_some(fd, p);
        }

        void reactor_backend_epoll::request_preemption() {
            _r->_preemption_monitor.head.store(1, std::memory_order_relaxed);
        }

        void reactor_backend_epoll::start_handling_signal() {
            // The epoll backend uses signals for the high resolution timer. That is used for thread_scheduling_group,
            // so we request preemption so when we receive a signal.
            request_preemption();
        }

        pollable_fd_state_ptr reactor_backend_epoll::make_pollable_fd_state(file_desc fd,
                                                                            pollable_fd::speculation speculate) {
            return pollable_fd_state_ptr(new epoll_pollable_fd_state(std::move(fd), std::move(speculate)));
        }

        void reactor_backend_epoll::reset_preemption_monitor() {
            _r->_preemption_monitor.head.store(0, std::memory_order_relaxed);
        }
    }    // namespace actor
}    // namespace nil
