//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#include <nil/actor/blocking_actor.hpp>

#include <utility>

#include <nil/actor/actor_registry.hpp>
#include <nil/actor/spawner.hpp>
#include <nil/actor/detail/default_invoke_result_visitor.hpp>
#include <nil/actor/detail/invoke_result_visitor.hpp>
#include <nil/actor/detail/set_thread_name.hpp>
#include <nil/actor/detail/sync_request_bouncer.hpp>
#include <nil/actor/logger.hpp>

namespace nil {
    namespace actor {

        blocking_actor::receive_cond::~receive_cond() {
            // nop
        }

        bool blocking_actor::receive_cond::pre() {
            return true;
        }

        bool blocking_actor::receive_cond::post() {
            return true;
        }

        blocking_actor::accept_one_cond::~accept_one_cond() {
            // nop
        }

        bool blocking_actor::accept_one_cond::post() {
            return false;
        }

        blocking_actor::blocking_actor(actor_config &cfg) :
            super(cfg.add_flag(local_actor::is_blocking_flag)), mailbox_(unit, unit, unit) {
            // nop
        }

        blocking_actor::~blocking_actor() {
            // avoid weak-vtables warning
        }

        void blocking_actor::enqueue(mailbox_element_ptr ptr, execution_unit *) {
            ACTOR_ASSERT(ptr != nullptr);
            ACTOR_ASSERT(getf(is_blocking_flag));
            ACTOR_LOG_TRACE(ACTOR_ARG(*ptr));
            ACTOR_LOG_SEND_EVENT(ptr);
            auto mid = ptr->mid;
            auto src = ptr->sender;
            // returns false if mailbox has been closed
            if (!mailbox().synchronized_push_back(mtx_, cv_, std::move(ptr))) {
                ACTOR_LOG_REJECT_EVENT();
                if (mid.is_request()) {
                    detail::sync_request_bouncer srb {exit_reason()};
                    srb(src, mid);
                }
            } else {
                ACTOR_LOG_ACCEPT_EVENT(false);
            }
        }

        mailbox_element *blocking_actor::peek_at_next_mailbox_element() {
            return mailbox().closed() || mailbox().blocked() ? nullptr : mailbox().peek();
        }

        const char *blocking_actor::name() const {
            return "blocking_actor";
        }

        void blocking_actor::launch(execution_unit *, bool, bool hide) {
            ACTOR_PUSH_AID_FROM_PTR(this);
            ACTOR_LOG_TRACE(ACTOR_ARG(hide));
            ACTOR_ASSERT(getf(is_blocking_flag));
            if (!hide)
                register_at_system();
            home_system().inc_detached_threads();
            std::thread(
                [](strong_actor_ptr ptr) {
                    // actor lives in its own thread
                    detail::set_thread_name("actor.actor");
                    ptr->home_system->thread_started();
                    auto this_ptr = ptr->get();
                    ACTOR_ASSERT(dynamic_cast<blocking_actor *>(this_ptr) != nullptr);
                    auto self = static_cast<blocking_actor *>(this_ptr);
                    ACTOR_SET_LOGGER_SYS(ptr->home_system);
                    ACTOR_PUSH_AID_FROM_PTR(self);
                    self->initialize();
                    error rsn;
#ifndef ACTOR_NO_EXCEPTIONS
                    try {
                        self->act();
                        rsn = self->fail_state_;
                    } catch (...) {
                        rsn = exit_reason::unhandled_exception;
                    }
                    try {
                        self->on_exit();
                    } catch (...) {
                        // simply ignore exception
                    }
#else
                    self->act();
                    rsn = self->fail_state_;
                    self->on_exit();
#endif
                    self->cleanup(std::move(rsn), self->context());
                    ptr->home_system->thread_terminates();
                    ptr->home_system->dec_detached_threads();
                },
                strong_actor_ptr {ctrl()})
                .detach();
        }

        blocking_actor::receive_while_helper blocking_actor::receive_while(std::function<bool()> stmt) {
            return {this, std::move(stmt)};
        }

        blocking_actor::receive_while_helper blocking_actor::receive_while(const bool &ref) {
            return receive_while([&] { return ref; });
        }

        void blocking_actor::await_all_other_actors_done() {
            system().registry().await_running_count_equal(getf(is_registered_flag) ? 1 : 0);
        }

        void blocking_actor::act() {
            ACTOR_LOG_TRACE("");
            if (initial_behavior_fac_)
                initial_behavior_fac_(this);
        }

        void blocking_actor::fail_state(error err) {
            fail_state_ = std::move(err);
        }

        intrusive::task_result blocking_actor::mailbox_visitor::operator()(mailbox_element &x) {
            ACTOR_LOG_TRACE(ACTOR_ARG(x));
            ACTOR_LOG_RECEIVE_EVENT((&x));
            auto check_if_done = [&]() -> intrusive::task_result {
                // Stop consuming items when reaching the end of the user-defined receive
                // loop either via post or pre condition.
                if (rcc.post() && rcc.pre())
                    return intrusive::task_result::resume;
                done = true;
                return intrusive::task_result::stop;
            };
            // Skip messages that don't match our message ID.
            if (mid.is_response()) {
                if (mid != x.mid) {
                    ACTOR_LOG_SKIP_EVENT();
                    return intrusive::task_result::skip;
                }
            } else if (x.mid.is_response()) {
                ACTOR_LOG_SKIP_EVENT();
                return intrusive::task_result::skip;
            }
            // Automatically unlink from actors after receiving an exit.
            if (x.content().match_elements<exit_msg>())
                self->unlink_from(x.content().get_as<exit_msg>(0).source);
            // Blocking actors can nest receives => push/pop `current_element_`
            auto prev_element = self->current_element_;
            self->current_element_ = &x;
            auto g = detail::make_scope_guard([&] { self->current_element_ = prev_element; });
            // Dispatch on x.
            detail::default_invoke_result_visitor<blocking_actor> visitor {self};
            switch (bhvr.nested(visitor, x.content())) {
                default:
                    return check_if_done();
                case match_case::no_match: {    // Blocking actors can have fallback handlers for catch-all rules.
                    auto sres = bhvr.fallback(*self->current_element_);
                    if (sres.flag != rt_skip) {
                        visitor.visit(sres);
                        ACTOR_LOG_FINALIZE_EVENT();
                        return check_if_done();
                    }
                }
                    // Response handlers must get re-invoked with an error when receiving an
                    // unexpected message.
                    if (mid.is_response()) {
                        auto err = make_error(sec::unexpected_response, x.move_content_to_message());
                        mailbox_element_view<error> tmp {std::move(x.sender), x.mid, std::move(x.stages), err};
                        self->current_element_ = &tmp;
                        bhvr.nested(tmp.content());
                        ACTOR_LOG_FINALIZE_EVENT();
                        return check_if_done();
                    }
                    ACTOR_ANNOTATE_FALLTHROUGH;
                case match_case::skip:
                    ACTOR_LOG_SKIP_EVENT();
                    return intrusive::task_result::skip;
            }
        }

        void blocking_actor::receive_impl(receive_cond &rcc, message_id mid, detail::blocking_behavior &bhvr) {
            ACTOR_LOG_TRACE(ACTOR_ARG(mid));
            // Set to `true` by the visitor when done.
            bool done = false;
            // Make sure each receive sees all mailbox elements.
            mailbox_visitor f {this, done, rcc, mid, bhvr};
            mailbox().flush_cache();
            // Check pre-condition once before entering the message consumption loop. The
            // consumer performs any future check on pre and post conditions via
            // check_if_done.
            if (!rcc.pre())
                return;
            // Read incoming messages for as long as the user's receive loop accepts more
            // messages.
            do {
                // Reset the timeout each iteration.
                auto rel_tout = bhvr.timeout();
                if (!rel_tout.valid()) {
                    await_data();
                } else {
                    auto abs_tout = std::chrono::high_resolution_clock::now();
                    abs_tout += rel_tout;
                    if (!await_data(abs_tout)) {
                        // Short-circuit "loop body".
                        bhvr.handle_timeout();
                        if (rcc.post() && rcc.pre())
                            continue;
                        else
                            return;
                    }
                }
                mailbox_.new_round(3, f);
            } while (!done);
        }

        void blocking_actor::await_data() {
            mailbox().synchronized_await(mtx_, cv_);
        }

        bool blocking_actor::await_data(timeout_type timeout) {
            return mailbox().synchronized_await(mtx_, cv_, timeout);
        }

        mailbox_element_ptr blocking_actor::dequeue() {
            mailbox().flush_cache();
            await_data();
            mailbox().fetch_more();
            auto &qs = mailbox().queue().queues();
            auto result = get<mailbox_policy::urgent_queue_index>(qs).take_front();
            if (!result)
                result = get<mailbox_policy::normal_queue_index>(qs).take_front();
            ACTOR_ASSERT(result != nullptr);
            return result;
        }

        void blocking_actor::varargs_tup_receive(receive_cond &rcc, message_id mid, std::tuple<behavior &> &tup) {
            using namespace detail;
            auto &bhvr = std::get<0>(tup);
            if (bhvr.timeout().valid()) {
                auto tmp = after(bhvr.timeout()) >> [&] { bhvr.handle_timeout(); };
                auto fun = make_blocking_behavior(&bhvr, std::move(tmp));
                receive_impl(rcc, mid, fun);
            } else {
                auto fun = make_blocking_behavior(&bhvr);
                receive_impl(rcc, mid, fun);
            }
        }

        sec blocking_actor::build_pipeline(stream_slot, stream_slot, stream_manager_ptr) {
            ACTOR_LOG_ERROR("blocking_actor::build_pipeline called");
            return sec::bad_function_call;
        }

        size_t blocking_actor::attach_functor(const actor &x) {
            return attach_functor(actor_cast<strong_actor_ptr>(x));
        }

        size_t blocking_actor::attach_functor(const actor_addr &x) {
            return attach_functor(actor_cast<strong_actor_ptr>(x));
        }

        size_t blocking_actor::attach_functor(const strong_actor_ptr &ptr) {
            using wait_for_atom = atom_constant<atom("waitFor")>;
            if (!ptr)
                return 0;
            actor self {this};
            ptr->get()->attach_functor([=](const error &) { anon_send(self, wait_for_atom::value); });
            return 1;
        }

        bool blocking_actor::cleanup(error &&fail_state, execution_unit *host) {
            if (!mailbox_.closed()) {
                mailbox_.close();
                // TODO: messages that are stuck in the cache can get lost
                detail::sync_request_bouncer bounce {fail_state};
                while (mailbox_.queue().new_round(1000, bounce).consumed_items)
                    ;    // nop
            }
            // Dispatch to parent's `cleanup` function.
            return super::cleanup(std::move(fail_state), host);
        }

    }    // namespace actor
}    // namespace nil
