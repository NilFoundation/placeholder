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

#pragma once

#include <tuple>
#include <chrono>

#include <nil/actor/actor.hpp>
#include <nil/actor/actor_cast.hpp>
#include <nil/actor/actor_clock.hpp>
#include <nil/actor/actor_control_block.hpp>
#include <nil/actor/check_typed_input.hpp>
#include <nil/actor/duration.hpp>
#include <nil/actor/no_stages.hpp>
#include <nil/actor/response_type.hpp>
#include <nil/actor/response_handle.hpp>
#include <nil/actor/fwd.hpp>
#include <nil/actor/message.hpp>
#include <nil/actor/message_priority.hpp>
#include <nil/actor/no_stages.hpp>
#include <nil/actor/response_handle.hpp>
#include <nil/actor/response_type.hpp>
#include <nil/actor/send.hpp>

#include <nil/actor/scheduler/abstract_coordinator.hpp>

namespace nil {
    namespace actor {
        namespace mixin {

            /// A `sender` is an actor that supports `self->send(...)`.
            template<class Base, class Subtype>
            class sender : public Base {
            public:
                // -- member types -----------------------------------------------------------

                using extended_base = sender;

                // -- constructors, destructors, and assignment operators --------------------

                template<class... Ts>
                sender(Ts &&... xs) : Base(std::forward<Ts>(xs)...) {
                    // nop
                }

                // -- send function family ---------------------------------------------------

                /// Sends `{xs...}` as an asynchronous message to `dest` with priority `mp`.
                template<message_priority P = message_priority::normal, class Dest = actor, class... Ts>
                void send(const Dest &dest, Ts &&... xs) {
                    detail::type_list<detail::strip_and_convert_t<Ts>...> args_token;
                    type_check(dest, args_token);
                    if (dest)
                        dest->eq_impl(make_message_id(P), dptr()->ctrl(), dptr()->context(), std::forward<Ts>(xs)...);
                }

                /// Sends `{xs...}` as an asynchronous message to `dest` with priority `mp`.
                template<message_priority P = message_priority::normal, class... Ts>
                void send(const strong_actor_ptr &dest, Ts &&... xs) {
                    using detail::type_list;
                    static_assert(sizeof...(Ts) > 0, "no message to send");
                    static_assert(!statically_typed<Subtype>(),
                                  "statically typed actors can only send() to other "
                                  "statically typed actors; use anon_send() or request() when "
                                  "communicating with dynamically typed actors");
                    if (dest)
                        dest->get()->eq_impl(make_message_id(P), dptr()->ctrl(), dptr()->context(),
                                             std::forward<Ts>(xs)...);
                }

                template<message_priority P = message_priority::normal, class Dest = actor, class... Ts>
                void anon_send(const Dest &dest, Ts &&... xs) {
                    nil::actor::anon_send(dest, std::forward<Ts>(xs)...);
                }

                /// Sends a message after an absolute timeout.
                template<message_priority P = message_priority::normal, class Dest = actor, class... Ts>
                typename std::enable_if<!std::is_same<Dest, group>::value>::type
                    scheduled_send(const Dest &dest, actor_clock::time_point timeout, Ts &&... xs) {
                    detail::type_list<detail::strip_and_convert_t<Ts>...> args_token;
                    type_check(dest, args_token);
                    if (dest) {
                        auto &clock = dptr()->system().clock();
                        clock.schedule_message(timeout, actor_cast<strong_actor_ptr>(dest),
                                               make_mailbox_element(dptr()->ctrl(), make_message_id(P), no_stages,
                                                                    std::forward<Ts>(xs)...));
                    }
                }

                /// Sends a message after an absolute timeout. Sends the message immediately
                /// if the timeout has already past.
                template<class... Ts>
                void scheduled_send(const group &dest, actor_clock::time_point timeout, Ts &&... xs) {
                    static_assert(!statically_typed<Subtype>(),
                                  "statically typed actors are not allowed to send to groups");
                    if (dest) {
                        auto &clock = dptr()->system().clock();
                        clock.schedule_message(timeout, dest, dptr()->ctrl(), make_message(std::forward<Ts>(xs)...));
                    }
                }

                /// Sends a message after a relative timeout.
                template<message_priority P = message_priority::normal, class Rep = int, class Period = std::ratio<1>,
                         class Dest = actor, class... Ts>
                typename std::enable_if<!std::is_same<Dest, group>::value>::type
                    delayed_send(const Dest &dest, std::chrono::duration<Rep, Period> rel_timeout, Ts &&... xs) {
                    detail::type_list<detail::strip_and_convert_t<Ts>...> args_token;
                    type_check(dest, args_token);
                    if (dest) {
                        auto &clock = dptr()->system().clock();
                        auto timeout = clock.now() + rel_timeout;
                        clock.schedule_message(timeout, actor_cast<strong_actor_ptr>(dest),
                                               make_mailbox_element(dptr()->ctrl(), make_message_id(P), no_stages,
                                                                    std::forward<Ts>(xs)...));
                    }
                }

                /// Sends a message after a relative timeout.
                template<class Rep = int, class Period = std::ratio<1>, class Dest = actor, class... Ts>
                void delayed_send(const group &dest, std::chrono::duration<Rep, Period> rtime, Ts &&... xs) {
                    static_assert(!statically_typed<Subtype>(),
                                  "statically typed actors are not allowed to send to groups");
                    if (dest) {
                        auto &clock = dptr()->system().clock();
                        auto timeout = clock.now() + rtime;
                        clock.schedule_message(timeout, dest, dptr()->ctrl(), make_message(std::forward<Ts>(xs)...));
                    }
                }

                template<message_priority P = message_priority::normal, class Dest = actor, class Rep = int,
                         class Period = std::ratio<1>, class... Ts>
                void delayed_anon_send(const Dest &dest, std::chrono::duration<Rep, Period> rtime, Ts &&... xs) {
                    nil::actor::delayed_anon_send<P>(dest, rtime, std::forward<Ts>(xs)...);
                }

                template<class Rep = int, class Period = std::ratio<1>, class... Ts>
                void delayed_anon_send(const group &dest, std::chrono::duration<Rep, Period> rtime, Ts &&... xs) {
                    nil::actor::delayed_anon_send(dest, rtime, std::forward<Ts>(xs)...);
                }

            private:
                template<class Dest, class ArgTypes>
                static void type_check(const Dest &, ArgTypes) {
                    static_assert(!statically_typed<Subtype>() || statically_typed<Dest>(),
                                  "statically typed actors are only allowed to send() to other "
                                  "statically typed actors; use anon_send() or request() when "
                                  "communicating with dynamically typed actors");
                    using rt = response_type_unbox<signatures_of_t<Dest>, ArgTypes>;
                    static_assert(rt::valid, "receiver does not accept given message");
                    // TODO: this only checks one way, we should check for loops
                    static_assert(is_void_response<typename rt::type>::value ||
                                      response_type_unbox<signatures_of_t<Subtype>, typename rt::type>::valid,
                                  "this actor does not accept the response message");
                }

                Subtype *dptr() {
                    return static_cast<Subtype *>(this);
                }
            };    // namespace actor
        }         // namespace mixin
    }             // namespace actor
}    // namespace nil
