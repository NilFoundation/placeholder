//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#pragma once

#include <nil/actor/actor.hpp>
#include <nil/actor/actor_addr.hpp>
#include <nil/actor/actor_cast.hpp>
#include <nil/actor/check_typed_input.hpp>
#include <nil/actor/is_message_sink.hpp>
#include <nil/actor/local_actor.hpp>
#include <nil/actor/mailbox_element.hpp>
#include <nil/actor/message.hpp>
#include <nil/actor/message_id.hpp>
#include <nil/actor/message_priority.hpp>
#include <nil/actor/no_stages.hpp>
#include <nil/actor/response_type.hpp>
#include <nil/actor/system_messages.hpp>
#include <nil/actor/typed_actor.hpp>

namespace nil {
    namespace actor {

        /// Sends `to` a message under the identity of `from` with priority `prio`.
        template<message_priority P = message_priority::normal, class Source = actor, class Dest = actor, class... Ts>
        void send_as(const Source &src, const Dest &dest, Ts &&... xs) {
            static_assert(sizeof...(Ts) > 0, "no message to send");
            using token = detail::type_list<typename detail::strip_and_convert<Ts>::type...>;
            static_assert(!statically_typed<Source>() || statically_typed<Dest>(),
                          "statically typed actors can only send() to other "
                          "statically typed actors; use anon_send() or request() when "
                          "communicating with dynamically typed actors");
            static_assert(response_type_unbox<typename signatures_of<Dest>::type, token>::valid,
                          "receiver does not accept given message");
            // TODO: this only checks one way, we should check for loops
            static_assert(is_void_response<response_type_unbox_t<typename signatures_of<Dest>::type, token>>::value ||
                              response_type_unbox<signatures_of_t<Source>,
                                                  response_type_unbox_t<signatures_of_t<Dest>, token>>::valid,
                          "this actor does not accept the response message");
            if (dest)
                dest->eq_impl(make_message_id(P), actor_cast<strong_actor_ptr>(src), nullptr, std::forward<Ts>(xs)...);
        }

        template<message_priority P = message_priority::normal, class Source, class Dest, class... Ts>
        void unsafe_send_as(Source *src, const Dest &dest, Ts &&... xs) {
            static_assert(sizeof...(Ts) > 0, "no message to send");
            if (dest)
                actor_cast<abstract_actor *>(dest)->eq_impl(make_message_id(P), src->ctrl(), src->context(),
                                                            std::forward<Ts>(xs)...);
        }

        template<class... Ts>
        void unsafe_response(local_actor *self, strong_actor_ptr src, std::vector<strong_actor_ptr> stages,
                             message_id mid, Ts &&... xs) {
            static_assert(sizeof...(Ts) > 0, "no message to send");
            strong_actor_ptr next;
            if (stages.empty()) {
                next = src;
                src = self->ctrl();
                if (mid.is_request())
                    mid = mid.response_id();
            } else {
                next = std::move(stages.back());
                stages.pop_back();
            }
            if (next)
                next->enqueue(make_mailbox_element(std::move(src), mid, std::move(stages), std::forward<Ts>(xs)...),
                              self->context());
        }

        /// Anonymously sends `dest` a message.
        template<message_priority P = message_priority::normal, class Dest = actor, class... Ts>
        void anon_send(const Dest &dest, Ts &&... xs) {
            static_assert(sizeof...(Ts) > 0, "no message to send");
            using token = detail::type_list<typename detail::strip_and_convert<Ts>::type...>;
            static_assert(response_type_unbox<typename signatures_of<Dest>::type, token>::valid,
                          "receiver does not accept given message");
            if (dest)
                dest->eq_impl(make_message_id(P), nullptr, nullptr, std::forward<Ts>(xs)...);
        }

        template<message_priority P = message_priority::normal, class Dest = actor, class Rep = int,
                 class Period = std::ratio<1>, class... Ts>
        typename std::enable_if<!std::is_same<Dest, group>::value>::type
            delayed_anon_send(const Dest &dest, std::chrono::duration<Rep, Period> rtime, Ts &&... xs) {
            static_assert(sizeof...(Ts) > 0, "no message to send");
            using token =
                detail::type_list<typename detail::implicit_conversions<typename std::decay<Ts>::type>::type...>;
            static_assert(response_type_unbox<signatures_of_t<Dest>, token>::valid,
                          "receiver does not accept given message");
            if (dest) {
                auto &clock = dest->home_system().clock();
                auto timeout = clock.now() + rtime;
                clock.schedule_message(
                    timeout, actor_cast<strong_actor_ptr>(dest),
                    make_mailbox_element(nullptr, make_message_id(P), no_stages, std::forward<Ts>(xs)...));
            }
        }

        template<class Rep = int, class Period = std::ratio<1>, class... Ts>
        void delayed_anon_send(const group &dest, std::chrono::duration<Rep, Period> rtime, Ts &&... xs) {
            static_assert(sizeof...(Ts) > 0, "no message to send");
            if (dest) {
                auto &clock = dest->system().clock();
                auto timeout = clock.now() + rtime;
                clock.schedule_message(timeout, dest, make_message(std::forward<Ts>(xs)...));
            }
        }

        /// Anonymously sends `dest` an exit message.
        template<class Dest>
        void anon_send_exit(const Dest &dest, exit_reason reason) {
            ACTOR_LOG_TRACE(ACTOR_ARG(dest) << ACTOR_ARG(reason));
            if (dest)
                dest->enqueue(nullptr, make_message_id(), make_message(exit_msg {dest->address(), reason}), nullptr);
        }

        /// Anonymously sends `to` an exit message.
        inline void anon_send_exit(const actor_addr &to, exit_reason reason) {
            auto ptr = actor_cast<strong_actor_ptr>(to);
            if (ptr)
                anon_send_exit(ptr, reason);
        }

        /// Anonymously sends `to` an exit message.
        inline void anon_send_exit(const weak_actor_ptr &to, exit_reason reason) {
            auto ptr = actor_cast<strong_actor_ptr>(to);
            if (ptr)
                anon_send_exit(ptr, reason);
        }
    }    // namespace actor
}    // namespace nil
