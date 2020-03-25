//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
//
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#pragma once

#include <nil/actor/scheduled_actor.hpp>

#include <nil/actor/mixin/sender.hpp>
#include <nil/actor/mixin/requester.hpp>

namespace nil {
    namespace actor {

        struct typed_actor_view_base {};

        template<class... Sigs>
        class typed_actor_view
            : public extend<typed_actor_view_base, typed_actor_view<Sigs...>>::template with<mixin::sender,
                                                                                             mixin::requester> {
        public:
            /// Stores the template parameter pack.
            using signatures = detail::type_list<Sigs...>;

            typed_actor_view(scheduled_actor *ptr) : self_(ptr) {
                // nop
            }

            typed_actor_view &operator=(scheduled_actor *ptr) {
                self_ = ptr;
                return *this;
            }

            /****************************************************************************
             *                           spawn actors                                   *
             ****************************************************************************/

            template<class T, spawn_options Os = no_spawn_options, class... Ts>
            typename infer_handle_from_class<T>::type spawn(Ts &&... xs) {
                return self_->spawn<T, Os>(std::forward<Ts>(xs)...);
            }

            template<class T, spawn_options Os = no_spawn_options>
            infer_handle_from_state_t<T> spawn() {
                return self_->spawn<T, Os>();
            }

            template<spawn_options Os = no_spawn_options, class F, class... Ts>
            typename infer_handle_from_fun<F>::type spawn(F fun, Ts &&... xs) {
                return self_->spawn<Os>(std::move(fun), std::forward<Ts>(xs)...);
            }

            /****************************************************************************
             *                      miscellaneous actor operations                      *
             ****************************************************************************/

            execution_unit *context() const {
                return self_->context();
            }

            spawner &system() const {
                return self_->system();
            }

            spawner &home_system() const {
                return self_->home_system();
            }

            void quit(exit_reason reason = exit_reason::normal) {
                self_->quit(reason);
            }

            template<class... Ts>
            typename detail::make_response_promise_helper<Ts...>::type make_response_promise() {
                return self_->make_response_promise<Ts...>();
            }

            template<message_priority P = message_priority::normal, class Handle = actor>
            void monitor(const Handle &x) {
                self_->monitor<P>(x);
            }

            template<class T>
            void demonitor(const T &x) {
                self_->demonitor(x);
            }

            response_promise make_response_promise() {
                return self_->make_response_promise();
            }

            template<class... Ts,
                     class R = typename detail::make_response_promise_helper<typename std::decay<Ts>::type...>::type>
            R response(Ts &&... xs) {
                return self_->response(std::forward<Ts>(xs)...);
            }

            /// Returns a pointer to the sender of the current message.
            /// @pre `current_mailbox_element() != nullptr`
            inline strong_actor_ptr &current_sender() {
                return self_->current_sender();
            }

            /// Returns a pointer to the currently processed mailbox element.
            inline mailbox_element *current_mailbox_element() {
                return self_->current_mailbox_element();
            }

            /// @private
            actor_control_block *ctrl() const {
                ACTOR_ASSERT(self_ != nullptr);
                return actor_control_block::from(self_);
                ;
            }

            /// @private
            scheduled_actor *internal_ptr() const {
                return self_;
            }

        private:
            scheduled_actor *self_;
        };

    }    // namespace actor
}    // namespace nil
