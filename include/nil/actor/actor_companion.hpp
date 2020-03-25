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

#include <memory>
#include <functional>

#include <nil/actor/fwd.hpp>
#include <nil/actor/extend.hpp>
#include <nil/actor/scheduled_actor.hpp>
#include <nil/actor/mailbox_element.hpp>

#include <nil/actor/mixin/sender.hpp>
#include <nil/actor/mixin/subscriber.hpp>
#include <nil/actor/mixin/behavior_changer.hpp>

#include <nil/actor/detail/disposer.hpp>
#include <nil/actor/detail/shared_spinlock.hpp>

namespace nil {
    namespace actor {

        template<>
        class behavior_type_of<actor_companion> {
        public:
            using type = behavior;
        };

        /// An co-existing actor forwarding all messages through a user-defined
        /// callback to another object, thus serving as gateway to
        /// allow any object to interact with other actors.
        /// @extends local_actor
        class actor_companion : public extend<scheduled_actor, actor_companion>::with<mixin::sender, mixin::subscriber,
                                                                                      mixin::behavior_changer> {
        public:
            // -- member types -----------------------------------------------------------

            /// Required by `spawn` for type deduction.
            using signatures = none_t;

            /// Required by `spawn` for type deduction.
            using behavior_type = behavior;

            /// A shared lockable.
            using lock_type = detail::shared_spinlock;

            /// Delegates incoming messages to user-defined event loop.
            using enqueue_handler = std::function<void(mailbox_element_ptr)>;

            /// Callback for actor termination.
            using on_exit_handler = std::function<void()>;

            // -- constructors, destructors ----------------------------------------------

            actor_companion(actor_config &cfg);

            ~actor_companion() override;

            // -- overridden functions ---------------------------------------------------

            void enqueue(mailbox_element_ptr ptr, execution_unit *host) override;

            void enqueue(strong_actor_ptr src, message_id mid, message content, execution_unit *eu) override;

            void launch(execution_unit *eu, bool lazy, bool hide) override;

            void on_exit() override;

            // -- modifiers --------------------------------------------------------------

            /// Removes the handler for incoming messages and terminates
            /// the companion for exit reason `rsn`.
            void disconnect(exit_reason rsn = exit_reason::normal);

            /// Sets the handler for incoming messages.
            /// @warning `handler` needs to be thread-safe
            void on_enqueue(enqueue_handler handler);

            /// Sets the handler for incoming messages.
            void on_exit(on_exit_handler handler);

        private:
            // set by parent to define custom enqueue action
            enqueue_handler on_enqueue_;

            // custom code for on_exit()
            on_exit_handler on_exit_;

            // guards access to handler_
            lock_type lock_;
        };
    }    // namespace actor
}    // namespace nil
