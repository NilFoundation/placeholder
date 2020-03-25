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

#include <nil/actor/locks.hpp>
#include <nil/actor/actor_companion.hpp>

namespace nil {
    namespace actor {

        actor_companion::actor_companion(actor_config &cfg) : extended_base(cfg) {
            // nop
        }

        actor_companion::~actor_companion() {
            // nop
        }

        void actor_companion::on_enqueue(enqueue_handler handler) {
            std::lock_guard<lock_type> guard(lock_);
            on_enqueue_ = std::move(handler);
        }

        void actor_companion::on_exit(on_exit_handler handler) {
            on_exit_ = std::move(handler);
        }

        void actor_companion::enqueue(mailbox_element_ptr ptr, execution_unit *) {
            ACTOR_ASSERT(ptr);
            shared_lock<lock_type> guard(lock_);
            if (on_enqueue_)
                on_enqueue_(std::move(ptr));
        }

        void actor_companion::enqueue(strong_actor_ptr src, message_id mid, message content, execution_unit *eu) {
            auto ptr = make_mailbox_element(std::move(src), mid, {}, std::move(content));
            enqueue(std::move(ptr), eu);
        }

        void actor_companion::launch(execution_unit *, bool, bool hide) {
            if (!hide)
                register_at_system();
        }

        void actor_companion::on_exit() {
            enqueue_handler tmp;
            {    // lifetime scope of guard
                std::lock_guard<lock_type> guard(lock_);
                on_enqueue_.swap(tmp);
            }
            if (on_exit_)
                on_exit_();
        }

    }    // namespace actor
}    // namespace nil
