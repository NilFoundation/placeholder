//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt or
// http://opensource.org/licenses/BSD-3-Clause
//---------------------------------------------------------------------------//

#pragma once

#include <nil/actor/actor.hpp>
#include <nil/actor/actor_proxy.hpp>

#include <nil/actor/detail/shared_spinlock.hpp>

namespace nil {
    namespace actor {

        /// Implements a simple proxy forwarding all operations to a manager.
        class forwarding_actor_proxy : public actor_proxy {
        public:
            using forwarding_stack = std::vector<strong_actor_ptr>;

            forwarding_actor_proxy(actor_config &cfg, actor dest);

            ~forwarding_actor_proxy() override;

            void enqueue(mailbox_element_ptr what, execution_unit *context) override;

            bool add_backlink(abstract_actor *x) override;

            bool remove_backlink(abstract_actor *x) override;

            void kill_proxy(execution_unit *ctx, error rsn) override;

        private:
            void forward_msg(strong_actor_ptr sender, message_id mid, message msg,
                             const forwarding_stack *fwd = nullptr);

            mutable detail::shared_spinlock broker_mtx_;
            actor broker_;
        };

    }    // namespace actor
}    // namespace nil
