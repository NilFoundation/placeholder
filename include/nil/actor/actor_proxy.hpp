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

#include <atomic>
#include <cstdint>

#include <nil/actor/abstract_actor.hpp>
#include <nil/actor/monitorable_actor.hpp>

#include <nil/actor/detail/shared_spinlock.hpp>

namespace nil {
    namespace actor {

        /// Represents an actor running on a remote machine,
        /// or different hardware, or in a separate process.
        class actor_proxy : public monitorable_actor {
        public:
            explicit actor_proxy(actor_config &cfg);

            ~actor_proxy() override;

            /// Invokes cleanup code.
            virtual void kill_proxy(execution_unit *ctx, error reason) = 0;
        };

    }    // namespace actor
}    // namespace nil
