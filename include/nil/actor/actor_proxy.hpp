//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <atomic>
#include <cstdint>

#include <nil/actor/abstract_actor.hpp>

#include <nil/actor/detail/shared_spinlock.hpp>
#include <nil/actor/monitorable_actor.hpp>

namespace nil {
    namespace actor {

        /// Represents an actor running on a remote machine,
        /// or different hardware, or in a separate process.
        class BOOST_SYMBOL_VISIBLE actor_proxy : public monitorable_actor {
        public:
            explicit actor_proxy(actor_config &cfg);

            ~actor_proxy() override;

            /// Invokes cleanup code.
            virtual void kill_proxy(execution_unit *ctx, error reason) = 0;
        };

    }    // namespace actor
}    // namespace nil