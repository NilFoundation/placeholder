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

#include <utility>

#include <nil/actor/fwd.hpp>

namespace nil {
    namespace actor {

        /// Marker type that allows ACTOR to spawn actors from composable states.
        class abstract_composable_behavior {
        public:
            virtual ~abstract_composable_behavior();

            virtual void init_behavior(message_handler &x) = 0;
        };

    }    // namespace actor
}    // namespace nil
