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

namespace nil {
    namespace actor {

        struct keep_behavior_t {
            constexpr keep_behavior_t() {
                // nop
            }
        };

        /// Policy tag that causes {@link event_based_actor::become} to
        /// keep the current behavior available.
        /// @relates local_actor
        constexpr keep_behavior_t keep_behavior = keep_behavior_t {};

    }    // namespace actor
}    // namespace nil
