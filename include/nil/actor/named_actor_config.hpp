//---------------------------------------------------------------------------//
// Copyright (c) 2011-2015 Dominik Charousset
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#pragma once

#include <cstddef>

#include <nil/actor/atom.hpp>
#include <nil/actor/deep_to_string.hpp>

#include <nil/actor/meta/type_name.hpp>

namespace nil {
    namespace actor {

        /// Stores a flow-control configuration.
        struct named_actor_config {
            atom_value strategy;
            size_t low_watermark;
            size_t max_pending;
        };

        template<class Inspector>
        typename Inspector::result_type inspect(Inspector &f, named_actor_config &x) {
            return f(meta::type_name("named_actor_config"), x.strategy, x.low_watermark, x.max_pending);
        }

    }    // namespace actor
}    // namespace nil
