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

#include <string>

#include <nil/actor/abstract_channel.hpp>
#include <nil/actor/behavior.hpp>
#include <nil/actor/detail/unique_function.hpp>
#include <nil/actor/fwd.hpp>
#include <nil/actor/input_range.hpp>

namespace nil {
    namespace actor {

        /// Stores spawn-time flags and groups.
        class actor_config {
        public:
            // -- member types -----------------------------------------------------------

            using init_fun_type = detail::unique_function<behavior(local_actor *)>;

            // -- constructors, destructors, and assignment operators --------------------

            explicit actor_config(execution_unit *ptr = nullptr);

            // -- member variables -------------------------------------------------------

            execution_unit *host;
            int flags;
            input_range<const group> *groups;
            detail::unique_function<behavior(local_actor *)> init_fun;

            // -- properties -------------------------------------------------------------

            actor_config &add_flag(int x) {
                flags |= x;
                return *this;
            }
        };

        /// @relates actor_config
        std::string to_string(const actor_config &x);

    }    // namespace actor
}    // namespace nil
