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

#include <string>

#include <nil/actor/abstract_channel.hpp>
#include <nil/actor/behavior.hpp>

#include <nil/actor/detail/unique_function.hpp>
#include <nil/actor/fwd.hpp>
#include <nil/actor/input_range.hpp>

namespace nil {
    namespace actor {

        /// Stores spawn-time flags and groups.
        class BOOST_SYMBOL_VISIBLE actor_config {
        public:
            // -- member types -----------------------------------------------------------

            using init_fun_type = detail::unique_function<behavior(local_actor *)>;

            // -- constructors, destructors, and assignment operators --------------------

            explicit actor_config(execution_unit *host = nullptr, local_actor *parent = nullptr);

            // -- member variables -------------------------------------------------------

            execution_unit *host;
            local_actor *parent;
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
        BOOST_SYMBOL_VISIBLE std::string to_string(const actor_config &x);

    }    // namespace actor
}    // namespace nil