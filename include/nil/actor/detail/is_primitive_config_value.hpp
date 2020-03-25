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

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include <nil/actor/detail/is_one_of.hpp>
#include <nil/actor/timespan.hpp>

// -- forward declarations (this header cannot include fwd.hpp) ----------------

namespace nil {
    namespace actor {

        class config_value;
        enum class atom_value : uint64_t;

    }    // namespace actor
}    // namespace nil

// -- trait --------------------------------------------------------------------

namespace nil {
    namespace actor {
        namespace detail {

            /// Checks wheter `T` is in a primitive value type in `config_value`.
            template<class T>
            using is_primitive_config_value = is_one_of<T, int64_t, bool, double, atom_value, timespan, std::string,
                                                        std::vector<config_value>, std::map<std::string, config_value>>;

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
