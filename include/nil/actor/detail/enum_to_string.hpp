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

#include <type_traits>

namespace nil {
    namespace actor {
        namespace detail {

            /// Converts x to its underlying type and fetches the name from the
            /// lookup table. Assumes consecutive enum values.
            template<class E, size_t N>
            const char *enum_to_string(E x, const char *(&lookup_table)[N]) {
                auto index = static_cast<typename std::underlying_type<E>::type>(x);
                return index < N ? lookup_table[index] : "<unknown>";
            }

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
