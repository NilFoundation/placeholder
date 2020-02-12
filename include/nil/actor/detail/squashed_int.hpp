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

#include <cstdint>
#include <type_traits>

#include <nil/actor/detail/type_list.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            /// Compile-time list of integer types types.
            using int_types_by_size = detail::type_list<    // bytes
                void,                                       // 0
                detail::type_pair<int8_t, uint8_t>,         // 1
                detail::type_pair<int16_t, uint16_t>,       // 2
                void,                                       // 3
                detail::type_pair<int32_t, uint32_t>,       // 4
                void,                                       // 5
                void,                                       // 6
                void,                                       // 7
                detail::type_pair<int64_t, uint64_t>        // 8
                >;

            /// Squashes integer types into [u]int_[8|16|32|64]_t equivalents
            template<class T>
            struct squashed_int {
                using tpair = typename detail::tl_at<int_types_by_size, sizeof(T)>::type;
                using type = typename std::conditional<std::is_signed<T>::value, typename tpair::first,
                                                       typename tpair::second>::type;
            };

            template<class T>
            using squashed_int_t = typename squashed_int<T>::type;

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
