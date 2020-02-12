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

            /// Checks wheter `T` is in the template parameter pack `Ts`.
            template<class T, class... Ts>
            struct is_one_of;

            template<class T>
            struct is_one_of<T> : std::false_type {};

            template<class T, class... Ts>
            struct is_one_of<T, T, Ts...> : std::true_type {};

            template<class T, class U, class... Ts>
            struct is_one_of<T, U, Ts...> : is_one_of<T, Ts...> {};

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
