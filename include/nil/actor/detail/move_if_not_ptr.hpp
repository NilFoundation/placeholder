//---------------------------------------------------------------------------//
// Copyright (c) 2011-2014 Dominik Charousset
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#pragma once

#include <type_traits>

#include <nil/actor/detail/type_traits.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            /// Moves the value from `x` if it is not a pointer (e.g., `optional` or
            /// `expected`), returns `*x` otherwise.
            template<class T>
            T &move_if_not_ptr(T *x) {
                return *x;
            }

            /// Moves the value from `x` if it is not a pointer (e.g., `optional` or
            /// `expected`), returns `*x` otherwise.
            template<class T, class E = typename std::enable_if<!std::is_pointer<T>::value>::type>
            auto move_if_not_ptr(T &x) -> decltype(std::move(*x)) {
                return std::move(*x);
            }

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
