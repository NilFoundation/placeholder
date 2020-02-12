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

#include <functional>
#include <type_traits>

#include <nil/actor/actor.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            /// Converts `scoped_actor` and pointers to actors to handles of type `actor`
            /// but simply forwards any other argument in the same way `std::forward` does.
            template<class T>
            typename std::conditional<is_convertible_to_actor<typename std::decay<T>::type>::value, actor, T &&>::type
                spawn_fwd(typename std::remove_reference<T>::type &arg) noexcept {
                return static_cast<T &&>(arg);
            }

            /// Converts `scoped_actor` and pointers to actors to handles of type `actor`
            /// but simply forwards any other argument in the same way `std::forward` does.
            template<class T>
            typename std::conditional<is_convertible_to_actor<typename std::decay<T>::type>::value, actor, T &&>::type
                spawn_fwd(typename std::remove_reference<T>::type &&arg) noexcept {
                static_assert(!std::is_lvalue_reference<T>::value, "silently converting an lvalue to an rvalue");
                return static_cast<T &&>(arg);
            }

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
