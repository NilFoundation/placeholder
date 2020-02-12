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

#include <nil/actor/detail/type_traits.hpp>
#include <nil/actor/infer_handle.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            /// Returns whether the function object `F` is spawnable from the actor
            /// implementation `Impl` with arguments of type `Ts...`.
            template<class F, class Impl, class... Ts>
            constexpr bool spawnable() {
                return is_callable_with<F, Ts...>::value || is_callable_with<F, Impl *, Ts...>::value;
            }

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
