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

#include <nil/actor/fwd.hpp>

namespace nil {
    namespace actor {

        /// Checks whether `T` is an `actor` or a `typed_actor<...>`.
        template<class T>
        struct is_actor_handle : std::false_type {};

        template<>
        struct is_actor_handle<actor> : std::true_type {};

        template<class... Ts>
        struct is_actor_handle<typed_actor<Ts...>> : std::true_type {};

    }    // namespace actor
}    // namespace nil
