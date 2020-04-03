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

#include <type_traits>

namespace nil::actor::detail {

    /// Checks whether `T` is in the template parameter pack `Ts`.
    template<class T, class... Ts>
    struct is_one_of;

    template<class T>
    struct is_one_of<T> : std::false_type {};

    template<class T, class... Ts>
    struct is_one_of<T, T, Ts...> : std::true_type {};

    template<class T, class U, class... Ts>
    struct is_one_of<T, U, Ts...> : is_one_of<T, Ts...> {};

}    // namespace nil::actor::detail