//---------------------------------------------------------------------------//
// Copyright (c) 2011-2014 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <type_traits>

#include <nil/actor/detail/type_traits.hpp>

namespace nil::actor::detail {

    /// Moves the value from `x` if it is not a pointer (e.g., `optional` or
    /// `expected`), returns `*x` otherwise.
    template<class T>
    T &move_if_not_ptr(T *x) {
        return *x;
    }

    /// Moves the value from `x` if it is not a pointer (e.g., `optional` or
    /// `expected`), returns `*x` otherwise.
    template<class T, class E = enable_if_t<!std::is_pointer<T>::value>>
    auto move_if_not_ptr(T &x) -> decltype(std::move(*x)) {
        return std::move(*x);
    }

}    // namespace nil::actor::detail