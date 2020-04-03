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

#include <functional>
#include <type_traits>

#include <nil/actor/actor.hpp>
#include <nil/actor/actor_traits.hpp>

namespace nil::actor::detail {

    template<class T>
    struct spawn_fwd_convert : std::false_type {};

    template<>
    struct spawn_fwd_convert<scoped_actor> : std::true_type {};

    template<class T>
    struct spawn_fwd_convert<T *> {
        static constexpr bool value = actor_traits<T>::is_dynamically_typed;
    };

    /// Converts `scoped_actor` and pointers to actors to handles of type `actor`
    /// but simply forwards any other argument in the same way `std::forward` does.
    template<class T>
    typename std::conditional<spawn_fwd_convert<typename std::remove_reference<T>::type>::value, actor, T &&>::type
        spawn_fwd(typename std::remove_reference<T>::type &arg) noexcept {
        return static_cast<T &&>(arg);
    }

    /// Converts `scoped_actor` and pointers to actors to handles of type `actor`
    /// but simply forwards any other argument in the same way `std::forward` does.
    template<class T>
    typename std::conditional<spawn_fwd_convert<typename std::remove_reference<T>::type>::value, actor, T &&>::type
        spawn_fwd(typename std::remove_reference<T>::type &&arg) noexcept {
        static_assert(!std::is_lvalue_reference<T>::value, "silently converting an lvalue to an rvalue");
        return static_cast<T &&>(arg);
    }

}    // namespace nil::actor::detail