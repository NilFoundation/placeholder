//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#pragma once

namespace nil {
    namespace actor {

        namespace detail {

            template<class D, class B, template<class, class> class... Ms>
            struct extend_helper;

            template<class D, class B>
            struct extend_helper<D, B> {
                using type = B;
            };

            template<class D, class B, template<class, class> class M, template<class, class> class... Ms>
            struct extend_helper<D, B, M, Ms...> : extend_helper<D, M<B, D>, Ms...> {
                // no content
            };

        }    // namespace detail

        /// Allows convenient definition of types using mixins.
        /// For example, `extend<ar, T>::with<ob, fo>` is an alias for
        /// `fo<ob<ar, T>, T>`.
        ///
        /// Mixins always have two template parameters: base type and
        /// derived type. This allows mixins to make use of the curiously recurring
        /// template pattern (CRTP). However, if none of the used mixins use CRTP,
        /// the second template argument can be ignored (it is then set to Base).
        template<class Base, class Derived = Base>
        struct extend {
            /// Identifies the combined type.
            template<template<class, class> class... Mixins>
            using with = typename detail::extend_helper<Derived, Base, Mixins...>::type;
        };

    }    // namespace actor
}    // namespace nil
