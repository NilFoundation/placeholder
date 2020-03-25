//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt or
// http://opensource.org/licenses/BSD-3-Clause
//---------------------------------------------------------------------------//

#pragma once

#include <type_traits>

namespace nil {
    namespace actor {
        namespace meta {

            /// Type tag for all meta annotations in ACTOR.
            struct annotation {
                constexpr annotation() {
                    // nop
                }
            };

            template<class T>
            struct is_annotation {
                static constexpr bool value = std::is_base_of<annotation, T>::value;
            };

            template<class T>
            struct is_annotation<T &> : is_annotation<T> {};

            template<class T>
            struct is_annotation<const T &> : is_annotation<T> {};

            template<class T>
            struct is_annotation<T &&> : is_annotation<T> {};

            template<class T>
            constexpr bool is_annotation_v = is_annotation<T>::value;

        }    // namespace meta
    }        // namespace actor
}    // namespace nil
