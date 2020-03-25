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

#include <nil/actor/meta/annotation.hpp>

namespace nil {
    namespace actor {
        namespace meta {

            template<class F>
            struct save_callback_t : annotation {
                save_callback_t(F &&f) : fun(f) {
                    // nop
                }

                save_callback_t(save_callback_t &&) = default;

                save_callback_t(const save_callback_t &) = default;

                F fun;
            };

            template<class T>
            struct is_save_callback : std::false_type {};

            template<class F>
            struct is_save_callback<save_callback_t<F>> : std::true_type {};

            template<class F>
            constexpr bool is_save_callback_v = is_save_callback<F>::value;

            /// Returns an annotation that allows inspectors to call
            /// user-defined code after performing save operations.
            template<class F>
            save_callback_t<F> save_callback(F fun) {
                return {std::move(fun)};
            }
        }    // namespace meta
    }        // namespace actor
}    // namespace nil
