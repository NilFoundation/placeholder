//---------------------------------------------------------------------------//
// Copyright (c) 2011-2017 Dominik Charousset
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

namespace nil {
    namespace actor {
        namespace detail {

            template<class... Fs>
            struct overload;

            template<class F>
            struct overload<F> : F {
                using F::operator();
                overload(F f) : F(f) {
                    // nop
                }
            };

            template<class F, class... Fs>
            struct overload<F, Fs...> : F, overload<Fs...> {
                using F::operator();
                using overload<Fs...>::operator();
                overload(F f, Fs... fs) : F(f), overload<Fs...>(fs...) {
                    // nop
                }
            };

            template<class... Fs>
            overload<Fs...> make_overload(Fs... fs) {
                return {fs...};
            }

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
