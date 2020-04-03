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

#include <cstddef>
#include <type_traits>
#include <utility>

#include <nil/actor/detail/type_list.hpp>
#include <nil/actor/sum_type_token.hpp>

namespace nil {
    namespace actor {

        /// Allows specializing the `sum_type_access` trait for any type that simply
        /// wraps a `variant` and exposes it with a `get_data()` member function.
        template<class T>
        struct default_sum_type_access {
            using types = typename T::types;

            using type0 = typename detail::tl_head<types>::type;

            static constexpr bool specialized = true;

            template<class U, int Pos>
            static bool is(const T &x, sum_type_token<U, Pos> token) {
                return x.get_data().is(pos(token));
            }

            template<class U, int Pos>
            static U &get(T &x, sum_type_token<U, Pos> token) {
                return x.get_data().get(pos(token));
            }

            template<class U, int Pos>
            static const U &get(const T &x, sum_type_token<U, Pos> token) {
                return x.get_data().get(pos(token));
            }

            template<class U, int Pos>
            static U *get_if(T *x, sum_type_token<U, Pos> token) {
                return is(*x, token) ? &get(*x, token) : nullptr;
            }

            template<class U, int Pos>
            static const U *get_if(const T *x, sum_type_token<U, Pos> token) {
                return is(*x, token) ? &get(*x, token) : nullptr;
            }

            template<class Result, class Visitor, class... Ts>
            static Result apply(T &x, Visitor &&visitor, Ts &&... xs) {
                return x.get_data().template apply<Result>(std::forward<Visitor>(visitor), std::forward<Ts>(xs)...);
            }

            template<class Result, class Visitor, class... Ts>
            static Result apply(const T &x, Visitor &&visitor, Ts &&... xs) {
                return x.get_data().template apply<Result>(std::forward<Visitor>(visitor), std::forward<Ts>(xs)...);
            }
        };

    }    // namespace actor
}    // namespace nil
