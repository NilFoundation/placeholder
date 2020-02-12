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

#include <tuple>

#include <nil/actor/fwd.hpp>
#include <nil/actor/replies_to.hpp>

#include <nil/actor/detail/type_list.hpp>

namespace nil {
    namespace actor {

        /// Defines:
        /// - `valid` if typedefs are set, can be used to check if actors accept input
        /// - `type` list of output types or `message` for dynamically typed actors
        /// - `delegated_type` type above wrapped in a `delegated`
        /// - `tuple_type` output types wrapped in a `std::tuple` or `message`
        template<class Ts, class... Xs>
        struct response_type;

        // short-circuit for dynamically typed messaging
        template<class... Xs>
        struct response_type<none_t, Xs...> {
            static constexpr bool valid = true;
            using type = message;
            using delegated_type = delegated<message>;
            using tuple_type = message;
        };

        // end of recursion (suppress type definitions for enabling SFINAE)
        template<class... Xs>
        struct response_type<detail::type_list<>, Xs...> {
            static constexpr bool valid = false;
        };

        // case #1: no match
        template<class In, class Out, class... Ts, class... Xs>
        struct response_type<detail::type_list<typed_mpi<In, Out>, Ts...>, Xs...>
            : response_type<detail::type_list<Ts...>, Xs...> {};

        // case #2: match
        template<class... Out, class... Ts, class... Xs>
        struct response_type<detail::type_list<typed_mpi<detail::type_list<Xs...>, output_tuple<Out...>>, Ts...>,
                             Xs...> {
            static constexpr bool valid = true;
            using type = detail::type_list<Out...>;
            using tuple_type = std::tuple<Out...>;
            using delegated_type = delegated<Out...>;
        };

        /// Computes the response message for input `Xs...` from the list
        /// of message passing interfaces `Ts`.
        template<class Ts, class... Xs>
        using response_type_t = typename response_type<Ts, Xs...>::type;

        /// Unboxes `Xs` and calls `response_type`.
        template<class Ts, class Xs>
        struct response_type_unbox;

        template<class Ts, class... Xs>
        struct response_type_unbox<Ts, detail::type_list<Xs...>> : response_type<Ts, Xs...> {};

        template<class Ts>
        struct response_type_unbox<Ts, message> : response_type<Ts, message> {};

        /// Computes the response message for input `Xs` from the list
        /// of message passing interfaces `Ts`.
        template<class Ts, class Xs>
        using response_type_unbox_t = typename response_type_unbox<Ts, Xs>::type;

    }    // namespace actor
}    // namespace nil