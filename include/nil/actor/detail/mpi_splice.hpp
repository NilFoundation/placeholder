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

#include <type_traits>

#include <nil/actor/replies_to.hpp>

#include <nil/actor/detail/type_list.hpp>
#include <nil/actor/detail/typed_actor_util.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            template<class T, class... Lists>
            struct mpi_splice_by_input;

            template<class T>
            struct mpi_splice_by_input<T> {
                using type = T;
            };

            template<class T, class... Lists>
            struct mpi_splice_by_input<T, type_list<>, Lists...> {
                // consumed an entire list without match -> fail
                using type = none_t;
            };

            // splice two MPIs if they have the same input
            template<class Input, class... Xs, class... Ys, class... Ts, class... Lists>
            struct mpi_splice_by_input<typed_mpi<Input, type_list<Xs...>>,
                                       type_list<typed_mpi<Input, type_list<Ys...>>, Ts...>, Lists...>
                : mpi_splice_by_input<typed_mpi<Input, type_list<Xs..., Ys...>>, Lists...> {};

            // skip element in list until empty
            template<class MPI, class MPI2, class... Ts, class... Lists>
            struct mpi_splice_by_input<MPI, type_list<MPI2, Ts...>, Lists...>
                : mpi_splice_by_input<MPI, type_list<Ts...>, Lists...> {};

            template<class Result, class CurrentNeedle, class... Lists>
            struct input_mapped;

            template<class... Rs, class... Lists>
            struct input_mapped<type_list<Rs...>, none_t, type_list<>, Lists...> {
                using type = type_list<Rs...>;
            };

            template<class... Rs, class T, class... Ts, class... Lists>
            struct input_mapped<type_list<Rs...>, none_t, type_list<T, Ts...>, Lists...>
                : input_mapped<type_list<Rs...>, T, type_list<Ts...>, Lists...> {};

            template<class... Rs, class T, class FirstList, class... Lists>
            struct input_mapped<type_list<Rs...>, T, FirstList, Lists...>
                : input_mapped<type_list<Rs..., typename mpi_splice_by_input<T, Lists...>::type>, none_t, FirstList,
                               Lists...> {};

            template<template<class...> class Target, class ListA, class ListB>
            struct mpi_splice;

            template<template<class...> class Target, class... Ts, class List>
            struct mpi_splice<Target, type_list<Ts...>, List> {
                using spliced_list = typename input_mapped<type_list<>, none_t, type_list<Ts...>, List>::type;
                using filtered_list = typename tl_filter_not_type<spliced_list, none_t>::type;
                static_assert(tl_size<filtered_list>::value > 0, "cannot splice incompatible actor handles");
                using type = typename tl_apply<filtered_list, Target>::type;
            };

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
