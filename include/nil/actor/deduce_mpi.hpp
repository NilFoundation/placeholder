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

#include <nil/actor/fwd.hpp>
#include <nil/actor/param.hpp>
#include <nil/actor/expected.hpp>
#include <nil/actor/optional.hpp>
#include <nil/actor/replies_to.hpp>

#include <nil/actor/detail/implicit_conversions.hpp>

namespace nil {
    namespace actor {

        namespace detail {

            // dmi = deduce_mpi_implementation
            template<class T>
            struct dmi;

            // case #1: function returning a single value
            template<class Y, class... Xs>
            struct dmi<Y(Xs...)> {
                using type =
                    typed_mpi<type_list<typename param_decay<Xs>::type...>, output_tuple<implicit_conversions_t<Y>>>;
            };

            // case #2a: function returning a result<...>
            template<class... Ys, class... Xs>
            struct dmi<result<Ys...>(Xs...)> {
                using type = typed_mpi<type_list<typename param_decay<Xs>::type...>,
                                       output_tuple<implicit_conversions_t<Ys>...>>;
            };

            // case #2b: function returning a std::tuple<...>
            template<class... Ys, class... Xs>
            struct dmi<std::tuple<Ys...>(Xs...)> {
                using type = typed_mpi<type_list<typename param_decay<Xs>::type...>,
                                       output_tuple<implicit_conversions_t<Ys>...>>;
            };

            // case #2c: function returning a std::tuple<...>
            template<class... Ys, class... Xs>
            struct dmi<delegated<Ys...>(Xs...)> {
                using type = typed_mpi<type_list<typename param_decay<Xs>::type...>,
                                       output_tuple<implicit_conversions_t<Ys>...>>;
            };

            // case #2d: function returning a typed_response_promise<...>
            template<class... Ys, class... Xs>
            struct dmi<typed_response_promise<Ys...>(Xs...)> {
                using type = typed_mpi<type_list<typename param_decay<Xs>::type...>,
                                       output_tuple<implicit_conversions_t<Ys>...>>;
            };

            // case #3: function returning an optional<>
            template<class Y, class... Xs>
            struct dmi<optional<Y>(Xs...)> : dmi<Y(Xs...)> {};

            // case #4: function returning an expected<>
            template<class Y, class... Xs>
            struct dmi<expected<Y>(Xs...)> : dmi<Y(Xs...)> {};

            // case #5: function returning an output_stream<>
            template<class Y, class... Ys, class P, class... Xs>
            struct dmi<output_stream<Y, std::tuple<Ys...>, P>(Xs...)> : dmi<Y(Xs...)> {
                using type = typed_mpi<type_list<typename param_decay<Xs>::type...>,
                                       output_tuple<stream<Y>, strip_and_convert_t<Ys>...>>;
            };

            // -- dmfou = deduce_mpi_function_object_unboxing

            template<class T, bool isClass = std::is_class<T>::value>
            struct dmfou;

            // case #1: const member function pointer
            template<class C, class Result, class... Ts>
            struct dmfou<Result (C::*)(Ts...) const, false> : dmi<Result(Ts...)> {};

            // case #2: member function pointer
            template<class C, class Result, class... Ts>
            struct dmfou<Result (C::*)(Ts...), false> : dmi<Result(Ts...)> {};

            // case #3: good ol' function
            template<class Result, class... Ts>
            struct dmfou<Result(Ts...), false> : dmi<Result(Ts...)> {};

            template<class T>
            struct dmfou<T, true> : dmfou<decltype(&T::operator()), false> {};

            // this specialization leaves timeout definitions untouched,
            // later stages such as interface_mismatch need to deal with them later
            template<class T>
            struct dmfou<timeout_definition<T>, true> {
                using type = timeout_definition<T>;
            };

            template<class T>
            struct dmfou<trivial_match_case<T>, true> : dmfou<T> {};

        }    // namespace detail

        /// Deduces the message passing interface from a function object.
        template<class T>
        using deduce_mpi_t = typename detail::dmfou<typename param_decay<T>::type>::type;

    }    // namespace actor
}    // namespace nil
