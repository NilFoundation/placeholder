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

#include <nil/actor/delegated.hpp>
#include <nil/actor/replies_to.hpp>
#include <nil/actor/response_promise.hpp>
#include <nil/actor/system_messages.hpp>
#include <nil/actor/typed_response_promise.hpp>

#include <nil/actor/detail/type_list.hpp>

namespace nil {
    namespace actor {    // forward declarations

        template<class... Ts>
        class typed_actor;

    }
}    // namespace nil

namespace nil {
    namespace actor {
        namespace detail {

            template<class Arguments, class Signature>
            struct input_is_eval_impl : std::false_type {};

            template<class Arguments, class Out>
            struct input_is_eval_impl<Arguments, typed_mpi<Arguments, Out>> : std::true_type {};

            template<class Arguments>
            struct input_is {
                template<class Signature>
                struct eval : input_is_eval_impl<Arguments, Signature> {};
            };

            template<class... Ts>
            struct make_response_promise_helper {
                using type = typed_response_promise<Ts...>;
            };

            template<class... Ts>
            struct make_response_promise_helper<typed_response_promise<Ts...>> : make_response_promise_helper<Ts...> {};

            template<>
            struct make_response_promise_helper<response_promise> {
                using type = response_promise;
            };

            template<class Output, class F>
            struct type_checker {
                static void check() {
                    using arg_types = typename tl_map<typename get_callable_trait<F>::arg_types, std::decay>::type;
                    static_assert(std::is_same<Output, arg_types>::value ||
                                      (std::is_same<Output, type_list<void>>::value &&
                                       std::is_same<arg_types, type_list<>>::value),
                                  "wrong functor signature");
                }
            };

            template<class F>
            struct type_checker<message, F> {
                static void check() {
                    // nop
                }
            };

            /// Generates an error using static_assert on an interface mismatch.
            /// @tparam NumMessageHandlers The number of message handlers
            ///                            provided by the user.
            /// @tparam Pos The index at which an error was detected or a negative value
            ///             if too many or too few handlers were provided.
            /// @tparam RemainingXs The remaining deduced messaging interfaces of the
            ///                     provided message handlers at the time of the error.
            /// @tparam RemainingYs The remaining unimplemented message handler
            ///                     signatures at the time of the error.
            template<int NumMessageHandlers, int Pos, class RemainingXs, class RemainingYs>
            struct static_error_printer {
                static_assert(NumMessageHandlers == Pos, "unexpected handler some index > 20");
            };

            template<int N, class Xs, class Ys>
            struct static_error_printer<N, -2, Xs, Ys> {
                static_assert(N == -1, "too many message handlers");
            };

            template<int N, class Xs, class Ys>
            struct static_error_printer<N, -1, Xs, Ys> {
                static_assert(N == -1, "not enough message handlers");
            };

#define ACTOR_STATICERR(x)                                          \
    template<int N, class Xs, class Ys>                           \
    struct static_error_printer<N, x, Xs, Ys> {                   \
        static_assert(N == x, "unexpected handler at index " #x); \
    }

            ACTOR_STATICERR(0);
            ACTOR_STATICERR(1);
            ACTOR_STATICERR(2);
            ACTOR_STATICERR(3);
            ACTOR_STATICERR(4);
            ACTOR_STATICERR(5);
            ACTOR_STATICERR(6);
            ACTOR_STATICERR(7);
            ACTOR_STATICERR(8);
            ACTOR_STATICERR(9);
            ACTOR_STATICERR(10);
            ACTOR_STATICERR(11);
            ACTOR_STATICERR(12);
            ACTOR_STATICERR(13);
            ACTOR_STATICERR(14);
            ACTOR_STATICERR(15);
            ACTOR_STATICERR(16);
            ACTOR_STATICERR(17);
            ACTOR_STATICERR(18);
            ACTOR_STATICERR(19);
            ACTOR_STATICERR(20);

            template<class... Ts>
            struct extend_with_helper;

            template<class... Xs>
            struct extend_with_helper<typed_actor<Xs...>> {
                using type = typed_actor<Xs...>;
            };

            template<class... Xs, class... Ys, class... Ts>
            struct extend_with_helper<typed_actor<Xs...>, typed_actor<Ys...>, Ts...>
                : extend_with_helper<typed_actor<Xs..., Ys...>, Ts...> {
                // nop
            };

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
