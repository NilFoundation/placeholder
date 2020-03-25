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

#include <nil/actor/make_message.hpp>
#include <nil/actor/message.hpp>
#include <nil/actor/stream_sink.hpp>

#include <nil/actor/detail/type_traits.hpp>

namespace nil {
    namespace actor {

        /// Dispatches a finalize call to a function taking either one or two arguments.
        template<class Fun,
                 class State,
                 bool AcceptsTwoArgs = detail::is_callable_with<Fun, State &, const error &>::value>
        struct stream_finalize_trait;

        /// Specializes the trait for callbacks that only take the state.
        template<class Fun, class State>
        struct stream_finalize_trait<Fun, State, false> {
            static void invoke(Fun &f, State &st, const error &) {
                static_assert(detail::is_callable_with<Fun, State &>::value,
                              "Finalize function neither accepts (State&, const error&) "
                              "nor (State&)");
                f(st);
            }
        };

        /// Specializes the trait for callbacks that take state and error.
        template<class Fun, class State>
        struct stream_finalize_trait<Fun, State, true> {
            static void invoke(Fun &f, State &st, const error &err) {
                f(st, err);
            }
        };

    }    // namespace actor
}    // namespace nil
