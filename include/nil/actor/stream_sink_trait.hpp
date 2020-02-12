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

#include <nil/actor/make_message.hpp>
#include <nil/actor/message.hpp>
#include <nil/actor/stream_sink.hpp>

#include <nil/actor/detail/type_traits.hpp>

namespace nil {
    namespace actor {

        namespace detail {

            // -- invoke helper to support element-wise and batch-wise processing ----------

            struct stream_sink_trait_invoke_one {
                template<class F, class State, class In>
                static void invoke(F &f, State &st, std::vector<In> &xs) {
                    for (auto &x : xs)
                        f(st, std::move(x));
                }
            };

            struct stream_sink_trait_invoke_all {
                template<class F, class State, class In>
                static void invoke(F &f, State &st, std::vector<In> &xs) {
                    f(st, xs);
                }
            };

        }    // namespace detail

        // -- trait implementation -----------------------------------------------------

        /// Base type for all sink traits.
        template<class State, class In>
        struct stream_sink_trait_base {
            /// Defines the state element for the function objects.
            using state = State;

            /// Defines the type of a single stream element.
            using input = In;

            /// Defines a pointer to a sink.
            using pointer = stream_sink_ptr<input>;
        };

        /// Defines required type aliases for stream sinks.
        template<class Fun>
        struct stream_sink_trait;

        /// Specializes the trait for element-wise processing.
        template<class State, class In>
        struct stream_sink_trait<void(State &, In)> : stream_sink_trait_base<State, In> {
            /// Defines a helper for dispatching to the processing function object.
            using process = detail::stream_sink_trait_invoke_one;
        };

        /// Specializes the trait for batch-wise processing.
        template<class State, class In>
        struct stream_sink_trait<void(State &, std::vector<In> &)> : stream_sink_trait_base<State, In> {
            /// Defines a helper for dispatching to the processing function object.
            using process = detail::stream_sink_trait_invoke_all;
        };

        /// Specializes the trait for batch-wise processing with const references.
        template<class State, class In>
        struct stream_sink_trait<void(State &, const std::vector<In> &)> : stream_sink_trait_base<State, In> {
            /// Defines a helper for dispatching to the processing function object.
            using process = detail::stream_sink_trait_invoke_all;
        };

        // -- convenience alias --------------------------------------------------------

        /// Derives a sink trait from the signatures of Fun and Fin.
        template<class Fun>
        using stream_sink_trait_t = stream_sink_trait<typename detail::get_callable_trait<Fun>::fun_sig>;

    }    // namespace actor
}    // namespace nil
