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

#include <nil/actor/config.hpp>
#include <nil/actor/error.hpp>

#include <nil/actor/detail/type_traits.hpp>

// The class `callback` intentionally has no virtual destructor, because
// the lifetime of callback objects is never managed via base pointers.
ACTOR_PUSH_NON_VIRTUAL_DTOR_WARNING

namespace nil {
    namespace actor {

        /// Describes a simple callback, usually implemented via lambda expression.
        /// Callbacks are used as "type-safe function objects" wherever an interface
        /// requires dynamic dispatching. The alternative would be to store the lambda
        /// in a `std::function`, which adds another layer of indirection and
        /// requires a heap allocation. With the callback implementation of =nil; Actor,
        /// the object remains on the stack and does not cause more overhead
        /// than necessary.
        template<class Signature>
        class callback;

        template<class Result, class... Ts>
        class callback<Result(Ts...)> {
        public:
            virtual Result operator()(Ts...) = 0;
        };

        /// Utility class for wrapping a function object of type `F`.
        template<class F, class Signature>
        class callback_impl;

        template<class F, class Result, class... Ts>
        class callback_impl<F, Result(Ts...)> : public callback<Result(Ts...)> {
        public:
            callback_impl(F &&f) : f_(std::move(f)) {
                // nop
            }

            callback_impl(callback_impl &&) = default;

            callback_impl &operator=(callback_impl &&) = default;

            Result operator()(Ts... xs) override {
                return f_(std::forward<Ts>(xs)...);
            }

        private:
            F f_;
        };

        /// Creates a ::callback from the function object `fun`.
        /// @relates callback
        template<class F>
        auto make_callback(F fun) {
            using signature = typename detail::get_callable_trait<F>::fun_sig;
            return callback_impl<F, signature> {std::move(fun)};
        }

    }    // namespace actor
}    // namespace nil

ACTOR_POP_WARNINGS
