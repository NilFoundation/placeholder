//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
//
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#pragma once

#include <nil/actor/attachable.hpp>

#include <nil/actor/detail/type_list.hpp>
#include <nil/actor/detail/type_traits.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            template<class F, int Args = tl_size<typename get_callable_trait<F>::arg_types>::value>
            struct functor_attachable : attachable {
                static_assert(Args == 1 || Args == 2, "Only 0, 1 or 2 arguments for F are supported");
                F functor_;
                functor_attachable(F arg) : functor_(std::move(arg)) {
                    // nop
                }
                void actor_exited(const error &fail_state, execution_unit *) override {
                    functor_(fail_state);
                }
                static constexpr size_t token_type = attachable::token::anonymous;
            };

            template<class F>
            struct functor_attachable<F, 2> : attachable {
                F functor_;
                functor_attachable(F arg) : functor_(std::move(arg)) {
                    // nop
                }
                void actor_exited(const error &x, execution_unit *y) override {
                    functor_(x, y);
                }
            };

            template<class F>
            struct functor_attachable<F, 0> : attachable {
                F functor_;
                functor_attachable(F arg) : functor_(std::move(arg)) {
                    // nop
                }
                void actor_exited(const error &, execution_unit *) override {
                    functor_();
                }
            };

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
