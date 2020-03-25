//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt or
// http://opensource.org/licenses/BSD-3-Clause
//---------------------------------------------------------------------------//

#pragma once

#include <nil/actor/param.hpp>
#include <nil/actor/behavior.hpp>
#include <nil/actor/replies_to.hpp>
#include <nil/actor/typed_actor.hpp>
#include <nil/actor/typed_actor_pointer.hpp>
#include <nil/actor/abstract_composable_behavior.hpp>

namespace nil {
    namespace actor {

        /// Generates an interface class that provides `operator()`. The signature
        /// of the apply operator is derived from the typed message passing interface
        /// `MPI`.
        template<class MPI>
        class composable_behavior_base;

        template<class... Xs, class... Ys>
        class composable_behavior_base<typed_mpi<detail::type_list<Xs...>, output_tuple<Ys...>>> {
        public:
            virtual ~composable_behavior_base() noexcept {
                // nop
            }

            virtual result<Ys...> operator()(param_t<Xs>...) = 0;

            // C++14 and later
#if __cplusplus > 201103L
            auto make_callback() {
                return [=](param_t<Xs>... xs) { return (*this)(std::move(xs)...); };
            }
#else
            // C++11
            std::function<result<Ys...>(param_t<Xs>...)> make_callback() {
                return [=](param_t<Xs>... xs) { return (*this)(std::move(xs)...); };
            }
#endif
        };

        /// Base type for composable actor states.
        template<class TypedActor>
        class composable_behavior;

        template<class... Clauses>
        class composable_behavior<typed_actor<Clauses...>> : virtual public abstract_composable_behavior,
                                                             public composable_behavior_base<Clauses>... {
        public:
            using signatures = detail::type_list<Clauses...>;

            using handle_type = typename detail::tl_apply<signatures, typed_actor>::type;

            using actor_base = typename handle_type::base;

            using broker_base = typename handle_type::broker_base;

            using behavior_type = typename handle_type::behavior_type;

            composable_behavior() : self(nullptr) {
                // nop
            }

            template<class SelfPointer>
            unit_t init_selfptr(SelfPointer x) {
                BOOST_ASSERT(x != nullptr);
                self = x;
                return unit;
            }

            void init_behavior(message_handler &x) override {
                init_behavior_impl(x);
            }

            unit_t init_behavior_impl(message_handler &x) {
                if (x)
                    x = x.or_else(composable_behavior_base<Clauses>::make_callback()...);
                else
                    x.assign(composable_behavior_base<Clauses>::make_callback()...);
                return unit;
            }

            typed_actor_pointer<Clauses...> self;
        };

    }    // namespace actor
}    // namespace nil
