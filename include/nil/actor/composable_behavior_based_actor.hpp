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

#include <nil/actor/stateful_actor.hpp>
#include <nil/actor/message_handler.hpp>

namespace nil {
    namespace actor {

        /// Implementation class for spawning composable states directly as actors.
        template<class State, class Base = typename State::actor_base>
        class composable_behavior_based_actor : public stateful_actor<State, Base> {
        public:
            static_assert(!std::is_abstract<State>::value,
                          "State is abstract, please make sure to override all "
                          "virtual operator() member functions");

            using super = stateful_actor<State, Base>;

            composable_behavior_based_actor(actor_config &cfg) : super(cfg) {
                // nop
            }

            using behavior_type = typename State::behavior_type;

            behavior_type make_behavior() override {
                this->state.init_selfptr(this);
                message_handler tmp;
                this->state.init_behavior(tmp);
                return behavior_type {typename behavior_type::unsafe_init {}, std::move(tmp)};
            }
        };

    }    // namespace actor
}    // namespace nil
