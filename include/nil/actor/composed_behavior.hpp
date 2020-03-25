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

#include <nil/actor/param.hpp>
#include <nil/actor/composable_behavior.hpp>
#include <nil/actor/typed_actor_pointer.hpp>

namespace nil {
    namespace actor {

        template<class... Ts>
        class composed_behavior : public Ts... {
        public:
            using signatures = typename detail::tl_union<typename Ts::signatures...>::type;

            using handle_type = typename detail::tl_apply<signatures, typed_actor>::type;

            using behavior_type = typename handle_type::behavior_type;

            using actor_base = typename handle_type::base;

            using broker_base = typename handle_type::broker_base;

            using self_pointer = typename detail::tl_apply<signatures, typed_actor_pointer>::type;

            composed_behavior() : self(nullptr) {
                // nop
            }

            template<class SelfPointer>
            unit_t init_selfptr(SelfPointer x) {
                BOOST_ASSERT(x != nullptr);
                self = x;
                return unit(static_cast<Ts *>(this)->init_selfptr(x)...);
            }

            void init_behavior(message_handler &x) override {
                init_behavior_impl(x);
            }

            unit_t init_behavior_impl(message_handler &x) {
                return unit(static_cast<Ts *>(this)->init_behavior_impl(x)...);
            }

        protected:
            self_pointer self;
        };

    }    // namespace actor
}    // namespace nil
