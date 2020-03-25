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

#include <type_traits>

#include <nil/actor/fwd.hpp>
#include <nil/actor/message_id.hpp>
#include <nil/actor/local_actor.hpp>
#include <nil/actor/actor_marker.hpp>
#include <nil/actor/typed_behavior.hpp>
#include <nil/actor/behavior_policy.hpp>
#include <nil/actor/response_handle.hpp>

#include <nil/actor/mixin/sender.hpp>
#include <nil/actor/mixin/requester.hpp>

namespace nil {
    namespace actor {
        namespace mixin {

            /// A `behavior_changer` is an actor that supports
            /// `self->become(...)` and `self->unbecome()`.
            template<class Base, class Subtype>
            class behavior_changer : public Base {
            public:
                // -- member types -----------------------------------------------------------

                using extended_base = behavior_changer;

                using behavior_type = typename behavior_type_of<Subtype>::type;

                // -- constructors, destructors, and assignment operators --------------------

                template<class... Ts>
                behavior_changer(Ts &&... xs) : Base(std::forward<Ts>(xs)...) {
                    // nop
                }

                // -- behavior management ----------------------------------------------------

                void become(behavior_type bhvr) {
                    dptr()->do_become(std::move(bhvr.unbox()), true);
                }

                void become(const keep_behavior_t &, behavior_type bhvr) {
                    dptr()->do_become(std::move(bhvr.unbox()), false);
                }

                template<class T0, class T1, class... Ts>
                typename std::enable_if<!std::is_same<keep_behavior_t, typename std::decay<T0>::type>::value>::type
                    become(T0 &&x0, T1 &&x1, Ts &&... xs) {
                    behavior_type bhvr {std::forward<T0>(x0), std::forward<T1>(x1), std::forward<Ts>(xs)...};
                    dptr()->do_become(std::move(bhvr.unbox()), true);
                }

                template<class T0, class T1, class... Ts>
                void become(const keep_behavior_t &, T0 &&x0, T1 &&x1, Ts &&... xs) {
                    behavior_type bhvr {std::forward<T0>(x0), std::forward<T1>(x1), std::forward<Ts>(xs)...};
                    dptr()->do_become(std::move(bhvr.unbox()), false);
                }

                void unbecome() {
                    dptr()->bhvr_stack_.pop_back();
                }

            private:
                Subtype *dptr() {
                    return static_cast<Subtype *>(this);
                }
            };

        }    // namespace mixin
    }        // namespace actor
}    // namespace nil
