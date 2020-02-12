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

#include <unordered_set>

#include <nil/actor/fwd.hpp>
#include <nil/actor/group.hpp>

namespace nil {
    namespace actor {
        namespace mixin {

            /// Marker for `subscriber`.
            struct subscriber_base {};

            /// A `subscriber` is an actor that can subscribe
            /// to a `group` via `self->join(...)`.
            template<class Base, class Subtype>
            class subscriber : public Base, public subscriber_base {
            public:
                // -- member types -----------------------------------------------------------

                /// Allows subtypes to refer mixed types with a simple name.
                using extended_base = subscriber;

                /// A container for storing subscribed groups.
                using subscriptions = std::unordered_set<group>;

                // -- constructors, destructors, and assignment operators --------------------

                template<class... Ts>
                subscriber(actor_config &cfg, Ts &&... xs) : Base(cfg, std::forward<Ts>(xs)...) {
                    if (cfg.groups != nullptr)
                        for (auto &grp : *cfg.groups)
                            join(grp);
                }

                // -- overridden functions of monitorable_actor ------------------------------

                bool cleanup(error &&fail_state, execution_unit *ptr) override {
                    auto me = dptr()->ctrl();
                    for (auto &subscription : subscriptions_)
                        subscription->unsubscribe(me);
                    subscriptions_.clear();
                    return Base::cleanup(std::move(fail_state), ptr);
                }

                // -- group management -------------------------------------------------------

                /// Causes this actor to subscribe to the group `what`.
                /// The group will be unsubscribed if the actor finishes execution.
                void join(const group &what) {
                    ACTOR_LOG_TRACE(ACTOR_ARG(what));
                    if (what == invalid_group)
                        return;
                    if (what->subscribe(dptr()->ctrl()))
                        subscriptions_.emplace(what);
                }

                /// Causes this actor to leave the group `what`.
                void leave(const group &what) {
                    ACTOR_LOG_TRACE(ACTOR_ARG(what));
                    if (subscriptions_.erase(what) > 0)
                        what->unsubscribe(dptr()->ctrl());
                }

                /// Returns all subscribed groups.
                const subscriptions &joined_groups() const {
                    return subscriptions_;
                }

            private:
                Subtype *dptr() {
                    return static_cast<Subtype *>(this);
                }

                // -- data members -----------------------------------------------------------

                /// Stores all subscribed groups.
                subscriptions subscriptions_;
            };

        }    // namespace mixin
    }        // namespace actor
}    // namespace nil
