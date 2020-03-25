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

#include <memory>
#include <unordered_map>

#include <nil/actor/logger.hpp>
#include <nil/actor/ref_counted.hpp>
#include <nil/actor/scheduled_actor.hpp>
#include <nil/actor/stream_manager.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            /// A stream distribution tree consist of peers forming an acyclic graph. The
            /// user is responsible for making sure peers do not form a loop. Data is
            /// flooded along the tree. Each peer serves any number of subscribers. The
            /// policy of the tree enables subscriptions to different chunks of the whole
            /// stream (substreams).
            ///
            /// The tree uses two ACTOR streams between each pair of peers for transmitting
            /// data. This automatically adds backpressure to the system, i.e., no peer can
            /// overwhelm others.
            ///
            /// Policies need to provide the following member types and functions:
            ///
            /// ~~~{.cpp}
            /// TODO
            /// };
            /// ~~~
            template<class Policy>
            class stream_distribution_tree : public stream_manager {
            public:
                // -- nested types -----------------------------------------------------------

                using super = stream_manager;

                using downstream_manager_type = typename Policy::downstream_manager_type;

                // --- constructors and destructors ------------------------------------------

                template<class... Ts>
                stream_distribution_tree(scheduled_actor *selfptr, Ts &&... xs) :
                    super(selfptr), out_(this), policy_(this, std::forward<Ts>(xs)...) {
                    continuous(true);
                }

                ~stream_distribution_tree() override {
                    // nop
                }

                // -- Accessors --------------------------------------------------------------

                inline Policy &policy() {
                    return policy_;
                }

                inline const Policy &policy() const {
                    return policy_;
                }

                // -- overridden member functions of `stream_manager` ------------------------

                void handle(inbound_path *path, downstream_msg::batch &x) override {
                    ACTOR_LOG_TRACE(ACTOR_ARG(path) << ACTOR_ARG(x));
                    auto slot = path->slots.receiver;
                    policy_.before_handle_batch(slot, path->hdl);
                    policy_.handle_batch(slot, path->hdl, x.xs);
                    policy_.after_handle_batch(slot, path->hdl);
                }

                void handle(inbound_path *path, downstream_msg::close &x) override {
                    ACTOR_LOG_TRACE(ACTOR_ARG(path) << ACTOR_ARG(x));
                    ACTOR_IGNORE_UNUSED(x);
                    policy_.path_closed(path->slots.receiver);
                }

                void handle(inbound_path *path, downstream_msg::forced_close &x) override {
                    ACTOR_LOG_TRACE(ACTOR_ARG(path) << ACTOR_ARG(x));
                    policy_.path_force_closed(path->slots.receiver, x.reason);
                }

                bool handle(stream_slots slots, upstream_msg::ack_open &x) override {
                    ACTOR_LOG_TRACE(ACTOR_ARG(slots) << ACTOR_ARG(x));
                    auto rebind_from = x.rebind_from;
                    auto rebind_to = x.rebind_to;
                    if (super::handle(slots, x)) {
                        policy_.ack_open_success(slots.receiver, rebind_from, rebind_to);
                        return true;
                    }
                    policy_.ack_open_failure(slots.receiver, rebind_from, rebind_to);
                    return false;
                }

                void handle(stream_slots slots, upstream_msg::drop &x) override {
                    ACTOR_LOG_TRACE(ACTOR_ARG(slots) << ACTOR_ARG(x));
                    ACTOR_IGNORE_UNUSED(x);
                    super::handle(slots, x);
                }

                void handle(stream_slots slots, upstream_msg::forced_drop &x) override {
                    ACTOR_LOG_TRACE(ACTOR_ARG(slots) << ACTOR_ARG(x));
                    ACTOR_IGNORE_UNUSED(x);
                    auto slot = slots.receiver;
                    if (out().remove_path(slots.receiver, x.reason, true))
                        policy_.path_force_dropped(slot, x.reason);
                }

                bool done() const override {
                    return !continuous() && pending_handshakes_ == 0 && inbound_paths_.empty() && out_.clean();
                }

                bool idle() const noexcept override {
                    // Same as `stream_stage<...>`::idle().
                    return out_.stalled() || (out_.clean() && this->inbound_paths_idle());
                }

                downstream_manager_type &out() override {
                    return out_;
                }

            private:
                downstream_manager_type out_;
                Policy policy_;
            };

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
