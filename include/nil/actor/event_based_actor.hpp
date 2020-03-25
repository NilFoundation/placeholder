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

#include <type_traits>

#include <nil/actor/fwd.hpp>
#include <nil/actor/extend.hpp>
#include <nil/actor/local_actor.hpp>
#include <nil/actor/actor_marker.hpp>
#include <nil/actor/response_handle.hpp>
#include <nil/actor/scheduled_actor.hpp>

#include <nil/actor/mixin/sender.hpp>
#include <nil/actor/mixin/requester.hpp>
#include <nil/actor/mixin/subscriber.hpp>
#include <nil/actor/mixin/behavior_changer.hpp>

#include <nil/actor/logger.hpp>

namespace nil {
    namespace actor {

        template<>
        class behavior_type_of<event_based_actor> {
        public:
            using type = behavior;
        };

        /// A cooperatively scheduled, event-based actor implementation. This is the
        /// recommended base class for user-defined actors.
        /// @extends scheduled_actor
        class event_based_actor
            : public extend<scheduled_actor, event_based_actor>::with<mixin::sender, mixin::requester,
                                                                      mixin::subscriber, mixin::behavior_changer>,
              public dynamically_typed_actor_base {
        public:
            // -- member types -----------------------------------------------------------

            /// Required by `spawn` for type deduction.
            using signatures = none_t;

            /// Required by `spawn` for type deduction.
            using behavior_type = behavior;

            // -- constructors, destructors ----------------------------------------------

            explicit event_based_actor(actor_config &cfg);

            ~event_based_actor() override;

            // -- overridden functions of local_actor ------------------------------------

            void initialize() override;

        protected:
            // -- behavior management ----------------------------------------------------

            /// Returns the initial actor behavior.
            virtual behavior make_behavior();
        };

    }    // namespace actor
}    // namespace nil
