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

#include <nil/actor/event_based_actor.hpp>

namespace nil {
    namespace actor {

        /// A cooperatively raw scheduled actor is a dynamically typed actor that does
        /// not handle any system messages. All handler for system messages as well as
        /// the default handler are ignored. This actor type is for testing and
        /// system-level actors.
        /// @extends event_based_actor
        class raw_event_based_actor : public event_based_actor {
        public:
            // -- member types -----------------------------------------------------------

            /// Required by `spawn` for type deduction.
            using signatures = none_t;

            /// Required by `spawn` for type deduction.
            using behavior_type = behavior;

            // -- constructors and destructors -------------------------------------------

            explicit raw_event_based_actor(actor_config &cfg);

            invoke_message_result consume(mailbox_element &x) override;
        };

    }    // namespace actor
}    // namespace nil
