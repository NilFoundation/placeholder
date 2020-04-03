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

#include <chrono>
#include <string>

#include <nil/actor/fwd.hpp>

namespace nil {
    namespace actor {

        /// A monotonic clock for scheduling timeouts and delayed messages.
        class BOOST_SYMBOL_VISIBLE actor_clock {
        public:
            // -- member types -----------------------------------------------------------

            /// Underlying clock type.
            using clock_type = std::chrono::steady_clock;

            /// Discrete point in time.
            using time_point = typename clock_type::time_point;

            /// Time interval.
            using duration_type = typename clock_type::duration;

            // -- constructors, destructors, and assignment operators --------------------

            virtual ~actor_clock();

            // -- observers --------------------------------------------------------------

            /// Returns the current wall-clock time.
            virtual time_point now() const noexcept;

            /// Schedules a `timeout_msg` for `self` at time point `t`, overriding any
            /// previous receive timeout.
            virtual void set_ordinary_timeout(time_point t, abstract_actor *self, std::string type, uint64_t id) = 0;

            /// Schedules a `timeout_msg` for `self` at time point `t`.
            virtual void set_multi_timeout(time_point t, abstract_actor *self, std::string type, uint64_t id) = 0;

            /// Schedules a `sec::request_timeout` for `self` at time point `t`.
            virtual void set_request_timeout(time_point t, abstract_actor *self, message_id id) = 0;

            /// Cancels a pending receive timeout.
            virtual void cancel_ordinary_timeout(abstract_actor *self, std::string type) = 0;

            /// Cancels the pending request timeout for `id`.
            virtual void cancel_request_timeout(abstract_actor *self, message_id id) = 0;

            /// Cancels all timeouts for `self`.
            virtual void cancel_timeouts(abstract_actor *self) = 0;

            /// Schedules an arbitrary message to `receiver` for time point `t`.
            virtual void schedule_message(time_point t, strong_actor_ptr receiver, mailbox_element_ptr content) = 0;

            /// Schedules an arbitrary message to `target` for time point `t`.
            virtual void schedule_message(time_point t, group target, strong_actor_ptr sender, message content) = 0;

            /// Cancels all timeouts and scheduled messages.
            virtual void cancel_all() = 0;
        };

    }    // namespace actor
}    // namespace nil