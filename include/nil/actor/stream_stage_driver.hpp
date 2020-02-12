//---------------------------------------------------------------------------//
// Copyright (c) 2011-2017 Dominik Charousset
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <tuple>
#include <vector>

#include <nil/actor/fwd.hpp>
#include <nil/actor/message.hpp>

namespace nil {
    namespace actor {

        /// Encapsulates user-provided functionality for generating a stream stage.
        template<class Input, class DownstreamManager>
        class stream_stage_driver {
        public:
            // -- member types -----------------------------------------------------------

            /// Element type of the input stream.
            using input_type = Input;

            /// Policy for distributing data to outbound paths.
            using downstream_manager_type = DownstreamManager;

            /// Element type of the output stream.
            using output_type = typename downstream_manager_type::output_type;

            /// Type of the output stream.
            using stream_type = stream<output_type>;

            /// Implemented `stream_stage` interface.
            using stage_type = stream_stage<input_type, DownstreamManager>;

            /// Smart pointer to the interface type.
            using stage_ptr_type = intrusive_ptr<stage_type>;

            // -- constructors, destructors, and assignment operators --------------------

            stream_stage_driver(DownstreamManager &out) : out_(out) {
                // nop
            }

            virtual ~stream_stage_driver() {
                // nop
            }

            // -- virtual functions ------------------------------------------------------

            /// Processes a single batch.
            virtual void process(downstream<output_type> &out, std::vector<input_type> &batch) = 0;

            /// Cleans up any state.
            virtual void finalize(const error &) {
                // nop
            }

            /// Can mark the stage as congested. The default implementation signals a
            /// congestion if the downstream manager has no capacity left in its buffer.
            virtual bool congested() const noexcept {
                return out_.capacity() == 0;
            }

            /// Acquires credit on an inbound path. The calculated credit to fill our
            /// queue fro two cycles is `desired`, but the driver is allowed to return
            /// any non-negative value.
            virtual int32_t acquire_credit(inbound_path *path, int32_t desired) {
                ACTOR_IGNORE_UNUSED(path);
                return desired;
            }

        protected:
            DownstreamManager &out_;
        };

    }    // namespace actor
}    // namespace nil
