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

#include <chrono>
#include <cstddef>
#include <string>
#include <vector>

#include <nil/actor/atom.hpp>
#include <nil/actor/timestamp.hpp>

// -- hard-coded default values for various ACTOR options ------------------------

namespace nil {
    namespace actor {
        namespace defaults {

            namespace stream {

                extern const timespan desired_batch_complexity;
                extern const timespan max_batch_delay;
                extern const timespan credit_round_interval;

            }    // namespace stream

            namespace scheduler {

                extern const atom_value policy;
                extern std::string profiling_output_file;
                extern const size_t max_threads;
                extern const size_t max_throughput;
                extern const timespan profiling_resolution;

            }    // namespace scheduler

            namespace work_stealing {

                extern const size_t aggressive_poll_attempts;
                extern const size_t aggressive_steal_interval;
                extern const size_t moderate_poll_attempts;
                extern const size_t moderate_steal_interval;
                extern const timespan moderate_sleep_duration;
                extern const size_t relaxed_steal_interval;
                extern const timespan relaxed_sleep_duration;

            }    // namespace work_stealing

            namespace logger {

                extern std::string component_filter;
                extern const atom_value console;
                extern std::string console_format;
                extern const atom_value console_verbosity;
                extern std::string file_format;
                extern std::string file_name;
                extern const atom_value file_verbosity;

            }    // namespace logger

            namespace middleman {

                extern std::vector<std::string> app_identifiers;
                extern const atom_value network_backend;
                extern const size_t max_consecutive_reads;
                extern const size_t heartbeat_interval;
                extern const size_t cached_udp_buffers;
                extern const size_t max_pending_msgs;
                extern const size_t workers;

            }    // namespace middleman

        }    // namespace defaults
    }        // namespace actor
}    // namespace nil
