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
#include <cstddef>
#include <string>
#include <vector>

#include <nil/actor/string_view.hpp>
#include <nil/actor/timestamp.hpp>

// -- hard-coded default values for various CAF options ------------------------

namespace nil::actor::defaults {

    namespace stream {

        extern BOOST_SYMBOL_VISIBLE const timespan desired_batch_complexity;
        extern BOOST_SYMBOL_VISIBLE const timespan max_batch_delay;
        extern BOOST_SYMBOL_VISIBLE const timespan credit_round_interval;
        extern BOOST_SYMBOL_VISIBLE const string_view credit_policy;

        namespace size_policy {

            extern BOOST_SYMBOL_VISIBLE const int32_t bytes_per_batch;
            extern BOOST_SYMBOL_VISIBLE const int32_t buffer_capacity;

        }    // namespace size_policy

    }    // namespace stream

    namespace scheduler {

        extern BOOST_SYMBOL_VISIBLE const string_view policy;
        extern BOOST_SYMBOL_VISIBLE string_view profiling_output_file;
        extern BOOST_SYMBOL_VISIBLE const size_t max_threads;
        extern BOOST_SYMBOL_VISIBLE const size_t max_throughput;
        extern BOOST_SYMBOL_VISIBLE const timespan profiling_resolution;

    }    // namespace scheduler

    namespace work_stealing {

        extern BOOST_SYMBOL_VISIBLE const size_t aggressive_poll_attempts;
        extern BOOST_SYMBOL_VISIBLE const size_t aggressive_steal_interval;
        extern BOOST_SYMBOL_VISIBLE const size_t moderate_poll_attempts;
        extern BOOST_SYMBOL_VISIBLE const size_t moderate_steal_interval;
        extern BOOST_SYMBOL_VISIBLE const timespan moderate_sleep_duration;
        extern BOOST_SYMBOL_VISIBLE const size_t relaxed_steal_interval;
        extern BOOST_SYMBOL_VISIBLE const timespan relaxed_sleep_duration;

    }    // namespace work_stealing

    namespace logger {

        extern BOOST_SYMBOL_VISIBLE string_view component_filter;
        extern BOOST_SYMBOL_VISIBLE const string_view console;
        extern BOOST_SYMBOL_VISIBLE string_view console_format;
        extern BOOST_SYMBOL_VISIBLE const string_view console_verbosity;
        extern BOOST_SYMBOL_VISIBLE string_view file_format;
        extern BOOST_SYMBOL_VISIBLE string_view file_name;
        extern BOOST_SYMBOL_VISIBLE const string_view file_verbosity;

    }    // namespace logger

    namespace middleman {

        extern BOOST_SYMBOL_VISIBLE std::vector<std::string> app_identifiers;
        extern BOOST_SYMBOL_VISIBLE const string_view network_backend;
        extern BOOST_SYMBOL_VISIBLE const size_t max_consecutive_reads;
        extern BOOST_SYMBOL_VISIBLE const size_t heartbeat_interval;
        extern BOOST_SYMBOL_VISIBLE const size_t cached_udp_buffers;
        extern BOOST_SYMBOL_VISIBLE const size_t max_pending_msgs;
        extern BOOST_SYMBOL_VISIBLE const size_t workers;

    }    // namespace middleman

}    // namespace nil::actor::defaults