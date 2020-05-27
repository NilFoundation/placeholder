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

// -- hard-coded default values for various =nil; Actor options ------------------------

namespace nil {
    namespace actor {
        namespace defaults {
            namespace detail {
                namespace {

                    static constexpr nil::actor::string_view default_log_level =
#if ACTOR_LOG_LEVEL == ACTOR_LOG_LEVEL_TRACE
                        "trace";
#elif ACTOR_LOG_LEVEL == ACTOR_LOG_LEVEL_DEBUG
                        "debug";
#elif ACTOR_LOG_LEVEL == ACTOR_LOG_LEVEL_INFO
                        "info";
#elif ACTOR_LOG_LEVEL == ACTOR_LOG_LEVEL_WARNING
                        "warning";
#elif ACTOR_LOG_LEVEL == ACTOR_LOG_LEVEL_ERROR
                        "error";
#else
                        "quiet";
#endif

                    using us_t = std::chrono::microseconds;

                    constexpr nil::actor::timespan us(us_t::rep x) {
                        return std::chrono::duration_cast<nil::actor::timespan>(us_t {x});
                    }

                    using ms_t = std::chrono::milliseconds;

                    constexpr nil::actor::timespan ms(ms_t::rep x) {
                        return std::chrono::duration_cast<nil::actor::timespan>(ms_t {x});
                    }

                }    // namespace
            }        // namespace detail

            namespace stream {
                BOOST_SYMBOL_VISIBLE static const timespan desired_batch_complexity = detail::us(50);
                BOOST_SYMBOL_VISIBLE static const timespan max_batch_delay = detail::ms(5);
                BOOST_SYMBOL_VISIBLE static const timespan credit_round_interval = detail::ms(10);
                BOOST_SYMBOL_VISIBLE static const string_view credit_policy = "complexity";

                namespace size_policy {

                    BOOST_SYMBOL_VISIBLE static const int32_t bytes_per_batch = 2048;         // 2 KB
                    BOOST_SYMBOL_VISIBLE static const int32_t buffer_capacity = 64 * 1024;    // 64 KB

                }    // namespace size_policy

            }    // namespace stream

            namespace scheduler {

                BOOST_SYMBOL_VISIBLE static const string_view policy = "stealing";
                BOOST_SYMBOL_VISIBLE static string_view profiling_output_file = "";
                BOOST_SYMBOL_VISIBLE static const size_t max_threads =
                    std::max(std::thread::hardware_concurrency(), 4u);
                BOOST_SYMBOL_VISIBLE static const size_t max_throughput = std::numeric_limits<size_t>::max();
                BOOST_SYMBOL_VISIBLE static const timespan profiling_resolution = detail::ms(100);

            }    // namespace scheduler

            namespace work_stealing {

                BOOST_SYMBOL_VISIBLE static const size_t aggressive_poll_attempts = 100;
                BOOST_SYMBOL_VISIBLE static const size_t aggressive_steal_interval = 10;
                BOOST_SYMBOL_VISIBLE static const size_t moderate_poll_attempts = 500;
                BOOST_SYMBOL_VISIBLE static const size_t moderate_steal_interval = 5;
                BOOST_SYMBOL_VISIBLE static const timespan moderate_sleep_duration = detail::us(50);
                BOOST_SYMBOL_VISIBLE static const size_t relaxed_steal_interval = 1;
                BOOST_SYMBOL_VISIBLE static const timespan relaxed_sleep_duration = detail::ms(10);

            }    // namespace work_stealing

            namespace logger {

                BOOST_SYMBOL_VISIBLE static string_view component_filter = "";
                BOOST_SYMBOL_VISIBLE static const string_view console = "none";
                BOOST_SYMBOL_VISIBLE static string_view console_format = "%m";
                BOOST_SYMBOL_VISIBLE static const string_view console_verbosity = detail::default_log_level;
                BOOST_SYMBOL_VISIBLE static string_view file_format = "%r %c %p %a %t %C %M %F:%L %m%n";
                BOOST_SYMBOL_VISIBLE static string_view file_name = "actor_log_[PID]_[TIMESTAMP]_[NODE].log";
                BOOST_SYMBOL_VISIBLE static const string_view file_verbosity = detail::default_log_level;

            }    // namespace logger
        }        // namespace defaults
    }            // namespace actor
}    // namespace nil