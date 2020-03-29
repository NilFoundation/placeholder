//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#include <nil/actor/defaults.hpp>

#include <algorithm>
#include <chrono>
#include <limits>
#include <thread>

#include <nil/actor/detail/build_config.hpp>
#include <nil/actor/detail/log_level.hpp>

using std::max;
using std::min;

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

namespace nil::actor::defaults {

    namespace stream {

        const timespan desired_batch_complexity = us(50);
        const timespan max_batch_delay = ms(5);
        const timespan credit_round_interval = ms(10);
        const string_view credit_policy = "complexity";

        namespace size_policy {

            const int32_t bytes_per_batch = 2048;         // 2 KB
            const int32_t buffer_capacity = 64 * 1024;    // 64 KB

        }    // namespace size_policy

    }    // namespace stream

    namespace scheduler {

        const string_view policy = "stealing";
        string_view profiling_output_file = "";
        const size_t max_threads = max(std::thread::hardware_concurrency(), 4u);
        const size_t max_throughput = std::numeric_limits<size_t>::max();
        const timespan profiling_resolution = ms(100);

    }    // namespace scheduler

    namespace work_stealing {

        const size_t aggressive_poll_attempts = 100;
        const size_t aggressive_steal_interval = 10;
        const size_t moderate_poll_attempts = 500;
        const size_t moderate_steal_interval = 5;
        const timespan moderate_sleep_duration = us(50);
        const size_t relaxed_steal_interval = 1;
        const timespan relaxed_sleep_duration = ms(10);

    }    // namespace work_stealing

    namespace logger {

        string_view component_filter = "";
        const string_view console = "none";
        string_view console_format = "%m";
        const string_view console_verbosity = default_log_level;
        string_view file_format = "%r %c %p %a %t %C %M %F:%L %m%n";
        string_view file_name = "actor_log_[PID]_[TIMESTAMP]_[NODE].log";
        const string_view file_verbosity = default_log_level;

    }    // namespace logger

    namespace middleman {

        std::vector<std::string> app_identifiers {"generic-caf-app"};
        const string_view network_backend = "default";
        const size_t max_consecutive_reads = 50;
        const size_t heartbeat_interval = 0;
        const size_t cached_udp_buffers = 10;
        const size_t max_pending_msgs = 10;
        const size_t workers = min(3u, std::thread::hardware_concurrency() / 4u) + 1;

    }    // namespace middleman

}    // namespace nil::actor::defaults