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

#include <nil/actor/defaults.hpp>

#include <algorithm>
#include <chrono>
#include <limits>
#include <thread>

using std::max;
using std::min;

namespace {

    using us_t = std::chrono::microseconds;

    constexpr nil::actor::timespan us(us_t::rep x) {
        return std::chrono::duration_cast<nil::actor::timespan>(us_t {x});
    }

    using ms_t = std::chrono::milliseconds;

    constexpr nil::actor::timespan ms(ms_t::rep x) {
        return std::chrono::duration_cast<nil::actor::timespan>(ms_t {x});
    }

}    // namespace

namespace nil {
    namespace actor {
        namespace defaults {

            namespace stream {

                const timespan desired_batch_complexity = us(50);
                const timespan max_batch_delay = ms(5);
                const timespan credit_round_interval = ms(10);

            }    // namespace stream

            namespace scheduler {

                const atom_value policy = atom("stealing");
                std::string profiling_output_file = "";
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

                std::string component_filter = "";
                const atom_value console = atom("none");
                std::string console_format = "%m";
                const atom_value console_verbosity = atom("trace");
                std::string file_format = "%r %c %p %a %t %C %M %F:%L %m%n";
                std::string file_name = "actor_log_[PID]_[TIMESTAMP]_[NODE].log";
                const atom_value file_verbosity = atom("trace");

            }    // namespace logger

            namespace middleman {

                std::vector<std::string> app_identifiers {"generic-actor-app"};
                const atom_value network_backend = atom("default");
                const size_t max_consecutive_reads = 50;
                const size_t heartbeat_interval = 0;
                const size_t cached_udp_buffers = 10;
                const size_t max_pending_msgs = 10;
                const size_t workers = min(3u, std::thread::hardware_concurrency() / 4u) + 1;

            }    // namespace middleman

        }    // namespace defaults
    }        // namespace actor
}    // namespace nil
