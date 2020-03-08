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

#include <nil/actor/policy/work_stealing.hpp>

#include <nil/actor/spawner_config.hpp>
#include <nil/actor/defaults.hpp>
#include <nil/actor/scheduler/abstract_coordinator.hpp>

#define CONFIG(str_name, var_name) get_or(p->config(), "work-stealing." str_name, defaults::work_stealing::var_name)

namespace nil {
    namespace actor {
        namespace policy {

            work_stealing::~work_stealing() {
                // nop
            }

            work_stealing::worker_data::worker_data(scheduler::abstract_coordinator *p) :
                rengine(std::random_device {}()),
                // no need to worry about wrap-around; if `p->num_workers() < 2`,
                // `uniform` will not be used anyway
                uniform(0, p->num_workers() - 2), strategies {{{p->config().work_stealing_aggressive_poll_attempts, 1,
                                                                p->config().work_stealing_aggressive_steal_interval,
                                                                timespan {0}},
                                                               {p->config().work_stealing_moderate_poll_attempts, 1,
                                                                p->config().work_stealing_moderate_steal_interval,
                                                                p->config().work_stealing_moderate_sleep_duration},
                                                               {1, 0, p->config().work_stealing_relaxed_steal_interval,
                                                                p->config().work_stealing_relaxed_sleep_duration}}} {
                // nop
            }

            work_stealing::worker_data::worker_data(const worker_data &other) :
                rengine(std::random_device {}()), uniform(other.uniform), strategies(other.strategies) {
                // nop
            }

        }    // namespace policy
    }        // namespace actor
}    // namespace nil
