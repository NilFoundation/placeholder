//---------------------------------------------------------------------------//
// Copyright (c) 2011-2017 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <string>
#include <type_traits>

#include <nil/actor/fwd.hpp>

namespace nil::actor::intrusive {

    /// Communicates the state of a consumer to a task queue.
    enum class task_result {
        /// The consumer processed the task and is ready to receive the next one.
        resume,
        /// The consumer skipped the task and is ready to receive the next one.
        /// Illegal for consumers of non-cached queues (non-cached queues treat
        /// `skip` and `resume` in the same way).
        skip,
        /// The consumer processed the task but does not accept further tasks.
        stop,
        /// The consumer processed the task but does not accept further tasks and no
        /// subsequent queue shall start a new round.
        stop_all,
    };

    std::string to_string(task_result);

}    // namespace nil::actor::intrusive