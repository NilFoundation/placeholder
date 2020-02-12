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

#include <type_traits>

#include <nil/actor/fwd.hpp>

namespace nil {
    namespace actor {
        namespace intrusive {

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

        }    // namespace intrusive
    }        // namespace actor
}    // namespace nil
