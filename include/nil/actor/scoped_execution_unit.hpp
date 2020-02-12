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

#pragma once

#include <nil/actor/execution_unit.hpp>

namespace nil {
    namespace actor {

        /// Identifies an execution unit, e.g., a worker thread of the scheduler. By
        /// querying its execution unit, an actor can access other context information.
        class scoped_execution_unit : public execution_unit {
        public:
            using super = execution_unit;

            using super::super;

            ~scoped_execution_unit() override;

            /// Delegates the resumable to the scheduler of `system()`.
            void exec_later(resumable *ptr) override;

            void system_ptr(spawner *ptr) noexcept {
                system_ = ptr;
            }
        };
    }    // namespace actor
}    // namespace nil
