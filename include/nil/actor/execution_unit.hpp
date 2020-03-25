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

#include <nil/actor/fwd.hpp>

#include <nil/actor/config.hpp>

namespace nil {
    namespace actor {

        /// Identifies an execution unit, e.g., a worker thread of the scheduler. By
        /// querying its execution unit, an actor can access other context information.
        class execution_unit {
        public:
            explicit execution_unit(spawner *sys);

            execution_unit() = default;
            execution_unit(execution_unit &&) = default;
            execution_unit &operator=(execution_unit &&) = default;
            execution_unit(const execution_unit &) = default;
            execution_unit &operator=(const execution_unit &) = default;

            virtual ~execution_unit();

            /// Enqueues `ptr` to the job list of the execution unit.
            /// @warning Must only be called from a {@link resumable} currently
            ///          executed by this execution unit.
            virtual void exec_later(resumable *ptr) = 0;

            /// Returns the enclosing actor system.
            /// @warning Must be set before the execution unit calls `resume` on an actor.
            spawner &system() const {
                ACTOR_ASSERT(system_ != nullptr);
                return *system_;
            }

            /// Returns a pointer to the proxy factory currently associated to this unit.
            proxy_registry *proxy_registry_ptr() {
                return proxies_;
            }

            /// Associated a new proxy factory to this unit.
            void proxy_registry_ptr(proxy_registry *ptr) {
                proxies_ = ptr;
            }

        protected:
            spawner *system_ = nullptr;
            proxy_registry *proxies_ = nullptr;
        };

    }    // namespace actor
}    // namespace nil
