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

#include <nil/actor/resumable.hpp>
#include <nil/actor/abstract_actor.hpp>

namespace nil {
    namespace actor {

        namespace scheduler {

            template<class>
            class profiled_coordinator;

        }    // namespace scheduler

        namespace policy {

            /// An enhancement of ACTOR's scheduling policy which records fine-grained
            /// resource utiliziation for worker threads and actors in the parent
            /// coordinator of the workers.
            template<class Policy>
            struct profiled : Policy {
                using coordinator_type = scheduler::profiled_coordinator<profiled<Policy>>;

                static actor_id id_of(resumable *job) {
                    auto ptr = dynamic_cast<abstract_actor *>(job);
                    return ptr != nullptr ? ptr->id() : 0;
                }

                template<class Worker>
                void before_resume(Worker *worker, resumable *job) {
                    Policy::before_resume(worker, job);
                    auto parent = static_cast<coordinator_type *>(worker->parent());
                    parent->start_measuring(worker->id(), id_of(job));
                }

                template<class Worker>
                void after_resume(Worker *worker, resumable *job) {
                    Policy::after_resume(worker, job);
                    auto parent = static_cast<coordinator_type *>(worker->parent());
                    parent->stop_measuring(worker->id(), id_of(job));
                }

                template<class Worker>
                void after_completion(Worker *worker, resumable *job) {
                    Policy::after_completion(worker, job);
                    auto parent = static_cast<coordinator_type *>(worker->parent());
                    parent->remove_job(id_of(job));
                }
            };

        }    // namespace policy
    }        // namespace actor
}    // namespace nil
