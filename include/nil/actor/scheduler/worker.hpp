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

#include <cstddef>

#include <nil/actor/detail/double_ended_queue.hpp>
#include <nil/actor/detail/set_thread_name.hpp>
#include <nil/actor/execution_unit.hpp>
#include <nil/actor/logger.hpp>
#include <nil/actor/resumable.hpp>

namespace nil {
    namespace actor {
        namespace scheduler {

            template<class Policy>
            class coordinator;

            /// Policy-based implementation of the abstract worker base class.
            template<class Policy>
            class worker : public execution_unit {
            public:
                using job_ptr = resumable *;
                using coordinator_ptr = coordinator<Policy> *;
                using policy_data = typename Policy::worker_data;

                worker(size_t worker_id, coordinator_ptr worker_parent, const policy_data &init, size_t throughput) :
                    execution_unit(&worker_parent->system()), max_throughput_(throughput), id_(worker_id),
                    parent_(worker_parent), data_(init) {
                    // nop
                }

                void start() {
                    ACTOR_ASSERT(this_thread_.get_id() == std::thread::id {});
                    auto this_worker = this;
                    this_thread_ = std::thread {[this_worker] {
                        ACTOR_SET_LOGGER_SYS(&this_worker->system());
                        detail::set_thread_name("actor.multiplexer");
                        this_worker->system().thread_started();
                        this_worker->run();
                        this_worker->system().thread_terminates();
                    }};
                }

                worker(const worker &) = delete;
                worker &operator=(const worker &) = delete;

                /// Enqueues a new job to the worker's queue from an external
                /// source, i.e., from any other thread.
                void external_enqueue(job_ptr job) {
                    ACTOR_ASSERT(job != nullptr);
                    policy_.external_enqueue(this, job);
                }

                /// Enqueues a new job to the worker's queue from an internal
                /// source, i.e., a job that is currently executed by this worker.
                /// @warning Must not be called from other threads.
                void exec_later(job_ptr job) override {
                    ACTOR_ASSERT(job != nullptr);
                    policy_.internal_enqueue(this, job);
                }

                coordinator_ptr parent() {
                    return parent_;
                }

                size_t id() const {
                    return id_;
                }

                std::thread &get_thread() {
                    return this_thread_;
                }

                actor_id id_of(resumable *ptr) {
                    abstract_actor *dptr = ptr != nullptr ? dynamic_cast<abstract_actor *>(ptr) : nullptr;
                    return dptr != nullptr ? dptr->id() : 0;
                }

                policy_data &data() {
                    return data_;
                }

                size_t max_throughput() {
                    return max_throughput_;
                }

            private:
                void run() {
                    ACTOR_SET_LOGGER_SYS(&system());
                    // scheduling loop
                    for (;;) {
                        auto job = policy_.dequeue(this);
                        ACTOR_ASSERT(job != nullptr);
                        ACTOR_ASSERT(job->subtype() != resumable::io_actor);
                        ACTOR_PUSH_AID_FROM_PTR(dynamic_cast<abstract_actor *>(job));
                        policy_.before_resume(this, job);
                        auto res = job->resume(this, max_throughput_);
                        policy_.after_resume(this, job);
                        switch (res) {
                            case resumable::resume_later: {
                                // keep reference to this actor, as it remains in the "loop"
                                policy_.resume_job_later(this, job);
                                break;
                            }
                            case resumable::done: {
                                policy_.after_completion(this, job);
                                intrusive_ptr_release(job);
                                break;
                            }
                            case resumable::awaiting_message: {
                                // resumable will maybe be enqueued again later, deref it for now
                                intrusive_ptr_release(job);
                                break;
                            }
                            case resumable::shutdown_execution_unit: {
                                policy_.after_completion(this, job);
                                policy_.before_shutdown(this);
                                return;
                            }
                        }
                    }
                }
                // number of messages each actor is allowed to consume per resume
                size_t max_throughput_;
                // the worker's thread
                std::thread this_thread_;
                // the worker's ID received from scheduler
                size_t id_;
                // pointer to central coordinator
                coordinator_ptr parent_;
                // scheduler_policy-specific data
                policy_data data_;
                // instance of our scheduler_policy object
                Policy policy_;
            };

        }    // namespace scheduler
    }        // namespace actor
}    // namespace nil
