//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#include <nil/actor/scheduler/test_coordinator.hpp>

#include <limits>

#include <nil/actor/spawner_config.hpp>
#include <nil/actor/monitorable_actor.hpp>
#include <nil/actor/raise_error.hpp>
#include <nil/actor/resumable.hpp>

namespace nil::actor::scheduler {

    namespace {

        class dummy_worker : public execution_unit {
        public:
            dummy_worker(test_coordinator *parent) : execution_unit(&parent->system()), parent_(parent) {
                // nop
            }

            void exec_later(resumable *ptr) override {
                parent_->jobs.push_back(ptr);
            }

        private:
            test_coordinator *parent_;
        };

        class dummy_printer : public monitorable_actor {
        public:
            dummy_printer(actor_config &cfg) : monitorable_actor(cfg) {
                mh_.assign([&](add_atom, actor_id, const std::string &str) { std::cout << str; });
            }

            void enqueue(mailbox_element_ptr what, execution_unit *) override {
                mh_(what->content());
            }

        private:
            message_handler mh_;
        };

    }    // namespace

    test_coordinator::test_coordinator(spawner &sys) : super(sys) {
        // nop
    }

    bool test_coordinator::detaches_utility_actors() const {
        return false;
    }

    detail::test_actor_clock &test_coordinator::clock() noexcept {
        return clock_;
    }

    void test_coordinator::start() {
        ACTOR_LOG_TRACE("");
        dummy_worker worker {this};
        actor_config cfg {&worker};
        auto &sys = system();
        utility_actors_[printer_id] = make_actor<dummy_printer, actor>(sys.next_actor_id(), sys.node(), &sys, cfg);
    }

    void test_coordinator::stop() {
        ACTOR_LOG_TRACE("");
        while (run() > 0)
            trigger_timeouts();
    }

    void test_coordinator::enqueue(resumable *ptr) {
        ACTOR_LOG_TRACE("");
        jobs.push_back(ptr);
        if (after_next_enqueue_ != nullptr) {
            ACTOR_LOG_DEBUG("inline this enqueue");
            std::function<void()> f;
            f.swap(after_next_enqueue_);
            f();
        }
    }

    bool test_coordinator::try_run_once() {
        ACTOR_LOG_TRACE("");
        if (jobs.empty())
            return false;
        auto job = jobs.front();
        jobs.pop_front();
        dummy_worker worker {this};
        switch (job->resume(&worker, 1)) {
            case resumable::resume_later:
                jobs.push_front(job);
                break;
            case resumable::done:
            case resumable::awaiting_message:
                intrusive_ptr_release(job);
                break;
            case resumable::shutdown_execution_unit:
                break;
        }
        return true;
    }

    bool test_coordinator::try_run_once_lifo() {
        ACTOR_LOG_TRACE("");
        if (jobs.empty())
            return false;
        if (jobs.size() >= 2)
            std::rotate(jobs.rbegin(), jobs.rbegin() + 1, jobs.rend());
        return try_run_once();
    }

    void test_coordinator::run_once() {
        ACTOR_LOG_TRACE("");
        if (jobs.empty())
            ACTOR_RAISE_ERROR("No job to run available.");
        try_run_once();
    }

    void test_coordinator::run_once_lifo() {
        ACTOR_LOG_TRACE("");
        if (jobs.empty())
            ACTOR_RAISE_ERROR("No job to run available.");
        try_run_once_lifo();
    }

    size_t test_coordinator::run(size_t max_count) {
        ACTOR_LOG_TRACE(ACTOR_ARG(max_count));
        size_t res = 0;
        while (res < max_count && try_run_once())
            ++res;
        return res;
    }

    void test_coordinator::inline_next_enqueue() {
        ACTOR_LOG_TRACE("");
        after_next_enqueue([=] { run_once_lifo(); });
    }

    void test_coordinator::inline_all_enqueues() {
        ACTOR_LOG_TRACE("");
        after_next_enqueue([=] { inline_all_enqueues_helper(); });
    }

    void test_coordinator::inline_all_enqueues_helper() {
        ACTOR_LOG_TRACE("");
        after_next_enqueue([=] { inline_all_enqueues_helper(); });
        run_once_lifo();
    }

}    // namespace nil::actor::scheduler