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
// this suite tests whether actors terminate as expect in several use cases
#define BOOST_TEST_MODULE thread_hook_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <nil/actor/config.hpp>
#include <nil/actor/all.hpp>

using namespace nil::actor;

namespace {

    using atomic_count = std::atomic<size_t>;

    size_t assumed_thread_count;
    size_t assumed_init_calls;

    struct dummy_thread_hook : thread_hook {
        void init(spawner &) override {
            // nop
        }

        void thread_started() override {
            // nop
        }

        void thread_terminates() override {
            // nop
        }
    };

    class counting_thread_hook : public thread_hook {
    public:
        counting_thread_hook() : count_init_ {0}, count_thread_started_ {0}, count_thread_terminates_ {0} {
            // nop
        }

        ~counting_thread_hook() override {
            BOOST_CHECK_EQUAL(count_init_, assumed_init_calls);
            BOOST_CHECK_EQUAL(count_thread_started_, assumed_thread_count);
            BOOST_CHECK_EQUAL(count_thread_terminates_, assumed_thread_count);
        }

        void init(spawner &) override {
            ++count_init_;
        }

        void thread_started() override {
            ++count_thread_started_;
        }

        void thread_terminates() override {
            ++count_thread_terminates_;
        }

    private:
        atomic_count count_init_;
        atomic_count count_thread_started_;
        atomic_count count_thread_terminates_;
    };

    template<class Hook>
    struct config : spawner_config {
        config() {
            add_thread_hook<Hook>();
            this->logger_verbosity = atom("quiet");
        }
    };

    template<class Hook>
    struct fixture {
        config<Hook> cfg;
        spawner sys;

        fixture() : sys(cfg) {
            // nop
        }
    };

}    // namespace

BOOST_AUTO_TEST_CASE(counting_no_system_test) {
    assumed_init_calls = 0;
    spawner_config cfg;
    cfg.add_thread_hook<counting_thread_hook>();
}

BOOST_FIXTURE_TEST_SUITE(dummy_hook, fixture<dummy_thread_hook>)

BOOST_AUTO_TEST_CASE(counting_no_args_test) {
    // nop
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(counting_hook, fixture<counting_thread_hook>)

BOOST_AUTO_TEST_CASE(counting_system_without_actor_test) {
    assumed_init_calls = 1;
    assumed_thread_count = cfg.scheduler_max_threads + 2;    // actor.clock thread
    auto &sched = sys.scheduler();
    if (sched.detaches_utility_actors()) {
        assumed_thread_count += sched.num_utility_actors();
    }
}

BOOST_AUTO_TEST_CASE(counting_system_with_actor_test) {
    assumed_init_calls = 1;
    assumed_thread_count = cfg.scheduler_max_threads + 3;    // actor.clock thread plus
    // detached actor
    auto &sched = sys.scheduler();
    if (sched.detaches_utility_actors()) {
        assumed_thread_count += sched.num_utility_actors();
    }
    sys.spawn<detached>([] {});
    sys.spawn([] {});
}

BOOST_AUTO_TEST_SUITE_END()