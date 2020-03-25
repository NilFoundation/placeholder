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

#include <nil/actor/config.hpp>

#define BOOST_TEST_MODULE actor_lifetime_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <mutex>
#include <atomic>
#include <condition_variable>

#include <nil/actor/all.hpp>

#include <nil/actor/test/dsl.hpp>

using check_atom = nil::actor::atom_constant<nil::actor::atom("check")>;

using namespace nil::actor;

namespace {

    std::mutex s_mtx;
    std::condition_variable s_cv;
    std::atomic<bool> s_tester_init_done;
    std::atomic<bool> s_testee_cleanup_done;

    std::atomic<long> s_testees;
    std::atomic<long> s_pending_on_exits;

    class testee : public event_based_actor {
    public:
        testee(actor_config &cfg) : event_based_actor(cfg) {
            ++s_testees;
            ++s_pending_on_exits;
        }

        ~testee() override {
            --s_testees;
        }

        const char *name() const override {
            return "testee";
        }

        void on_exit() override {
            --s_pending_on_exits;
        }

        behavior make_behavior() override {
            return {[=](int x) { return x; }};
        }
    };

    template<class ExitMsgType>
    behavior tester(event_based_actor *self, const actor &aut) {
        if (std::is_same<ExitMsgType, exit_msg>::value) {
            self->set_exit_handler([self](exit_msg &msg) {
                // must be still alive at this point
                BOOST_CHECK_EQUAL(s_testees.load(), 1);
                BOOST_CHECK(msg.reason == exit_reason::user_shutdown);
                self->send(self, check_atom::value);
            });
            self->link_to(aut);
        } else {
            self->set_down_handler([self](down_msg &msg) {
                // must be still alive at this point
                BOOST_CHECK_EQUAL(s_testees.load(), 1);
                BOOST_CHECK(msg.reason == exit_reason::user_shutdown);
                // testee might be still running its cleanup code in
                // another worker thread; by waiting some milliseconds, we make sure
                // testee had enough time to return control to the scheduler
                // which in turn destroys it by dropping the last remaining reference
                self->send(self, check_atom::value);
            });
            self->monitor(aut);
        }
        anon_send_exit(aut, exit_reason::user_shutdown);
        {
            std::unique_lock<std::mutex> guard {s_mtx};
            s_tester_init_done = true;
            s_cv.notify_one();
        }
        return {[self](check_atom) {
            {    // make sure aut's dtor and on_exit() have been called
                std::unique_lock<std::mutex> guard {s_mtx};
                while (!s_testee_cleanup_done.load()) {
                    s_cv.wait(guard);
                }
            }
            BOOST_CHECK_EQUAL(s_testees.load(), 0);
            BOOST_CHECK_EQUAL(s_pending_on_exits.load(), 0);
            self->quit();
        }};
    }

    struct config : spawner_config {
        config() {
            scheduler_policy = atom("testing");
        }
    };

    struct fixture {
        using sched_t = scheduler::test_coordinator;

        config cfg;
        spawner system;
        sched_t &sched;

        fixture() : system(cfg), sched(dynamic_cast<sched_t &>(system.scheduler())) {
            // nop
        }

        template<spawn_options Os, class... Ts>
        actor spawn(Ts &&... xs) {
            return system.spawn<Os>(xs...);
        }

        template<class T, spawn_options Os, class... Ts>
        actor spawn(Ts &&... xs) {
            return system.spawn<T, Os>(xs...);
        }

        template<class ExitMsgType, spawn_options TesterOptions, spawn_options TesteeOptions>
        void tst() {
            // We re-use these static variables with each run.
            s_tester_init_done = false;
            s_testee_cleanup_done = false;
            // Spawn test subject and tester.
            auto tst_subject = spawn<testee, TesteeOptions>();
            sched.run();
            auto tst_driver = spawn<TesterOptions>(tester<ExitMsgType>, tst_subject);
            tst_subject = nullptr;
            if (has_detach_flag(TesterOptions)) {
                // When dealing with a detached tester we need to insert two
                // synchronization points: 1) exit_msg sent and 2) cleanup code of tester
                // done.
                {    // Wait for the exit_msg from the driver.
                    std::unique_lock<std::mutex> guard {s_mtx};
                    while (!s_tester_init_done) {
                        s_cv.wait(guard);
                    }
                }
                // Run the exit_msg.
                sched.run_once();
                // expect((exit_msg), from(tst_driver).to(tst_subject));
                {    // Resume driver.
                    std::unique_lock<std::mutex> guard {s_mtx};
                    s_testee_cleanup_done = true;
                    s_cv.notify_one();
                }
            } else {
                // When both actors are running in the scheduler we don't need any extra
                // synchronization.
                s_tester_init_done = true;
                s_testee_cleanup_done = true;
                sched.run();
            }
        }
    };

}    // namespace

BOOST_AUTO_TEST_CASE(destructor_call_test) {
    {    // lifetime scope of actor systme
        spawner_config cfg;
        spawner system {cfg};
        system.spawn<testee>();
    }
    BOOST_CHECK_EQUAL(s_testees.load(), 0);
    BOOST_CHECK_EQUAL(s_pending_on_exits.load(), 0);
}

BOOST_FIXTURE_TEST_SUITE(actor_lifetime_tests, fixture)

BOOST_AUTO_TEST_CASE(no_spawn_options_and_exit_msg_test) {
    tst<exit_msg, no_spawn_options, no_spawn_options>();
}

BOOST_AUTO_TEST_CASE(no_spawn_options_and_down_msg_test) {
    tst<down_msg, no_spawn_options, no_spawn_options>();
}

BOOST_AUTO_TEST_CASE(mixed_spawn_options_and_exit_msg_test) {
    tst<exit_msg, detached, no_spawn_options>();
}

BOOST_AUTO_TEST_CASE(mixed_spawn_options_and_down_msg_test) {
    tst<down_msg, detached, no_spawn_options>();
}

BOOST_AUTO_TEST_SUITE_END()
