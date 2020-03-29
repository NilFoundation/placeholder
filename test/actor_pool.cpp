//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE actor_pool

#include <nil/actor/actor_pool.hpp>

#include "core-test.hpp"

#include <nil/actor/all.hpp>

using namespace nil::actor;

namespace {

    std::atomic<size_t> s_ctors;
    std::atomic<size_t> s_dtors;

    class worker : public event_based_actor {
    public:
        worker(actor_config &cfg) : event_based_actor(cfg) {
            ++s_ctors;
        }

        ~worker() override {
            ++s_dtors;
        }

        behavior make_behavior() override {
            auto nested = exit_handler_;
            set_exit_handler([=](scheduled_actor *self, exit_msg &em) { nested(self, em); });
            return {
                [](int32_t x, int32_t y) { return x + y; },
            };
        }
    };

    struct fixture {
        // allows us to check s_dtors after dtor of spawner
        spawner_config cfg;
        union {
            spawner system;
        };
        union {
            scoped_execution_unit context;
        };

        std::function<actor()> spawn_worker;

        fixture() {
            new (&system) spawner(cfg);
            new (&context) scoped_execution_unit(&system);
            spawn_worker = [&] { return system.spawn<worker>(); };
        }

        ~fixture() {
            system.await_all_actors_done();
            context.~scoped_execution_unit();
            system.~spawner();
            BOOST_CHECK_EQUAL(s_dtors.load(), s_ctors.load());
        }
    };

#define HANDLE_ERROR [](const error &err) { BOOST_FAIL("AUT responded with an error: " + to_string(err)); }

}    // namespace

BOOST_FIXTURE_TEST_SUITE(actor_pool_tests, fixture)

BOOST_AUTO_TEST_CASE(round_robin_actor_pool) {
    scoped_actor self {system};
    auto pool = actor_pool::make(&context, 5, spawn_worker, actor_pool::round_robin());
    self->send(pool, sys_atom_v, put_atom_v, spawn_worker());
    std::vector<actor> workers;
    for (int32_t i = 0; i < 6; ++i) {
        self->request(pool, infinite, i, i)
            .receive(
                [&](int32_t res) {
                    BOOST_CHECK_EQUAL(res, i + i);
                    auto sender = actor_cast<strong_actor_ptr>(self->current_sender());
                    ACTOR_REQUIRE(sender);
                    workers.push_back(actor_cast<actor>(std::move(sender)));
                },
                HANDLE_ERROR);
    }
    BOOST_CHECK_EQUAL(workers.size(), 6u);
    ACTOR_CHECK(std::unique(workers.begin(), workers.end()) == workers.end());
    self->request(pool, infinite, sys_atom_v, get_atom_v)
        .receive(
            [&](std::vector<actor> &ws) {
                std::sort(workers.begin(), workers.end());
                std::sort(ws.begin(), ws.end());
                ACTOR_REQUIRE_EQUAL(workers.size(), ws.size());
                ACTOR_CHECK(std::equal(workers.begin(), workers.end(), ws.begin()));
            },
            HANDLE_ERROR);
    ACTOR_MESSAGE("await last worker");
    anon_send_exit(workers.back(), exit_reason::user_shutdown);
    self->wait_for(workers.back());
    ACTOR_MESSAGE("last worker shut down");
    workers.pop_back();
    // poll actor pool up to 10 times or until it removes the failed worker
    bool success = false;
    size_t i = 0;
    while (!success && ++i <= 10) {
        self->request(pool, infinite, sys_atom_v, get_atom_v)
            .receive(
                [&](std::vector<actor> &ws) {
                    success = workers.size() == ws.size();
                    if (success) {
                        std::sort(ws.begin(), ws.end());
                        BOOST_CHECK_EQUAL(workers, ws);
                    } else {
                        // wait a bit until polling again
                        std::this_thread::sleep_for(std::chrono::milliseconds(5));
                    }
                },
                HANDLE_ERROR);
    }
    ACTOR_REQUIRE_EQUAL(success, true);
    ACTOR_MESSAGE("about to send exit to workers");
    self->send_exit(pool, exit_reason::user_shutdown);
    self->wait_for(workers);
}

BOOST_AUTO_TEST_CASE(broadcast_actor_pool) {
    scoped_actor self {system};
    auto spawn5 = [&] { return actor_pool::make(&context, 5, fixture::spawn_worker, actor_pool::broadcast()); };
    BOOST_CHECK_EQUAL(system.registry().running(), 1u);
    auto pool = actor_pool::make(&context, 5, spawn5, actor_pool::broadcast());
    BOOST_CHECK_EQUAL(system.registry().running(), 32u);
    self->send(pool, 1, 2);
    std::vector<int> results;
    int i = 0;
    self->receive_for(i, 25)([&](int res) { results.push_back(res); },
                             after(std::chrono::milliseconds(250)) >> [] { ACTOR_ERROR("didn't receive a result"); });
    BOOST_CHECK_EQUAL(results.size(), 25u);
    ACTOR_CHECK(std::all_of(results.begin(), results.end(), [](int res) { return res == 3; }));
    self->send_exit(pool, exit_reason::user_shutdown);
}

BOOST_AUTO_TEST_CASE(random_actor_pool) {
    scoped_actor self {system};
    auto pool = actor_pool::make(&context, 5, spawn_worker, actor_pool::random());
    for (int i = 0; i < 5; ++i) {
        self->request(pool, std::chrono::milliseconds(250), 1, 2)
            .receive([&](int res) { BOOST_CHECK_EQUAL(res, 3); }, HANDLE_ERROR);
    }
    self->send_exit(pool, exit_reason::user_shutdown);
}

BOOST_AUTO_TEST_SUITE_END()
