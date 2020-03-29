//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE request_timeout

#include "core-test.hpp"

#include <chrono>

#include <nil/actor/all.hpp>

using namespace nil::actor;

using std::chrono::milliseconds;
using std::chrono::seconds;

using namespace std::string_literals;

namespace {

    struct pong_state {
        static inline const char *name = "pong";
    };

    behavior pong(stateful_actor<pong_state> *) {
        return {
            [=](ping_atom) { return pong_atom_v; },
        };
    }

    struct ping_state {
        static const char *name;
        bool had_first_timeout = false;    // unused in ping_singleN functions
    };

    const char *ping_state::name = "ping";

    using ping_actor = stateful_actor<ping_state>;

    using fptr = behavior (*)(ping_actor *, bool *, const actor &);
    using test_vec = std::vector<std::pair<fptr, std::string>>;

    // assumes to receive a timeout (sent via delayed_send) before pong replies
    behavior ping_single1(ping_actor *self, bool *had_timeout, const actor &buddy) {
        self->send(buddy, ping_atom_v);
        self->delayed_send(self, std::chrono::seconds(1), timeout_atom_v);
        return {
            [=](pong_atom) { BOOST_FAIL("received pong atom"); },
            [=](timeout_atom) {
                *had_timeout = true;
                self->quit();
            },
        };
    }

    // assumes to receive a timeout (via after()) before pong replies
    behavior ping_single2(ping_actor *self, bool *had_timeout, const actor &buddy) {
        self->send(buddy, ping_atom_v);
        return {
            [=](pong_atom) { BOOST_FAIL("received pong atom"); },
            after(std::chrono::seconds(1)) >>
                [=] {
                    ACTOR_LOG_TRACE(ACTOR_ARG2("had_timeout", *had_timeout));
                    *had_timeout = true;
                    self->quit();
                },
        };
    }

    // assumes to receive a timeout (via request error handler) before pong replies
    behavior ping_single3(ping_actor *self, bool *had_timeout, const actor &buddy) {
        self->request(buddy, milliseconds(100), ping_atom_v)
            .then([=](pong_atom) { BOOST_FAIL("received pong atom"); },
                  [=](const error &err) {
                      BOOST_REQUIRE(err == sec::request_timeout);
                      *had_timeout = true;
                  });
        return {};    // dummy value in order to give all 3 variants the same fun sig
    }

    // assumes to receive an inner timeout (sent via delayed_send) before pong
    // replies, then second timeout fires
    behavior ping_nested1(ping_actor *self, bool *had_timeout, const actor &buddy) {
        self->send(buddy, ping_atom_v);
        self->delayed_send(self, std::chrono::seconds(1), timeout_atom_v);
        return {
            [=](pong_atom) { BOOST_FAIL("received pong atom"); },
            [=](timeout_atom) {
                self->state.had_first_timeout = true;
                self->become(after(milliseconds(100)) >> [=] {
                    BOOST_CHECK(self->state.had_first_timeout);
                    *had_timeout = true;
                    self->quit();
                });
            },
        };
    }

    // assumes to receive an inner timeout (via after()) before pong replies, then a
    // second timeout fires
    behavior ping_nested2(ping_actor *self, bool *had_timeout, const actor &buddy) {
        self->send(buddy, ping_atom_v);
        return {
            [=](pong_atom) { BOOST_FAIL("received pong atom"); },
            after(std::chrono::seconds(1)) >>
                [=] {
                    self->state.had_first_timeout = true;
                    self->become(after(milliseconds(100)) >> [=] {
                        BOOST_CHECK(self->state.had_first_timeout);
                        *had_timeout = true;
                        self->quit();
                    });
                },
        };
    }

    // assumes to receive an inner timeout (via request error handler) before pong
    // replies, then a second timeout fires
    behavior ping_nested3(ping_actor *self, bool *had_timeout, const actor &buddy) {
        self->request(buddy, milliseconds(100), ping_atom_v)
            .then(
                [=](pong_atom) {
                    BOOST_FAIL("received pong atom");
                    self->quit(sec::unexpected_message);
                },
                [=](const error &err) {
                    BOOST_REQUIRE_EQUAL(err, sec::request_timeout);
                    self->state.had_first_timeout = true;
                });
        return {
            after(milliseconds(100)) >>
                [=] {
                    BOOST_CHECK(self->state.had_first_timeout);
                    *had_timeout = true;
                    self->quit();
                },
        };
    }

    // uses .then on both requests
    behavior ping_multiplexed1(ping_actor *self, bool *had_timeout, const actor &pong_actor) {
        self->request(pong_actor, milliseconds(100), ping_atom_v)
            .then([=](pong_atom) { BOOST_FAIL("received pong atom"); },
                  [=](const error &err) {
                      BOOST_REQUIRE_EQUAL(err, sec::request_timeout);
                      if (!self->state.had_first_timeout)
                          self->state.had_first_timeout = true;
                      else
                          *had_timeout = true;
                  });
        self->request(pong_actor, milliseconds(100), ping_atom_v)
            .then([=](pong_atom) { BOOST_FAIL("received pong atom"); },
                  [=](const error &err) {
                      BOOST_REQUIRE_EQUAL(err, sec::request_timeout);
                      if (!self->state.had_first_timeout)
                          self->state.had_first_timeout = true;
                      else
                          *had_timeout = true;
                  });
        return {};
    }

    // uses .await on both requests
    behavior ping_multiplexed2(ping_actor *self, bool *had_timeout, const actor &pong_actor) {
        self->request(pong_actor, milliseconds(100), ping_atom_v)
            .await([=](pong_atom) { BOOST_FAIL("received pong atom"); },
                   [=](const error &err) {
                       BOOST_REQUIRE_EQUAL(err, sec::request_timeout);
                       if (!self->state.had_first_timeout)
                           self->state.had_first_timeout = true;
                       else
                           *had_timeout = true;
                   });
        self->request(pong_actor, milliseconds(100), ping_atom_v)
            .await([=](pong_atom) { BOOST_FAIL("received pong atom"); },
                   [=](const error &err) {
                       BOOST_REQUIRE_EQUAL(err, sec::request_timeout);
                       if (!self->state.had_first_timeout)
                           self->state.had_first_timeout = true;
                       else
                           *had_timeout = true;
                   });
        return {};
    }

    // uses .await and .then
    behavior ping_multiplexed3(ping_actor *self, bool *had_timeout, const actor &pong_actor) {
        self->request(pong_actor, milliseconds(100), ping_atom_v)
            .then([=](pong_atom) { BOOST_FAIL("received pong atom"); },
                  [=](const error &err) {
                      BOOST_REQUIRE_EQUAL(err, sec::request_timeout);
                      if (!self->state.had_first_timeout)
                          self->state.had_first_timeout = true;
                      else
                          *had_timeout = true;
                  });
        self->request(pong_actor, milliseconds(100), ping_atom_v)
            .await([=](pong_atom) { BOOST_FAIL("received pong atom"); },
                   [=](const error &err) {
                       BOOST_REQUIRE_EQUAL(err, sec::request_timeout);
                       if (!self->state.had_first_timeout)
                           self->state.had_first_timeout = true;
                       else
                           *had_timeout = true;
                   });
        return {};
    }

}    // namespace

BOOST_FIXTURE_TEST_SUITE(request_timeout_tests, test_coordinator_fixture<>)

BOOST_AUTO_TEST_CASE(single_timeout) {
    test_vec fs {{ping_single1, "ping_single1"}, {ping_single2, "ping_single2"}, {ping_single3, "ping_single3"}};
    for (auto f : fs) {
        bool had_timeout = false;
        BOOST_TEST_MESSAGE("test implementation " << f.second);
        auto testee = sys.spawn(f.first, &had_timeout, sys.spawn<lazy_init>(pong));
        BOOST_REQUIRE_EQUAL(sched.jobs.size(), 1u);
        BOOST_REQUIRE_EQUAL(sched.next_job<local_actor>().name(), "ping"s);
        sched.run_once();
        BOOST_REQUIRE_EQUAL(sched.jobs.size(), 1u);
        BOOST_REQUIRE_EQUAL(sched.next_job<local_actor>().name(), "pong"s);
        sched.trigger_timeout();
        BOOST_REQUIRE_EQUAL(sched.jobs.size(), 2u);
        // now, the timeout message is already dispatched, while pong did
        // not respond to the message yet, i.e., timeout arrives before response
        BOOST_CHECK_EQUAL(sched.run(), 2u);
        BOOST_CHECK(had_timeout);
    }
}

BOOST_AUTO_TEST_CASE(nested_timeout) {
    test_vec fs {{ping_nested1, "ping_nested1"}, {ping_nested2, "ping_nested2"}, {ping_nested3, "ping_nested3"}};
    for (auto f : fs) {
        bool had_timeout = false;
        BOOST_TEST_MESSAGE("test implementation " << f.second);
        auto testee = sys.spawn(f.first, &had_timeout, sys.spawn<lazy_init>(pong));
        BOOST_REQUIRE_EQUAL(sched.jobs.size(), 1u);
        BOOST_REQUIRE_EQUAL(sched.next_job<local_actor>().name(), "ping"s);
        sched.run_once();
        BOOST_REQUIRE_EQUAL(sched.jobs.size(), 1u);
        BOOST_REQUIRE_EQUAL(sched.next_job<local_actor>().name(), "pong"s);
        sched.trigger_timeout();
        BOOST_REQUIRE_EQUAL(sched.jobs.size(), 2u);
        // now, the timeout message is already dispatched, while pong did
        // not respond to the message yet, i.e., timeout arrives before response
        sched.run();
        // dispatch second timeout
        BOOST_REQUIRE_EQUAL(sched.trigger_timeout(), true);
        BOOST_REQUIRE_EQUAL(sched.next_job<local_actor>().name(), "ping"s);
        BOOST_CHECK(!had_timeout);
        BOOST_CHECK(sched.next_job<ping_actor>().state.had_first_timeout);
        sched.run();
        BOOST_CHECK(had_timeout);
    }
}

BOOST_AUTO_TEST_CASE(multiplexed_timeout) {
    test_vec fs {{ping_multiplexed1, "ping_multiplexed1"},
                 {ping_multiplexed2, "ping_multiplexed2"},
                 {ping_multiplexed3, "ping_multiplexed3"}};
    for (auto f : fs) {
        bool had_timeout = false;
        BOOST_TEST_MESSAGE("test implementation " << f.second);
        auto testee = sys.spawn(f.first, &had_timeout, sys.spawn<lazy_init>(pong));
        BOOST_REQUIRE_EQUAL(sched.jobs.size(), 1u);
        BOOST_REQUIRE_EQUAL(sched.next_job<local_actor>().name(), "ping"s);
        sched.run_once();
        BOOST_REQUIRE_EQUAL(sched.jobs.size(), 1u);
        BOOST_REQUIRE_EQUAL(sched.next_job<local_actor>().name(), "pong"s);
        sched.trigger_timeouts();
        BOOST_REQUIRE_EQUAL(sched.jobs.size(), 2u);
        // now, the timeout message is already dispatched, while pong did
        // not respond to the message yet, i.e., timeout arrives before response
        sched.run();
        BOOST_CHECK(had_timeout);
    }
}

BOOST_AUTO_TEST_SUITE_END()
