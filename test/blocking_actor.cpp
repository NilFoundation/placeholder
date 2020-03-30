//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE blocking_actor

#include <nil/actor/blocking_actor.hpp>

#include "core_test.hpp"

using namespace nil::actor;

namespace {

    struct fixture {
        spawner_config cfg;
        spawner system;
        scoped_actor self;

        fixture() : system(cfg), self(system) {
            // nop
        }
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(blocking_actor_tests, fixture)

BOOST_AUTO_TEST_CASE(catch_all) {
    self->send(self, 42);
    self->receive([](float) { BOOST_FAIL("received unexpected float"); },
                  others >> [](message &msg) -> result<message> {
                      BOOST_CHECK_EQUAL(to_string(msg), "(42)");
                      return sec::unexpected_message;
                  });
    self->receive([](const error &err) { BOOST_CHECK_EQUAL(err, sec::unexpected_message); });
}

BOOST_AUTO_TEST_CASE(behavior_ref) {
    behavior bhvr {[](int i) { BOOST_CHECK_EQUAL(i, 42); }};
    self->send(self, 42);
    self->receive(bhvr);
}

BOOST_AUTO_TEST_CASE(timeout_in_scoped_actor) {
    bool timeout_called = false;
    scoped_actor self {system};
    self->receive(after(std::chrono::milliseconds(20)) >> [&] { timeout_called = true; });
    BOOST_CHECK(timeout_called);
}

// -- scoped_actors using skip -------------------------------------------------

using msg_t = int;
// send_order_t contains messages which are send to an actor in the same order
// as in vector
using send_order_t = std::vector<msg_t>;
// sequence_t contains a number of messages for processing by an actor with
// the information to skip the current message for later processing
using sequence_t = std::vector<std::pair<msg_t, bool>>;
using check_order_t = std::pair<send_order_t, sequence_t>;

behavior check_order_behavior_factory(local_actor *, sequence_t::const_iterator *seq_it_ptr) {
    return {[=](int i) -> result<void> {
        auto &seq_it = *seq_it_ptr;
        BOOST_CHECK_EQUAL(i, seq_it->first);
        if (seq_it->second) {
            BOOST_TEST_MESSAGE("current: " << i << "; awaiting: " << seq_it->first << " SKIPPED");
            ++seq_it;
            return skip();
        } else {
            BOOST_TEST_MESSAGE("current: " << i << "; awaiting: " << seq_it->first << " OK");
            ++seq_it;
            return unit;
        }
    }};
}

void check_order_event_based_actor(const check_order_t &corder) {
    spawner_config cfg;
    spawner system {cfg};
    auto &send_order = corder.first;
    auto &sequence = corder.second;
    auto seq_it = sequence.cbegin();
    {
        auto tmp = system.spawn([&](event_based_actor *self) {
            self->set_default_handler(skip);
            for (auto i : send_order) {
                self->send(self, i);
            }
            self->become(check_order_behavior_factory(self, &seq_it));
        });
    }
    system.await_all_actors_done();
}

void check_order_scoped_actor(const check_order_t &corder) {
    spawner_config cfg;
    spawner system {cfg};
    auto &send_order = corder.first;
    auto &sequence = corder.second;
    auto seq_it = begin(sequence);
    scoped_actor self {system};
    auto check_order_behavior = check_order_behavior_factory(actor_cast<local_actor *>(self), &seq_it);
    for (auto i : send_order) {
        self->send(self, i);
    }
    while (seq_it != end(sequence)) {
        self->receive(check_order_behavior);
    }
}

BOOST_AUTO_TEST_CASE(skip_message) {
    check_order_t a = {{0, 1, 2, 3},    // recv_order = 0,1,2,3
                       {{0, false}, {1, false}, {2, false}, {3, false}}};
    check_order_t b = {{3, 2, 1, 0},    // recv_order = 0,1,2,3
                       {{3, true},
                        {2, true},
                        {1, true},
                        {0, false},
                        {3, true},
                        {2, true},
                        {1, false},
                        {3, true},
                        {2, false},
                        {3, false}}};
    check_order_t c = {{1, 0, 2},    // recv_order = 0,1,2
                       {{1, true}, {0, false}, {1, false}, {2, false}}};
    check_order_t d = {
        {3, 1, 2, 0},    // recv_order = 0,1,2,3
        {{3, true}, {1, true}, {2, true}, {0, false}, {3, true}, {1, false}, {3, true}, {2, false}, {3, false}}};
    check_order_event_based_actor(a);
    check_order_event_based_actor(b);
    check_order_event_based_actor(c);
    check_order_event_based_actor(d);
    check_order_scoped_actor(a);
    check_order_scoped_actor(b);
    check_order_scoped_actor(c);
    check_order_scoped_actor(d);
}

BOOST_AUTO_TEST_SUITE_END()
