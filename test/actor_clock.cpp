//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE actor_clock

#include <nil/actor/actor_clock.hpp>

#include "core-test.hpp"

#include <chrono>
#include <memory>

#include <nil/actor/all.hpp>
#include <nil/actor/detail/test_actor_clock.hpp>
#include <nil/actor/raw_event_based_actor.hpp>

using namespace nil::actor;

using namespace std::chrono_literals;

namespace {

    struct testee_state {
        uint64_t timeout_id = 41;
    };

    behavior testee(stateful_actor<testee_state, raw_event_based_actor> *self, detail::test_actor_clock *t) {
        return {
            [=](ok_atom) {
                ACTOR_LOG_TRACE("" << self->current_mailbox_element()->content());
                auto n = t->now() + 10s;
                self->state.timeout_id += 1;
                t->set_ordinary_timeout(n, self, "", self->state.timeout_id);
            },
            [=](add_atom) {
                ACTOR_LOG_TRACE("");
                auto n = t->now() + 10s;
                self->state.timeout_id += 1;
                t->set_multi_timeout(n, self, "", self->state.timeout_id);
            },
            [=](put_atom) {
                ACTOR_LOG_TRACE("");
                auto n = t->now() + 10s;
                self->state.timeout_id += 1;
                auto mid = make_message_id(self->state.timeout_id).response_id();
                t->set_request_timeout(n, self, mid);
            },
            [](const timeout_msg &) { ACTOR_LOG_TRACE(""); },
            [](const error &) { ACTOR_LOG_TRACE(""); },
            [](const std::string &) { ACTOR_LOG_TRACE(""); },
            [=](group &grp) {
                ACTOR_LOG_TRACE("");
                self->join(grp);
            },
            [=](exit_msg &x) {
                ACTOR_LOG_TRACE("");
                self->quit(x.reason);
            },
        };
    }

    struct fixture : test_coordinator_fixture<> {
        detail::test_actor_clock t;
        actor aut;

        fixture() : aut(sys.spawn<lazy_init>(testee, &t)) {
            // nop
        }
    };

    struct tid {
        uint32_t value;
    };

    inline bool operator==(const timeout_msg &x, const tid &y) {
        return x.timeout_id == y.value;
    }

}    // namespace

BOOST_FIXTURE_TEST_SUITE(timer_tests, fixture)

BOOST_AUTO_TEST_CASE(single_receive_timeout) {
    // Have AUT call t.set_receive_timeout().
    self->send(aut, ok_atom_v);
    expect((ok_atom), from(self).to(aut).with(_));
    BOOST_CHECK_EQUAL(t.schedule().size(), 1u);
    BOOST_CHECK_EQUAL(t.actor_lookup().size(), 1u);
    // Advance time to send timeout message.
    t.advance_time(10s);
    BOOST_CHECK_EQUAL(t.schedule().size(), 0u);
    BOOST_CHECK_EQUAL(t.actor_lookup().size(), 0u);
    // Have AUT receive the timeout.
    expect((timeout_msg), from(aut).to(aut).with(tid {42}));
}

BOOST_AUTO_TEST_CASE(override_receive_timeout) {
    // Have AUT call t.set_receive_timeout().
    self->send(aut, ok_atom_v);
    expect((ok_atom), from(self).to(aut).with(_));
    BOOST_CHECK_EQUAL(t.schedule().size(), 1u);
    BOOST_CHECK_EQUAL(t.actor_lookup().size(), 1u);
    // Have AUT call t.set_timeout() again.
    self->send(aut, ok_atom_v);
    expect((ok_atom), from(self).to(aut).with(_));
    BOOST_CHECK_EQUAL(t.schedule().size(), 1u);
    BOOST_CHECK_EQUAL(t.actor_lookup().size(), 1u);
    // Advance time to send timeout message.
    t.advance_time(10s);
    BOOST_CHECK_EQUAL(t.schedule().size(), 0u);
    BOOST_CHECK_EQUAL(t.actor_lookup().size(), 0u);
    // Have AUT receive the timeout.
    expect((timeout_msg), from(aut).to(aut).with(tid {43}));
}

BOOST_AUTO_TEST_CASE(multi_timeout) {
    // Have AUT call t.set_multi_timeout().
    self->send(aut, add_atom_v);
    expect((add_atom), from(self).to(aut).with(_));
    BOOST_CHECK_EQUAL(t.schedule().size(), 1u);
    BOOST_CHECK_EQUAL(t.actor_lookup().size(), 1u);
    // Advance time just a little bit.
    t.advance_time(5s);
    // Have AUT call t.set_multi_timeout() again.
    self->send(aut, add_atom_v);
    expect((add_atom), from(self).to(aut).with(_));
    BOOST_CHECK_EQUAL(t.schedule().size(), 2u);
    BOOST_CHECK_EQUAL(t.actor_lookup().size(), 2u);
    // Advance time to send timeout message.
    t.advance_time(5s);
    BOOST_CHECK_EQUAL(t.schedule().size(), 1u);
    BOOST_CHECK_EQUAL(t.actor_lookup().size(), 1u);
    // Have AUT receive the timeout.
    expect((timeout_msg), from(aut).to(aut).with(tid {42}));
    // Advance time to send second timeout message.
    t.advance_time(5s);
    BOOST_CHECK_EQUAL(t.schedule().size(), 0u);
    BOOST_CHECK_EQUAL(t.actor_lookup().size(), 0u);
    // Have AUT receive the timeout.
    expect((timeout_msg), from(aut).to(aut).with(tid {43}));
}

BOOST_AUTO_TEST_CASE(mixed_receive_and_multi_timeouts) {
    // Have AUT call t.set_receive_timeout().
    self->send(aut, add_atom_v);
    expect((add_atom), from(self).to(aut).with(_));
    BOOST_CHECK_EQUAL(t.schedule().size(), 1u);
    BOOST_CHECK_EQUAL(t.actor_lookup().size(), 1u);
    // Advance time just a little bit.
    t.advance_time(5s);
    // Have AUT call t.set_multi_timeout() again.
    self->send(aut, ok_atom_v);
    expect((ok_atom), from(self).to(aut).with(_));
    BOOST_CHECK_EQUAL(t.schedule().size(), 2u);
    BOOST_CHECK_EQUAL(t.actor_lookup().size(), 2u);
    // Advance time to send timeout message.
    t.advance_time(5s);
    BOOST_CHECK_EQUAL(t.schedule().size(), 1u);
    BOOST_CHECK_EQUAL(t.actor_lookup().size(), 1u);
    // Have AUT receive the timeout.
    expect((timeout_msg), from(aut).to(aut).with(tid {42}));
    // Advance time to send second timeout message.
    t.advance_time(5s);
    BOOST_CHECK_EQUAL(t.schedule().size(), 0u);
    BOOST_CHECK_EQUAL(t.actor_lookup().size(), 0u);
    // Have AUT receive the timeout.
    expect((timeout_msg), from(aut).to(aut).with(tid {43}));
}

BOOST_AUTO_TEST_CASE(single_request_timeout) {
    // Have AUT call t.set_request_timeout().
    self->send(aut, put_atom_v);
    expect((put_atom), from(self).to(aut).with(_));
    BOOST_CHECK_EQUAL(t.schedule().size(), 1u);
    BOOST_CHECK_EQUAL(t.actor_lookup().size(), 1u);
    // Advance time to send timeout message.
    t.advance_time(10s);
    BOOST_CHECK_EQUAL(t.schedule().size(), 0u);
    BOOST_CHECK_EQUAL(t.actor_lookup().size(), 0u);
    // Have AUT receive the timeout.
    expect((error), from(aut).to(aut).with(sec::request_timeout));
}

BOOST_AUTO_TEST_CASE(mixed_receive_and_request_timeouts) {
    // Have AUT call t.set_receive_timeout().
    self->send(aut, ok_atom_v);
    expect((ok_atom), from(self).to(aut).with(_));
    BOOST_CHECK_EQUAL(t.schedule().size(), 1u);
    BOOST_CHECK_EQUAL(t.actor_lookup().size(), 1u);
    // Cause the request timeout to arrive later.
    t.advance_time(5s);
    // Have AUT call t.set_request_timeout().
    self->send(aut, put_atom_v);
    expect((put_atom), from(self).to(aut).with(_));
    BOOST_CHECK_EQUAL(t.schedule().size(), 2u);
    BOOST_CHECK_EQUAL(t.actor_lookup().size(), 2u);
    // Advance time to send receive timeout message.
    t.advance_time(5s);
    BOOST_CHECK_EQUAL(t.schedule().size(), 1u);
    BOOST_CHECK_EQUAL(t.actor_lookup().size(), 1u);
    // Have AUT receive the timeout.
    expect((timeout_msg), from(aut).to(aut).with(tid {42}));
    // Advance time to send request timeout message.
    t.advance_time(10s);
    BOOST_CHECK_EQUAL(t.schedule().size(), 0u);
    BOOST_CHECK_EQUAL(t.actor_lookup().size(), 0u);
    // Have AUT receive the timeout.
    expect((error), from(aut).to(aut).with(sec::request_timeout));
}

BOOST_AUTO_TEST_CASE(delay_actor_message) {
    // Schedule a message for now + 10s.
    auto n = t.now() + 10s;
    auto autptr = actor_cast<strong_actor_ptr>(aut);
    t.schedule_message(n, autptr, make_mailbox_element(autptr, make_message_id(), no_stages, "foo"));
    BOOST_CHECK_EQUAL(t.schedule().size(), 1u);
    BOOST_CHECK_EQUAL(t.actor_lookup().size(), 0u);
    // Advance time to send the message.
    t.advance_time(10s);
    BOOST_CHECK_EQUAL(t.schedule().size(), 0u);
    BOOST_CHECK_EQUAL(t.actor_lookup().size(), 0u);
    // Have AUT receive the message.
    expect((std::string), from(aut).to(aut).with("foo"));
}

BOOST_AUTO_TEST_CASE(delay_group_message) {
    // Have AUT join the group.
    auto grp = sys.groups().anonymous();
    self->send(aut, grp);
    expect((group), from(self).to(aut).with(_));
    // Schedule a message for now + 10s.
    auto n = t.now() + 10s;
    auto autptr = actor_cast<strong_actor_ptr>(aut);
    t.schedule_message(n, std::move(grp), autptr, make_message("foo"));
    BOOST_CHECK_EQUAL(t.schedule().size(), 1u);
    BOOST_CHECK_EQUAL(t.actor_lookup().size(), 0u);
    // Advance time to send the message.
    t.advance_time(10s);
    BOOST_CHECK_EQUAL(t.schedule().size(), 0u);
    BOOST_CHECK_EQUAL(t.actor_lookup().size(), 0u);
    // Have AUT receive the message.
    expect((std::string), from(aut).to(aut).with("foo"));
    // Kill AUT (necessary because the group keeps a reference around).
    self->send_exit(aut, exit_reason::kill);
    expect((exit_msg), from(self).to(aut).with(_));
}

BOOST_AUTO_TEST_SUITE_END()
