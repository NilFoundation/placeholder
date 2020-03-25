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

#define BOOST_TEST_MODULE sender_test

#include <nil/actor/mixin/sender.hpp>

#include <nil/actor/test/dsl.hpp>

#include <chrono>

using namespace nil::actor;

using std::chrono::seconds;

namespace {

    behavior testee_impl(event_based_actor *self) {
        self->set_default_handler(drop);
        return {[] {
            // nop
        }};
    }

    struct fixture : test_coordinator_fixture<> {
        group grp;
        actor testee;

        fixture() {
            grp = sys.groups().anonymous();
            testee = sys.spawn_in_group(grp, testee_impl);
        }

        ~fixture() {
            anon_send_exit(testee, exit_reason::user_shutdown);
        }
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(request_timeout_tests, fixture)

BOOST_AUTO_TEST_CASE(delayed_actor_message_test) {
    self->delayed_send(testee, seconds(1), "hello world");
    sched.

        trigger_timeout();

    expect((std::string), from(self).to(testee).with("hello world"));
}

BOOST_AUTO_TEST_CASE(delayed_group_message_test) {
    self->delayed_send(grp, seconds(1), "hello world");
    sched.trigger_timeout();

    expect((std::string), from(self).to(testee).with("hello world"));
}

BOOST_AUTO_TEST_CASE(scheduled_actor_message) {
    self->scheduled_send(testee, self->clock().now() + seconds(1), "hello world");
    sched.trigger_timeout();
    expect((std::string), from(self).to(testee).with("hello world"));
}

BOOST_AUTO_TEST_CASE(scheduled_group_message) {
    self->scheduled_send(grp, self->clock().now() + seconds(1), "hello world");
    sched.trigger_timeout();
    expect((std::string), from(self).to(testee).with("hello world"));
}

BOOST_AUTO_TEST_SUITE_END()