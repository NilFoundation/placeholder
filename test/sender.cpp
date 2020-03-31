//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE mixin.sender

#include <nil/actor/mixin/sender.hpp>

#include <nil/actor/test/dsl.hpp>

#include <chrono>

using namespace nil::actor;

using std::chrono::seconds;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<template<typename...> class P, typename... T>
            struct print_log_value<P<T...>> {
                void operator()(std::ostream &, P<T...> const &) {
                }
            };

            template<template<typename, std::size_t> class P, typename T, std::size_t S>
            struct print_log_value<P<T, S>> {
                void operator()(std::ostream &, P<T, S> const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

namespace {

    behavior testee_impl(event_based_actor *self) {
        self->set_default_handler(reflect);
        return {
            [] {
                // nop
            },
        };
    }

    struct fixture : test_coordinator_fixture<> {
        group grp;
        actor testee;

        std::string hello = "hello world";

        fixture() {
            grp = sys.groups().anonymous();
            testee = sys.spawn_in_group(grp, testee_impl);
        }

        ~fixture() {
            anon_send_exit(testee, exit_reason::user_shutdown);
        }
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(sender_tests, fixture)

BOOST_AUTO_TEST_CASE(delayed_actor_messages_receive_responses) {
    self->delayed_send(testee, seconds(1), hello);
    sched.trigger_timeout();
    expect((std::string), from(self).to(testee).with(hello));
    expect((std::string), from(testee).to(self).with(hello));
    self->scheduled_send(testee, self->clock().now() + seconds(1), hello);
    sched.trigger_timeout();
    expect((std::string), from(self).to(testee).with(hello));
    expect((std::string), from(testee).to(self).with(hello));
}

BOOST_AUTO_TEST_CASE(delayed_group_message_receive_responses) {
    self->delayed_send(grp, seconds(1), hello);
    sched.trigger_timeout();
    expect((std::string), from(self).to(testee).with(hello));
    expect((std::string), from(testee).to(self).with(hello));
    self->scheduled_send(grp, self->clock().now() + seconds(1), hello);
    sched.trigger_timeout();
    expect((std::string), from(self).to(testee).with(hello));
    expect((std::string), from(testee).to(self).with(hello));
}

BOOST_AUTO_TEST_CASE(anonymous_messages_receive_no_response) {
    self->anon_send(testee, hello);
    expect((std::string), to(testee).with(hello));
    disallow((std::string), from(testee).to(self).with(hello));
    self->delayed_anon_send(testee, seconds(1), hello);
    sched.trigger_timeout();
    expect((std::string), to(testee).with(hello));
    disallow((std::string), from(testee).to(self).with(hello));
    self->scheduled_anon_send(testee, self->clock().now() + seconds(1), hello);
    sched.trigger_timeout();
    expect((std::string), to(testee).with(hello));
    disallow((std::string), from(testee).to(self).with(hello));
    self->delayed_anon_send(grp, seconds(1), hello);
    sched.trigger_timeout();
    expect((std::string), to(testee).with(hello));
    disallow((std::string), from(testee).to(self).with(hello));
    self->scheduled_anon_send(grp, self->clock().now() + seconds(1), hello);
    sched.trigger_timeout();
    expect((std::string), to(testee).with(hello));
    disallow((std::string), from(testee).to(self).with(hello));
}

BOOST_AUTO_TEST_SUITE_END()
