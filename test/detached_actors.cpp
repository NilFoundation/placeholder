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

#define BOOST_TEST_MODULE detached_actors_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <nil/actor/all.hpp>

using namespace nil::actor;

using std::endl;

namespace {

    struct fixture {
        spawner_config cfg;
        spawner sys;
        scoped_actor self;

        fixture() : sys(cfg), self(sys, true) {
            // nop
        }
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(detached_actors, fixture)

BOOST_AUTO_TEST_CASE(shutdown_test) {
    BOOST_TEST_MESSAGE("does sys shut down after spawning a detached actor?");
    sys.spawn<detached>([] {});
}

BOOST_AUTO_TEST_CASE(shutdown_with_delayed_send_test) {
    BOOST_TEST_MESSAGE(
        "does sys shut down after spawning a detached actor that used "
        "delayed_send?");
    auto f = [](event_based_actor *self) -> behavior {
        self->delayed_send(self, std::chrono::nanoseconds(1), ok_atom::value);
        return {[=](ok_atom) { self->quit(); }};
    };
    sys.spawn<detached>(f);
}

BOOST_AUTO_TEST_CASE(shutdown_with_unhandled_delayed_send_test) {
    BOOST_TEST_MESSAGE(
        "does sys shut down after spawning a detached actor that used "
        "delayed_send but didn't bother waiting for it?");
    auto f = [](event_based_actor *self) { self->delayed_send(self, std::chrono::nanoseconds(1), ok_atom::value); };
    sys.spawn<detached>(f);
}

BOOST_AUTO_TEST_CASE(shutdown_with_after_test) {
    BOOST_TEST_MESSAGE(
        "does sys shut down after spawning a detached actor that used "
        "after()?");
    auto f = [](event_based_actor *self) -> behavior {
        return {after(std::chrono::nanoseconds(1)) >> [=] { self->quit(); }};
    };
    sys.spawn<detached>(f);
}

BOOST_AUTO_TEST_CASE(shutdown_delayed_send_loop_test) {
    BOOST_TEST_MESSAGE(
        "does sys shut down after spawning a detached actor that used "
        "a delayed send loop and was interrupted via exit message?");
    auto f = [](event_based_actor *self) -> behavior {
        self->delayed_send(self, std::chrono::milliseconds(1), ok_atom::value);
        return {[=](ok_atom) { self->delayed_send(self, std::chrono::milliseconds(1), ok_atom::value); }};
    };
    auto a = sys.spawn<detached>(f);
    auto g = detail::make_scope_guard([&] { self->send_exit(a, exit_reason::user_shutdown); });
}

BOOST_AUTO_TEST_SUITE_END()
