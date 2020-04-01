//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE detached_actors

#include <nil/actor/all.hpp>

#include <nil/actor/test/dsl.hpp>

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

BOOST_AUTO_TEST_CASE(shutdown) {
    BOOST_TEST_MESSAGE("does sys shut down after spawning a detached actor?");
    sys.spawn<detached>([] {});
}

BOOST_AUTO_TEST_CASE(shutdown_with_delayed_send) {
    BOOST_TEST_MESSAGE(
        "does sys shut down after spawning a detached actor that used "
        "delayed_send?");
    auto f = [](event_based_actor *self) -> behavior {
        self->delayed_send(self, std::chrono::nanoseconds(1), ok_atom_v);
        return {
            [=](ok_atom) { self->quit(); },
        };
    };
    sys.spawn<detached>(f);
}

BOOST_AUTO_TEST_CASE(shutdown_with_unhandled_delayed_send) {
    BOOST_TEST_MESSAGE(
        "does sys shut down after spawning a detached actor that used "
        "delayed_send but didn't bother waiting for it?");
    auto f = [](event_based_actor *self) { self->delayed_send(self, std::chrono::nanoseconds(1), ok_atom_v); };
    sys.spawn<detached>(f);
}

BOOST_AUTO_TEST_CASE(shutdown_with_after) {
    BOOST_TEST_MESSAGE(
        "does sys shut down after spawning a detached actor that used "
        "after()?");
    auto f = [](event_based_actor *self) -> behavior {
        return {
            after(std::chrono::nanoseconds(1)) >> [=] { self->quit(); },
        };
    };
    sys.spawn<detached>(f);
}

BOOST_AUTO_TEST_CASE(shutdown_delayed_send_loop) {
    BOOST_TEST_MESSAGE(
        "does sys shut down after spawning a detached actor that used "
        "a delayed send loop and was interrupted via exit message?");
    auto f = [](event_based_actor *self) -> behavior {
        self->delayed_send(self, std::chrono::milliseconds(1), ok_atom_v);
        return {
            [=](ok_atom) { self->delayed_send(self, std::chrono::milliseconds(1), ok_atom_v); },
        };
    };
    auto a = sys.spawn<detached>(f);
    auto g = detail::make_scope_guard([&] { self->send_exit(a, exit_reason::user_shutdown); });
}

BOOST_AUTO_TEST_SUITE_END()
