//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE local_group

#include <nil/actor/all.hpp>

#include <nil/actor/test/dsl.hpp>

#include <array>
#include <chrono>
#include <algorithm>

using namespace nil::actor;

namespace {

    using testee_if = typed_actor<replies_to<get_atom>::with<int>, reacts_to<put_atom, int>>;

    struct testee_state {
        int x = 0;
    };

    behavior testee_impl(stateful_actor<testee_state> *self) {
        auto subscriptions = self->joined_groups();
        return {[=](put_atom, int x) { self->state.x = x; }, [=](get_atom) { return self->state.x; }};
    }

    struct fixture {
        spawner_config config;
        spawner system {config};
        scoped_actor self {system};
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(group_tests, fixture)

BOOST_AUTO_TEST_CASE(class_based_joined_at_spawn) {
    auto grp = system.groups().get_local("test");
    // initialize all testee actors, spawning them in the group
    std::array<actor, 10> xs;
    for (auto &x : xs)
        x = system.spawn_in_group(grp, testee_impl);
    // get a function view for all testees
    std::array<function_view<testee_if>, 10> fs;
    std::transform(xs.begin(), xs.end(), fs.begin(),
                   [](const actor &x) { return make_function_view(actor_cast<testee_if>(x)); });
    // make sure all actors start at 0
    for (auto &f : fs)
        BOOST_CHECK_EQUAL(f(get_atom_v), 0);
    // send a put to all actors via the group and make sure they change state
    self->send(grp, put_atom_v, 42);
    for (auto &f : fs)
        BOOST_CHECK_EQUAL(f(get_atom_v), 42);
    // shutdown all actors
    for (auto &x : xs)
        self->send_exit(x, exit_reason::user_shutdown);
}

BOOST_AUTO_TEST_SUITE_END()
