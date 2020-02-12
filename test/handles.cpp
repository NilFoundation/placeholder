//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

// This unit test checks guarantees regarding ordering and equality for actor
// handles, i.e., actor_addr, actor, and typed_actor<...>.

#include <nil/actor/config.hpp>

#define BOOST_TEST_MODULE handles_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <nil/actor/all.hpp>

using namespace nil::actor;

namespace {

    // Simple int32_terface for testee actors.
    using testee_actor = typed_actor<replies_to<int32_t>::with<int32_t>>;

    // Dynamically typed testee.
    behavior dt_testee() {
        return {[](int32_t x) { return x * x; }};
    }

    // Statically typed testee.
    testee_actor::behavior_type st_testee() {
        return {[](int32_t x) { return x * x; }};
    }

    // A simple wrapper for storing a handle in all representations.
    struct handle_set {
        // Weak handle to the actor.
        actor_addr wh;
        // Dynamically typed handle to the actor.
        actor dt;
        // Staically typed handle to the actor.
        testee_actor st;

        handle_set() = default;

        template<class T>
        handle_set(const T &hdl) : wh(hdl.address()), dt(actor_cast<actor>(hdl)), st(actor_cast<testee_actor>(hdl)) {
            // nop
        }
    };

    struct fixture {
        fixture() : sys(cfg), self(sys, true), a1 {sys.spawn(dt_testee)}, a2 {sys.spawn(st_testee)} {
            // nop
        }

        spawner_config cfg;
        spawner sys;
        scoped_actor self;
        handle_set a0;
        handle_set a1 {sys.spawn(dt_testee)};
        handle_set a2 {sys.spawn(st_testee)};
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(handle_tests, fixture)

BOOST_AUTO_TEST_CASE(identity_test) {
    // all handles in a0 are equal
    BOOST_CHECK(a0.wh == a0.wh);
    BOOST_CHECK(a0.wh == a0.dt);
    BOOST_CHECK(a0.wh == a0.st);
    BOOST_CHECK(a0.dt == a0.wh);
    BOOST_CHECK(a0.dt == a0.dt);
    BOOST_CHECK(a0.dt == a0.st);
    BOOST_CHECK(a0.st == a0.wh);
    BOOST_CHECK(a0.st == a0.dt);
    BOOST_CHECK(a0.st == a0.st);
    // all hand a1 ar == equal
    BOOST_CHECK(a1.wh == a1.wh);
    BOOST_CHECK(a1.wh == a1.dt);
    BOOST_CHECK(a1.wh == a1.st);
    BOOST_CHECK(a1.dt == a1.wh);
    BOOST_CHECK(a1.dt == a1.dt);
    BOOST_CHECK(a1.dt == a1.st);
    BOOST_CHECK(a1.st == a1.wh);
    BOOST_CHECK(a1.st == a1.dt);
    BOOST_CHECK(a1.st == a1.st);
    // all hand a2 ar == equal
    BOOST_CHECK(a2.wh == a2.wh);
    BOOST_CHECK(a2.wh == a2.dt);
    BOOST_CHECK(a2.wh == a2.st);
    BOOST_CHECK(a2.dt == a2.wh);
    BOOST_CHECK(a2.dt == a2.dt);
    BOOST_CHECK(a2.dt == a2.st);
    BOOST_CHECK(a2.st == a2.wh);
    BOOST_CHECK(a2.st == a2.dt);
    BOOST_CHECK(a2.st == a2.st);
    // all handles in a0 are *not* equal to any handle in a1 or a2
    BOOST_CHECK(a0.wh != a1.wh);
    BOOST_CHECK(a0.wh != a1.dt);
    BOOST_CHECK(a0.wh != a1.st);
    BOOST_CHECK(a0.dt != a1.wh);
    BOOST_CHECK(a0.dt != a1.dt);
    BOOST_CHECK(a0.dt != a1.st);
    BOOST_CHECK(a0.st != a1.wh);
    BOOST_CHECK(a0.st != a1.dt);
    BOOST_CHECK(a0.st != a1.st);
    BOOST_CHECK(a0.wh != a2.wh);
    BOOST_CHECK(a0.wh != a2.dt);
    BOOST_CHECK(a0.wh != a2.st);
    BOOST_CHECK(a0.dt != a2.wh);
    BOOST_CHECK(a0.dt != a2.dt);
    BOOST_CHECK(a0.dt != a2.st);
    BOOST_CHECK(a0.st != a2.wh);
    BOOST_CHECK(a0.st != a2.dt);
    BOOST_CHECK(a0.st != a2.st);
    // all hand in a1 !=are *not* equal to any handle in a0 or a2
    BOOST_CHECK(a1.wh != a0.wh);
    BOOST_CHECK(a1.wh != a0.dt);
    BOOST_CHECK(a1.wh != a0.st);
    BOOST_CHECK(a1.dt != a0.wh);
    BOOST_CHECK(a1.dt != a0.dt);
    BOOST_CHECK(a1.dt != a0.st);
    BOOST_CHECK(a1.st != a0.wh);
    BOOST_CHECK(a1.st != a0.dt);
    BOOST_CHECK(a1.st != a0.st);
    BOOST_CHECK(a1.wh != a2.wh);
    BOOST_CHECK(a1.wh != a2.dt);
    BOOST_CHECK(a1.wh != a2.st);
    BOOST_CHECK(a1.dt != a2.wh);
    BOOST_CHECK(a1.dt != a2.dt);
    BOOST_CHECK(a1.dt != a2.st);
    BOOST_CHECK(a1.st != a2.wh);
    BOOST_CHECK(a1.st != a2.dt);
    BOOST_CHECK(a1.st != a2.st);
    // all hand in a2 !=are *not* equal to any handle in a0 or a1
    BOOST_CHECK(a2.wh != a0.wh);
    BOOST_CHECK(a2.wh != a0.dt);
    BOOST_CHECK(a2.wh != a0.st);
    BOOST_CHECK(a2.dt != a0.wh);
    BOOST_CHECK(a2.dt != a0.dt);
    BOOST_CHECK(a2.dt != a0.st);
    BOOST_CHECK(a2.st != a0.wh);
    BOOST_CHECK(a2.st != a0.dt);
    BOOST_CHECK(a2.st != a0.st);
    BOOST_CHECK(a2.wh != a1.wh);
    BOOST_CHECK(a2.wh != a1.dt);
    BOOST_CHECK(a2.wh != a1.st);
    BOOST_CHECK(a2.dt != a1.wh);
    BOOST_CHECK(a2.dt != a1.dt);
    BOOST_CHECK(a2.dt != a1.st);
    BOOST_CHECK(a2.st != a1.wh);
    BOOST_CHECK(a2.st != a1.dt);
    BOOST_CHECK(a2.st != a1.st);
}

BOOST_AUTO_TEST_CASE(ordering_test) {
    // handles in a0 are all equal, i.e., are not in less-than relation
    BOOST_CHECK(a0.wh >= a0.wh);
    BOOST_CHECK(a0.wh >= a0.dt);
    BOOST_CHECK(a0.wh >= a0.st);
    BOOST_CHECK(a0.dt >= a0.wh);
    BOOST_CHECK(a0.dt >= a0.dt);
    BOOST_CHECK(a0.dt >= a0.st);
    BOOST_CHECK(a0.st >= a0.wh);
    BOOST_CHECK(a0.st >= a0.dt);
    BOOST_CHECK(a0.st >= a0.st);
    // handles a1 are >=all equal, i.e., are not in less-than relation
    BOOST_CHECK(a1.wh >= a1.wh);
    BOOST_CHECK(a1.wh >= a1.dt);
    BOOST_CHECK(a1.wh >= a1.st);
    BOOST_CHECK(a1.dt >= a1.wh);
    BOOST_CHECK(a1.dt >= a1.dt);
    BOOST_CHECK(a1.dt >= a1.st);
    BOOST_CHECK(a1.st >= a1.wh);
    BOOST_CHECK(a1.st >= a1.dt);
    BOOST_CHECK(a1.st >= a1.st);
    // handles a2 are >=all equal, i.e., are not in less-than relation
    BOOST_CHECK(a2.wh >= a2.wh);
    BOOST_CHECK(a2.wh >= a2.dt);
    BOOST_CHECK(a2.wh >= a2.st);
    BOOST_CHECK(a2.dt >= a2.wh);
    BOOST_CHECK(a2.dt >= a2.dt);
    BOOST_CHECK(a2.dt >= a2.st);
    BOOST_CHECK(a2.st >= a2.wh);
    BOOST_CHECK(a2.st >= a2.dt);
    BOOST_CHECK(a2.st >= a2.st);
    // all handles in a0 are less than handles in a1 or a2
    BOOST_CHECK(a0.wh < a1.wh);
    BOOST_CHECK(a0.wh < a1.dt);
    BOOST_CHECK(a0.wh < a1.st);
    BOOST_CHECK(a0.dt < a1.wh);
    BOOST_CHECK(a0.dt < a1.dt);
    BOOST_CHECK(a0.dt < a1.st);
    BOOST_CHECK(a0.st < a1.wh);
    BOOST_CHECK(a0.st < a1.dt);
    BOOST_CHECK(a0.st < a1.st);
    BOOST_CHECK(a0.wh < a2.wh);
    BOOST_CHECK(a0.wh < a2.dt);
    BOOST_CHECK(a0.wh < a2.st);
    BOOST_CHECK(a0.dt < a2.wh);
    BOOST_CHECK(a0.dt < a2.dt);
    BOOST_CHECK(a0.dt < a2.st);
    BOOST_CHECK(a0.st < a2.wh);
    BOOST_CHECK(a0.st < a2.dt);
    BOOST_CHECK(a0.st < a2.st);
    // all hand in a1 <are less than handles in a2
    BOOST_CHECK(a1.wh < a2.wh);
    BOOST_CHECK(a1.wh < a2.dt);
    BOOST_CHECK(a1.wh < a2.st);
    BOOST_CHECK(a1.dt < a2.wh);
    BOOST_CHECK(a1.dt < a2.dt);
    BOOST_CHECK(a1.dt < a2.st);
    BOOST_CHECK(a1.st < a2.wh);
    BOOST_CHECK(a1.st < a2.dt);
    BOOST_CHECK(a1.st < a2.st);
    // all handles in a1are *not* less than handles in a0
    BOOST_CHECK(a1.wh >= a0.wh);
    BOOST_CHECK(a1.wh >= a0.dt);
    BOOST_CHECK(a1.wh >= a0.st);
    BOOST_CHECK(a1.dt >= a0.wh);
    BOOST_CHECK(a1.dt >= a0.dt);
    BOOST_CHECK(a1.dt >= a0.st);
    BOOST_CHECK(a1.st >= a0.wh);
    BOOST_CHECK(a1.st >= a0.dt);
    BOOST_CHECK(a1.st >= a0.st);
    // all hand in a2 >=are *not* less than handles in a0 or a1
    BOOST_CHECK(a2.wh >= a0.wh);
    BOOST_CHECK(a2.wh >= a0.dt);
    BOOST_CHECK(a2.wh >= a0.st);
    BOOST_CHECK(a2.dt >= a0.wh);
    BOOST_CHECK(a2.dt >= a0.dt);
    BOOST_CHECK(a2.dt >= a0.st);
    BOOST_CHECK(a2.st >= a0.wh);
    BOOST_CHECK(a2.st >= a0.dt);
    BOOST_CHECK(a2.st >= a0.st);
    BOOST_CHECK(a2.wh >= a1.wh);
    BOOST_CHECK(a2.wh >= a1.dt);
    BOOST_CHECK(a2.wh >= a1.st);
    BOOST_CHECK(a2.dt >= a1.wh);
    BOOST_CHECK(a2.dt >= a1.dt);
    BOOST_CHECK(a2.dt >= a1.st);
    BOOST_CHECK(a2.st >= a1.wh);
    BOOST_CHECK(a2.st >= a1.dt);
    BOOST_CHECK(a2.st >= a1.st);
}

BOOST_AUTO_TEST_CASE(string_representation_test) {
    auto s1 = a0.wh;
    auto s2 = a0.dt;
    auto s3 = a0.st;
    BOOST_CHECK(s1 == s2);
    BOOST_CHECK(s2 == s3);
}

BOOST_AUTO_TEST_CASE(mpi_string_representation_test) {
    BOOST_CHECK(sys.message_types(a0.dt).empty());
    std::set<std::string> st_expected {"nil::actor::replies_to<@i32>::with<@i32>"};
    BOOST_CHECK(st_expected == sys.message_types(a0.st));
    BOOST_CHECK(st_expected == sys.message_types<testee_actor>());
}

BOOST_AUTO_TEST_SUITE_END()
