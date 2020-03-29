//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

// This unit test checks guarantees regarding ordering and equality for actor
// handles, i.e., actor_addr, actor, and typed_actor<...>.

#define BOOST_TEST_MODULE handles

#include <nil/actor/actor.hpp>
#include <nil/actor/actor_addr.hpp>
#include <nil/actor/typed_actor.hpp>

#include "core-test.hpp"

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
        // Statically typed handle to the actor.
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

BOOST_AUTO_TEST_CASE(identity) {
    // all handles in a0 are equal
    BOOST_CHECK_EQUAL(a0.wh, a0.wh);
    BOOST_CHECK_EQUAL(a0.wh, a0.dt);
    BOOST_CHECK_EQUAL(a0.wh, a0.st);
    BOOST_CHECK_EQUAL(a0.dt, a0.wh);
    BOOST_CHECK_EQUAL(a0.dt, a0.dt);
    BOOST_CHECK_EQUAL(a0.dt, a0.st);
    BOOST_CHECK_EQUAL(a0.st, a0.wh);
    BOOST_CHECK_EQUAL(a0.st, a0.dt);
    BOOST_CHECK_EQUAL(a0.st, a0.st);
    // all handles in a1 are equal
    BOOST_CHECK_EQUAL(a1.wh, a1.wh);
    BOOST_CHECK_EQUAL(a1.wh, a1.dt);
    BOOST_CHECK_EQUAL(a1.wh, a1.st);
    BOOST_CHECK_EQUAL(a1.dt, a1.wh);
    BOOST_CHECK_EQUAL(a1.dt, a1.dt);
    BOOST_CHECK_EQUAL(a1.dt, a1.st);
    BOOST_CHECK_EQUAL(a1.st, a1.wh);
    BOOST_CHECK_EQUAL(a1.st, a1.dt);
    BOOST_CHECK_EQUAL(a1.st, a1.st);
    // all handles in a2 are equal
    BOOST_CHECK_EQUAL(a2.wh, a2.wh);
    BOOST_CHECK_EQUAL(a2.wh, a2.dt);
    BOOST_CHECK_EQUAL(a2.wh, a2.st);
    BOOST_CHECK_EQUAL(a2.dt, a2.wh);
    BOOST_CHECK_EQUAL(a2.dt, a2.dt);
    BOOST_CHECK_EQUAL(a2.dt, a2.st);
    BOOST_CHECK_EQUAL(a2.st, a2.wh);
    BOOST_CHECK_EQUAL(a2.st, a2.dt);
    BOOST_CHECK_EQUAL(a2.st, a2.st);
    // all handles in a0 are *not* equal to any handle in a1 or a2
    BOOST_CHECK_NE(a0.wh, a1.wh);
    BOOST_CHECK_NE(a0.wh, a1.dt);
    BOOST_CHECK_NE(a0.wh, a1.st);
    BOOST_CHECK_NE(a0.dt, a1.wh);
    BOOST_CHECK_NE(a0.dt, a1.dt);
    BOOST_CHECK_NE(a0.dt, a1.st);
    BOOST_CHECK_NE(a0.st, a1.wh);
    BOOST_CHECK_NE(a0.st, a1.dt);
    BOOST_CHECK_NE(a0.st, a1.st);
    BOOST_CHECK_NE(a0.wh, a2.wh);
    BOOST_CHECK_NE(a0.wh, a2.dt);
    BOOST_CHECK_NE(a0.wh, a2.st);
    BOOST_CHECK_NE(a0.dt, a2.wh);
    BOOST_CHECK_NE(a0.dt, a2.dt);
    BOOST_CHECK_NE(a0.dt, a2.st);
    BOOST_CHECK_NE(a0.st, a2.wh);
    BOOST_CHECK_NE(a0.st, a2.dt);
    BOOST_CHECK_NE(a0.st, a2.st);
    // all handles in a1 are *not* equal to any handle in a0 or a2
    BOOST_CHECK_NE(a1.wh, a0.wh);
    BOOST_CHECK_NE(a1.wh, a0.dt);
    BOOST_CHECK_NE(a1.wh, a0.st);
    BOOST_CHECK_NE(a1.dt, a0.wh);
    BOOST_CHECK_NE(a1.dt, a0.dt);
    BOOST_CHECK_NE(a1.dt, a0.st);
    BOOST_CHECK_NE(a1.st, a0.wh);
    BOOST_CHECK_NE(a1.st, a0.dt);
    BOOST_CHECK_NE(a1.st, a0.st);
    BOOST_CHECK_NE(a1.wh, a2.wh);
    BOOST_CHECK_NE(a1.wh, a2.dt);
    BOOST_CHECK_NE(a1.wh, a2.st);
    BOOST_CHECK_NE(a1.dt, a2.wh);
    BOOST_CHECK_NE(a1.dt, a2.dt);
    BOOST_CHECK_NE(a1.dt, a2.st);
    BOOST_CHECK_NE(a1.st, a2.wh);
    BOOST_CHECK_NE(a1.st, a2.dt);
    BOOST_CHECK_NE(a1.st, a2.st);
    // all handles in a2 are *not* equal to any handle in a0 or a1
    BOOST_CHECK_NE(a2.wh, a0.wh);
    BOOST_CHECK_NE(a2.wh, a0.dt);
    BOOST_CHECK_NE(a2.wh, a0.st);
    BOOST_CHECK_NE(a2.dt, a0.wh);
    BOOST_CHECK_NE(a2.dt, a0.dt);
    BOOST_CHECK_NE(a2.dt, a0.st);
    BOOST_CHECK_NE(a2.st, a0.wh);
    BOOST_CHECK_NE(a2.st, a0.dt);
    BOOST_CHECK_NE(a2.st, a0.st);
    BOOST_CHECK_NE(a2.wh, a1.wh);
    BOOST_CHECK_NE(a2.wh, a1.dt);
    BOOST_CHECK_NE(a2.wh, a1.st);
    BOOST_CHECK_NE(a2.dt, a1.wh);
    BOOST_CHECK_NE(a2.dt, a1.dt);
    BOOST_CHECK_NE(a2.dt, a1.st);
    BOOST_CHECK_NE(a2.st, a1.wh);
    BOOST_CHECK_NE(a2.st, a1.dt);
    BOOST_CHECK_NE(a2.st, a1.st);
}

BOOST_AUTO_TEST_CASE(ordering) {
    // handles in a0 are all equal, i.e., are not in less-than relation
    BOOST_CHECK_NOT_LESS(a0.wh, a0.wh);
    BOOST_CHECK_NOT_LESS(a0.wh, a0.dt);
    BOOST_CHECK_NOT_LESS(a0.wh, a0.st);
    BOOST_CHECK_NOT_LESS(a0.dt, a0.wh);
    BOOST_CHECK_NOT_LESS(a0.dt, a0.dt);
    BOOST_CHECK_NOT_LESS(a0.dt, a0.st);
    BOOST_CHECK_NOT_LESS(a0.st, a0.wh);
    BOOST_CHECK_NOT_LESS(a0.st, a0.dt);
    BOOST_CHECK_NOT_LESS(a0.st, a0.st);
    // handles in a1 are all equal, i.e., are not in less-than relation
    BOOST_CHECK_NOT_LESS(a1.wh, a1.wh);
    BOOST_CHECK_NOT_LESS(a1.wh, a1.dt);
    BOOST_CHECK_NOT_LESS(a1.wh, a1.st);
    BOOST_CHECK_NOT_LESS(a1.dt, a1.wh);
    BOOST_CHECK_NOT_LESS(a1.dt, a1.dt);
    BOOST_CHECK_NOT_LESS(a1.dt, a1.st);
    BOOST_CHECK_NOT_LESS(a1.st, a1.wh);
    BOOST_CHECK_NOT_LESS(a1.st, a1.dt);
    BOOST_CHECK_NOT_LESS(a1.st, a1.st);
    // handles in a2 are all equal, i.e., are not in less-than relation
    BOOST_CHECK_NOT_LESS(a2.wh, a2.wh);
    BOOST_CHECK_NOT_LESS(a2.wh, a2.dt);
    BOOST_CHECK_NOT_LESS(a2.wh, a2.st);
    BOOST_CHECK_NOT_LESS(a2.dt, a2.wh);
    BOOST_CHECK_NOT_LESS(a2.dt, a2.dt);
    BOOST_CHECK_NOT_LESS(a2.dt, a2.st);
    BOOST_CHECK_NOT_LESS(a2.st, a2.wh);
    BOOST_CHECK_NOT_LESS(a2.st, a2.dt);
    BOOST_CHECK_NOT_LESS(a2.st, a2.st);
    // all handles in a0 are less than handles in a1 or a2
    BOOST_CHECK_LT(a0.wh, a1.wh);
    BOOST_CHECK_LT(a0.wh, a1.dt);
    BOOST_CHECK_LT(a0.wh, a1.st);
    BOOST_CHECK_LT(a0.dt, a1.wh);
    BOOST_CHECK_LT(a0.dt, a1.dt);
    BOOST_CHECK_LT(a0.dt, a1.st);
    BOOST_CHECK_LT(a0.st, a1.wh);
    BOOST_CHECK_LT(a0.st, a1.dt);
    BOOST_CHECK_LT(a0.st, a1.st);
    BOOST_CHECK_LT(a0.wh, a2.wh);
    BOOST_CHECK_LT(a0.wh, a2.dt);
    BOOST_CHECK_LT(a0.wh, a2.st);
    BOOST_CHECK_LT(a0.dt, a2.wh);
    BOOST_CHECK_LT(a0.dt, a2.dt);
    BOOST_CHECK_LT(a0.dt, a2.st);
    BOOST_CHECK_LT(a0.st, a2.wh);
    BOOST_CHECK_LT(a0.st, a2.dt);
    BOOST_CHECK_LT(a0.st, a2.st);
    // all handles in a1 are less than handles in a2
    BOOST_CHECK_LT(a1.wh, a2.wh);
    BOOST_CHECK_LT(a1.wh, a2.dt);
    BOOST_CHECK_LT(a1.wh, a2.st);
    BOOST_CHECK_LT(a1.dt, a2.wh);
    BOOST_CHECK_LT(a1.dt, a2.dt);
    BOOST_CHECK_LT(a1.dt, a2.st);
    BOOST_CHECK_LT(a1.st, a2.wh);
    BOOST_CHECK_LT(a1.st, a2.dt);
    BOOST_CHECK_LT(a1.st, a2.st);
    // all handles in a1 are *not* less than handles in a0
    BOOST_CHECK_NOT_LESS(a1.wh, a0.wh);
    BOOST_CHECK_NOT_LESS(a1.wh, a0.dt);
    BOOST_CHECK_NOT_LESS(a1.wh, a0.st);
    BOOST_CHECK_NOT_LESS(a1.dt, a0.wh);
    BOOST_CHECK_NOT_LESS(a1.dt, a0.dt);
    BOOST_CHECK_NOT_LESS(a1.dt, a0.st);
    BOOST_CHECK_NOT_LESS(a1.st, a0.wh);
    BOOST_CHECK_NOT_LESS(a1.st, a0.dt);
    BOOST_CHECK_NOT_LESS(a1.st, a0.st);
    // all handles in a2 are *not* less than handles in a0 or a1
    BOOST_CHECK_NOT_LESS(a2.wh, a0.wh);
    BOOST_CHECK_NOT_LESS(a2.wh, a0.dt);
    BOOST_CHECK_NOT_LESS(a2.wh, a0.st);
    BOOST_CHECK_NOT_LESS(a2.dt, a0.wh);
    BOOST_CHECK_NOT_LESS(a2.dt, a0.dt);
    BOOST_CHECK_NOT_LESS(a2.dt, a0.st);
    BOOST_CHECK_NOT_LESS(a2.st, a0.wh);
    BOOST_CHECK_NOT_LESS(a2.st, a0.dt);
    BOOST_CHECK_NOT_LESS(a2.st, a0.st);
    BOOST_CHECK_NOT_LESS(a2.wh, a1.wh);
    BOOST_CHECK_NOT_LESS(a2.wh, a1.dt);
    BOOST_CHECK_NOT_LESS(a2.wh, a1.st);
    BOOST_CHECK_NOT_LESS(a2.dt, a1.wh);
    BOOST_CHECK_NOT_LESS(a2.dt, a1.dt);
    BOOST_CHECK_NOT_LESS(a2.dt, a1.st);
    BOOST_CHECK_NOT_LESS(a2.st, a1.wh);
    BOOST_CHECK_NOT_LESS(a2.st, a1.dt);
    BOOST_CHECK_NOT_LESS(a2.st, a1.st);
}

BOOST_AUTO_TEST_CASE(string_representation) {
    auto s1 = a0.wh;
    auto s2 = a0.dt;
    auto s3 = a0.st;
    BOOST_CHECK_EQUAL(s1, s2);
    BOOST_CHECK_EQUAL(s2, s3);
}

BOOST_AUTO_TEST_CASE(mpi_string_representation) {
    BOOST_CHECK(sys.message_types(a0.dt).empty());
    std::set<std::string> st_expected {"nil::actor::replies_to<int32_t>::with<int32_t>"};
    BOOST_CHECK_EQUAL(st_expected, sys.message_types(a0.st));
    BOOST_CHECK_EQUAL(st_expected, sys.message_types<testee_actor>());
}

BOOST_AUTO_TEST_SUITE_END()
