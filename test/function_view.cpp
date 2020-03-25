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

#define BOOST_TEST_MODULE function_view_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <string>
#include <vector>

#include <nil/actor/all.hpp>

using namespace nil::actor;

namespace {

    using calculator = typed_actor<replies_to<int, int>::with<int>>;

    calculator::behavior_type adder() {
        return {[](int x, int y) { return x + y; }};
    }

    calculator::behavior_type multiplier() {
        return {[](int x, int y) { return x * y; }};
    }

    calculator::behavior_type divider() {
        return {[](int x, int y) -> optional<int> {
            if (y == 0) {
                return none;
            }
            return x / y;
        }};
    }

    using doubler = typed_actor<replies_to<int>::with<int, int>>;

    doubler::behavior_type simple_doubler() {
        return {[](int x) { return std::make_tuple(x, x); }};
    }

    using cell = typed_actor<reacts_to<put_atom, int>, replies_to<get_atom>::with<int>>;

    struct cell_state {
        int value = 0;
    };

    cell::behavior_type simple_cell(cell::stateful_pointer<cell_state> self) {
        return {[=](put_atom, int val) { self->state.value = val; }, [=](get_atom) { return self->state.value; }};
    }

    struct fixture {
        fixture() : system(cfg) {
            // nop
        }

        spawner_config cfg;
        spawner system;
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(function_view_tests, fixture)

BOOST_AUTO_TEST_CASE(empty_function_fiew_test) {
    function_view<calculator> f;
    BOOST_CHECK(f(10, 20) == sec::bad_function_call);
}

BOOST_AUTO_TEST_CASE(single_res_function_view_test) {
    auto f = make_function_view(system.spawn(adder));
    BOOST_CHECK_EQUAL(f(3, 4), 7);
    BOOST_CHECK(f != nullptr);
    BOOST_CHECK(nullptr != f);
    function_view<calculator> g;
    g = std::move(f);
    BOOST_CHECK(f == nullptr);
    BOOST_CHECK(nullptr == f);
    BOOST_CHECK(g != nullptr);
    BOOST_CHECK(nullptr != g);
    BOOST_CHECK_EQUAL(g(10, 20), 30);
    g.assign(system.spawn(multiplier));
    BOOST_CHECK_EQUAL(g(10, 20), 200);
    g.assign(system.spawn(divider));
    BOOST_CHECK(!g(1, 0));
    g.assign(system.spawn(divider));
    BOOST_CHECK_EQUAL(g(4, 2), 2);
}

BOOST_AUTO_TEST_CASE(tuple_res_function_view_test) {
    auto f = make_function_view(system.spawn(simple_doubler));
    BOOST_CHECK(f(10) == std::make_tuple(10, 10));
}

BOOST_AUTO_TEST_CASE(cell_function_view_test) {
    auto f = make_function_view(system.spawn(simple_cell));
    BOOST_CHECK_EQUAL(f(get_atom::value), 0);
    f(put_atom::value, 1024);
    BOOST_CHECK_EQUAL(f(get_atom::value), 1024);
}

BOOST_AUTO_TEST_SUITE_END()
