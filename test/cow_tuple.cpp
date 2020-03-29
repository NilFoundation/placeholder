//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE cow_tuple

#include <nil/actor/cow_tuple.hpp>

#include "core-test.hpp"

using std::make_tuple;
using std::string;
using std::tuple;

using namespace caf;

BOOST_AUTO_TEST_CASE(default_construction) {
    cow_tuple<string, string> x;
    BOOST_CHECK_EQUAL(x.unique(), true);
    BOOST_CHECK_EQUAL(get<0>(x), "");
    BOOST_CHECK_EQUAL(get<1>(x), "");
}

BOOST_AUTO_TEST_CASE(value_construction) {
    cow_tuple<int, int> x {1, 2};
    BOOST_CHECK_EQUAL(x.unique(), true);
    BOOST_CHECK_EQUAL(get<0>(x), 1);
    BOOST_CHECK_EQUAL(get<1>(x), 2);
    BOOST_CHECK_EQUAL(x, make_cow_tuple(1, 2));
}

BOOST_AUTO_TEST_CASE(copy_construction) {
    cow_tuple<int, int> x {1, 2};
    cow_tuple<int, int> y {x};
    BOOST_CHECK_EQUAL(x, y);
    BOOST_CHECK_EQUAL(x.ptr(), y.ptr());
    BOOST_CHECK_EQUAL(x.unique(), false);
    BOOST_CHECK_EQUAL(y.unique(), false);
}

BOOST_AUTO_TEST_CASE(move_construction) {
    cow_tuple<int, int> x {1, 2};
    cow_tuple<int, int> y {std::move(x)};
    BOOST_CHECK_EQUAL(x.ptr(), nullptr);
    BOOST_CHECK_EQUAL(y, make_tuple(1, 2));
    BOOST_CHECK_EQUAL(y.unique(), true);
}

BOOST_AUTO_TEST_CASE(copy_assignment) {
    cow_tuple<int, int> x {1, 2};
    cow_tuple<int, int> y {3, 4};
    BOOST_CHECK_NE(x, y);
    x = y;
    BOOST_CHECK_EQUAL(x, y);
    BOOST_CHECK_EQUAL(x.ptr(), y.ptr());
    BOOST_CHECK_EQUAL(x.unique(), false);
    BOOST_CHECK_EQUAL(y.unique(), false);
}

BOOST_AUTO_TEST_CASE(move_assignment) {
    cow_tuple<int, int> x {1, 2};
    cow_tuple<int, int> y {3, 4};
    BOOST_CHECK_NE(x, y);
    x = std::move(y);
    BOOST_CHECK_EQUAL(x, make_tuple(3, 4));
    BOOST_CHECK_EQUAL(x.unique(), true);
    BOOST_CHECK_EQUAL(y.ptr(), nullptr);
}

BOOST_AUTO_TEST_CASE(make_cow_tuple) {
    cow_tuple<int, int> x {1, 2};
    auto y = make_cow_tuple(1, 2);
    BOOST_CHECK_EQUAL(x, y);
    BOOST_CHECK_EQUAL(x.unique(), true);
    BOOST_CHECK_EQUAL(y.unique(), true);
}

BOOST_AUTO_TEST_CASE(unsharing) {
    auto x = make_cow_tuple(string {"old"}, string {"school"});
    auto y = x;
    BOOST_CHECK_EQUAL(x.unique(), false);
    BOOST_CHECK_EQUAL(y.unique(), false);
    get<0>(y.unshared()) = "new";
    BOOST_CHECK_EQUAL(x.unique(), true);
    BOOST_CHECK_EQUAL(y.unique(), true);
    BOOST_CHECK_EQUAL(x.data(), make_tuple("old", "school"));
    BOOST_CHECK_EQUAL(y.data(), make_tuple("new", "school"));
}

BOOST_AUTO_TEST_CASE(to_string) {
    auto x = make_cow_tuple(1, string {"abc"});
    BOOST_CHECK_EQUAL(deep_to_string(x), "(1, \"abc\")");
}

BOOST_FIXTURE_TEST_SUITE(cow_tuple_tests, test_coordinator_fixture<>)

BOOST_AUTO_TEST_CASE(serialization) {
    auto x = make_cow_tuple(1, 2, 3);
    auto y = roundtrip(x);
    BOOST_CHECK_EQUAL(x, y);
    BOOST_CHECK_EQUAL(x.unique(), true);
    BOOST_CHECK_EQUAL(y.unique(), true);
    BOOST_CHECK_NE(x.ptr(), y.ptr());
}

BOOST_AUTO_TEST_SUITE_END()
