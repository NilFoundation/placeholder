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

#define BOOST_TEST_MODULE dictionary_test

#include <nil/actor/test/dsl.hpp>

#include <nil/actor/dictionary.hpp>

using namespace nil::actor;

namespace {

    using int_dict = dictionary<int>;

    struct fixture {};

}    // namespace

BOOST_FIXTURE_TEST_SUITE(dictionary_tests, fixture)

BOOST_AUTO_TEST_CASE(construction_and_comparions_test) {
    int_dict xs;
    BOOST_CHECK_EQUAL(xs.empty(), true);
    BOOST_CHECK_EQUAL(xs.size(), 0u);
    int_dict ys {{"foo", 1}, {"bar", 2}};
    BOOST_CHECK_EQUAL(ys.empty(), false);
    BOOST_CHECK_EQUAL(ys.size(), 2u);
    BOOST_CHECK(xs != ys);
    int_dict zs {ys.begin(), ys.end()};
    BOOST_CHECK_EQUAL(zs.empty(), false);
    BOOST_CHECK_EQUAL(zs.size(), 2u);
    BOOST_CHECK(ys == zs);
    zs.clear();

    BOOST_CHECK_EQUAL(zs.empty(), true);
    BOOST_CHECK_EQUAL(zs.size(), 0u);
    BOOST_CHECK(xs == zs);
}

BOOST_AUTO_TEST_CASE(iterators_test) {
    using std::equal;
    using vector_type = std::vector<int_dict::value_type>;
    int_dict xs {{"a", 1}, {"b", 2}, {"c", 3}};
    vector_type ys {{"a", 1}, {"b", 2}, {"c", 3}};
    BOOST_CHECK(equal(xs.begin(), xs.end(), ys.begin()));
    BOOST_CHECK(equal(xs.cbegin(), xs.cend(), ys.cbegin()));
    BOOST_CHECK(equal(xs.rbegin(), xs.rend(), ys.rbegin()));
    BOOST_CHECK(equal(xs.crbegin(), xs.crend(), ys.crbegin()));
}

BOOST_AUTO_TEST_CASE(swapping_test) {
    int_dict xs {{"foo", 1}, {"bar", 2}};
    int_dict ys;
    int_dict zs {{"foo", 1}, {"bar", 2}};
    BOOST_CHECK(xs != ys);
    BOOST_CHECK(ys != zs);
    BOOST_CHECK(xs == zs);
    xs.swap(ys);
    BOOST_CHECK(xs != ys);
    BOOST_CHECK(ys == zs);
    BOOST_CHECK(xs != zs);
}

BOOST_AUTO_TEST_CASE(emplacing_test) {
    int_dict xs;
    BOOST_CHECK_EQUAL(xs.emplace("x", 1).second, true);
    BOOST_CHECK_EQUAL(xs.emplace("y", 2).second, true);
    BOOST_CHECK_EQUAL(xs.emplace("y", 3).second, false);
}

BOOST_AUTO_TEST_CASE(insertion_test) {
    int_dict xs;
    BOOST_CHECK_EQUAL(xs.insert("a", 1).second, true);
    BOOST_CHECK_EQUAL(xs.insert("b", 2).second, true);
    BOOST_CHECK_EQUAL(xs.insert("c", 3).second, true);
    BOOST_CHECK_EQUAL(xs.insert("c", 4).second, false);
    int_dict ys;
    BOOST_CHECK_EQUAL(ys.insert_or_assign("a", 1).second, true);
    BOOST_CHECK_EQUAL(ys.insert_or_assign("b", 2).second, true);
    BOOST_CHECK_EQUAL(ys.insert_or_assign("c", 0).second, true);
    BOOST_CHECK_EQUAL(ys.insert_or_assign("c", 3).second, false);
    BOOST_CHECK(xs == ys);
}

BOOST_AUTO_TEST_CASE(insertion_with_hint_test) {
    int_dict xs;
    auto xs_last = xs.end();
    auto xs_insert = [&](string_view key, int val) { xs_last = xs.insert(xs_last, key, val); };
    xs_insert("a", 1);
    xs_insert("c", 3);
    xs_insert("b", 2);
    xs_insert("c", 4);
    int_dict ys;
    auto ys_last = ys.end();
    auto ys_insert_or_assign = [&](string_view key, int val) { ys_last = ys.insert_or_assign(ys_last, key, val); };
    ys_insert_or_assign("a", 1);
    ys_insert_or_assign("c", 0);
    ys_insert_or_assign("b", 2);
    ys_insert_or_assign("c", 3);
    BOOST_CHECK(xs == ys);
}

BOOST_AUTO_TEST_CASE(bounds_test) {
    int_dict xs {{"a", 1}, {"b", 2}, {"c", 3}, {"d", 4}};
    const int_dict &const_xs = xs;
    BOOST_CHECK_EQUAL(xs.lower_bound("c")->first, "c");
    BOOST_CHECK_EQUAL(xs.upper_bound("c")->first, "d");
    BOOST_CHECK_EQUAL(const_xs.lower_bound("c")->first, "c");
    BOOST_CHECK_EQUAL(const_xs.upper_bound("c")->first, "d");
}

BOOST_AUTO_TEST_CASE(find_test) {
    int_dict xs {{"a", 1}, {"b", 2}, {"c", 3}, {"d", 4}};
    const int_dict &const_xs = xs;
    BOOST_CHECK(xs.find("e") == xs.end());
    BOOST_CHECK_EQUAL(xs.find("a")->second, 1);
    BOOST_CHECK_EQUAL(xs.find("c")->second, 3);
    BOOST_CHECK(const_xs.find("e") == xs.end());
    BOOST_CHECK_EQUAL(const_xs.find("a")->second, 1);
    BOOST_CHECK_EQUAL(const_xs.find("c")->second, 3);
}

BOOST_AUTO_TEST_CASE(element_access_test) {
    int_dict xs {{"a", 1}, {"b", 2}, {"c", 3}, {"d", 4}};
    BOOST_CHECK_EQUAL(xs["a"], 1);
    BOOST_CHECK_EQUAL(xs["b"], 2);
    BOOST_CHECK_EQUAL(xs["e"], 0);
}

BOOST_AUTO_TEST_SUITE_END()
