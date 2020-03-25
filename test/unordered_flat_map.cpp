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

#define BOOST_TEST_MODULE unordered_flat_map_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

#include <nil/actor/detail/unordered_flat_map.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            template<class T>
            bool operator==(const unordered_flat_map<int, T> &xs, const std::vector<std::pair<int, T>> &ys) {
                return xs.container() == ys;
            }

            template<class T>
            bool operator==(const std::vector<std::pair<int, T>> &xs, const unordered_flat_map<int, T> &ys) {
                return ys == xs;
            }

        }    // namespace detail
    }        // namespace actor
}    // namespace nil

using nil::actor::detail::unordered_flat_map;

using namespace nil::actor;

template<class T>
using kvp_vec = std::vector<std::pair<int, T>>;

kvp_vec<int> ivec(std::initializer_list<std::pair<int, int>> xs) {
    return {xs};
}

kvp_vec<std::string> svec(std::initializer_list<std::pair<int, std::string>> xs) {
    return {xs};
}

struct fixture {
    unordered_flat_map<int, int> xs;
    unordered_flat_map<int, std::string> ys;

    // fills xs with {1, 10} ... {4, 40}
    void fill_xs() {
        for (int i = 1; i < 5; ++i) {
            xs.emplace(i, i * 10);
        }
    }

    // fills xs with {1, "a"} ... {4, "d"}
    void fill_ys() {
        char buf[] = {'\0', '\0'};
        for (int i = 0; i < 4; ++i) {
            buf[0] = static_cast<char>('a' + i);
            ys.emplace(i + 1, buf);
        }
    }

    static std::pair<int, int> kvp(int x, int y) {
        return std::make_pair(x, y);
    }

    static std::pair<int, std::string> kvp(int x, std::string y) {
        return std::make_pair(x, std::move(y));
    }
};

BOOST_FIXTURE_TEST_SUITE(unordered_flat_map_tests, fixture)

BOOST_AUTO_TEST_CASE(default_constructed_test) {
    // A default-constructed map must be empty, i.e., have size 0.
    BOOST_CHECK_EQUAL(xs.empty(), true);
    BOOST_CHECK_EQUAL(xs.size(), 0u);
    // The begin() and end() iterators must compare equal.
    BOOST_CHECK(xs.begin() == xs.end());
    BOOST_CHECK(xs.cbegin() == xs.begin());
    BOOST_CHECK(xs.cend() == xs.end());
    BOOST_CHECK(xs.cbegin() == xs.cend());
    BOOST_CHECK(xs.rbegin() == xs.rend());
    // Calling begin() and end() on a const reference must return the same as
    // cbegin() and cend().
    const auto &cxs = xs;
    BOOST_CHECK(cxs.begin() == xs.cbegin());
    BOOST_CHECK(cxs.end() == xs.cend());
}

BOOST_AUTO_TEST_CASE(initializer_list_constructed_test) {
    unordered_flat_map<int, int> zs {{1, 10}, {2, 20}, {3, 30}, {4, 40}};
    BOOST_CHECK_EQUAL(zs.size(), 4u);
    BOOST_CHECK(zs == ivec({{1, 10}, {2, 20}, {3, 30}, {4, 40}}));
}

BOOST_AUTO_TEST_CASE(range_constructed_test) {
    kvp_vec<int> tmp {{1, 10}, {2, 20}, {3, 30}, {4, 40}};
    unordered_flat_map<int, int> zs(tmp.begin(), tmp.end());
    BOOST_CHECK_EQUAL(zs.size(), 4u);
    BOOST_CHECK(zs == tmp);
}

BOOST_AUTO_TEST_CASE(integer_insertion_test) {
    xs.insert(kvp(3, 30));
    xs.insert(xs.begin(), kvp(2, 20));
    xs.insert(xs.cbegin(), kvp(1, 10));
    xs.emplace(5, 50);
    xs.emplace_hint(xs.cend() - 1, 4, 40);
    BOOST_CHECK(xs == ivec({{1, 10}, {2, 20}, {3, 30}, {4, 40}, {5, 50}}));
}

BOOST_AUTO_TEST_CASE(integer_removal_test) {
    fill_xs();
    BOOST_CHECK(xs == ivec({{1, 10}, {2, 20}, {3, 30}, {4, 40}}));
    xs.erase(xs.begin());
    BOOST_CHECK(xs == ivec({{2, 20}, {3, 30}, {4, 40}}));
    xs.erase(xs.begin(), xs.begin() + 2);
    BOOST_CHECK(xs == ivec({{4, 40}}));
    xs.erase(4);
    BOOST_CHECK_EQUAL(xs.empty(), true);
    BOOST_CHECK_EQUAL(xs.size(), 0u);
}

BOOST_AUTO_TEST_CASE(lookup_test) {
    fill_xs();
    BOOST_CHECK_EQUAL(xs.count(2), 1u);
    BOOST_CHECK_EQUAL(xs.count(6), 0u);
    // trigger non-const member functions
    BOOST_CHECK_EQUAL(xs.at(3), 30);
    BOOST_CHECK(xs.find(1) == xs.begin());
    BOOST_CHECK(xs.find(2) == xs.begin() + 1);
    // trigger const member functions
    const auto &cxs = xs;
    BOOST_CHECK_EQUAL(cxs.at(2), 20);
    BOOST_CHECK(cxs.find(4) == xs.end() - 1);
    BOOST_CHECK(cxs.find(5) == xs.end());
}

#ifndef ACTOR_NO_EXCEPTIONS
BOOST_AUTO_TEST_CASE(exceptions_test) {
    fill_xs();
    try {
        auto x = xs.at(10);
        BOOST_FAIL("got an unexpected value: " << x);
    } catch (std::out_of_range &) {
        BOOST_TEST_MESSAGE("got expected out_of_range exception");
    } catch (...) {
        BOOST_FAIL("got an expected exception");
    }
}

#endif    // ACTOR_NO_EXCEPTIONS

// We repeat several tests with std::strings as value type instead of integers to
// trigger non-trivial destructors.

BOOST_AUTO_TEST_CASE(string_insertion_test) {
    ys.insert(kvp(3, "c"));
    ys.insert(ys.begin(), kvp(2, "b"));
    ys.insert(ys.cbegin(), kvp(1, "a"));
    ys.emplace(5, "e");
    ys.emplace_hint(ys.cend() - 1, 4, "d");
    kvp_vec<std::string> tmp {{1, "a"}, {2, "b"}, {3, "c"}, {4, "d"}, {5, "e"}};
    BOOST_CHECK(ys == tmp);
}

BOOST_AUTO_TEST_CASE(string_removal_test) {
    fill_ys();
    BOOST_CHECK(ys == svec({{1, "a"}, {2, "b"}, {3, "c"}, {4, "d"}}));
    ys.erase(ys.begin());
    BOOST_CHECK(ys == svec({{2, "b"}, {3, "c"}, {4, "d"}}));
    ys.erase(ys.begin(), ys.begin() + 2);
    BOOST_CHECK(ys == svec({{4, "d"}}));
    ys.erase(4);
    BOOST_CHECK_EQUAL(ys.empty(), true);
    BOOST_CHECK_EQUAL(ys.size(), 0u);
}

BOOST_AUTO_TEST_SUITE_END()
