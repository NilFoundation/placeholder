//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE span

#include <nil/actor/span.hpp>

#include "core-test.hpp"

#include <algorithm>

using namespace nil::actor;

namespace {

    using i8_list = std::vector<int8_t>;

    using i16_list = std::vector<int16_t>;

    template<class T, class U>
    bool equal(const T &xs, const U &ys) {
        return xs.size() == ys.size() && std::equal(xs.begin(), xs.end(), ys.begin());
    }

    struct fixture {
        i8_list chars {'a', 'b', 'c', 'd', 'e', 'f'};

        i8_list rchars {'f', 'e', 'd', 'c', 'b', 'a'};

        i16_list shorts {1, 2, 4, 8, 16, 32, 64};

        i16_list rshorts {64, 32, 16, 8, 4, 2, 1};
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(span_tests, fixture)

BOOST_AUTO_TEST_CASE(default_construction) {
    span<int> xs;
    BOOST_CHECK_EQUAL(xs.size(), 0u);
    BOOST_CHECK_EQUAL(xs.empty(), true);
    BOOST_CHECK_EQUAL(xs.data(), nullptr);
    BOOST_CHECK_EQUAL(xs.size_bytes(), 0u);
    BOOST_CHECK_EQUAL(xs.begin(), xs.end());
    BOOST_CHECK_EQUAL(xs.cbegin(), xs.cend());
    BOOST_CHECK_EQUAL(xs.rbegin(), xs.rend());
    BOOST_CHECK_EQUAL(xs.crbegin(), xs.crend());
    BOOST_CHECK_EQUAL(as_bytes(xs).size_bytes(), 0u);
    BOOST_CHECK_EQUAL(as_writable_bytes(xs).size_bytes(), 0u);
}

BOOST_AUTO_TEST_CASE(iterators) {
    auto xs = make_span(chars);
    ACTOR_CHECK(std::equal(xs.begin(), xs.end(), chars.begin()));
    ACTOR_CHECK(std::equal(xs.rbegin(), xs.rend(), rchars.begin()));
    auto ys = make_span(shorts);
    ACTOR_CHECK(std::equal(ys.begin(), ys.end(), shorts.begin()));
    ACTOR_CHECK(std::equal(ys.rbegin(), ys.rend(), rshorts.begin()));
}

BOOST_AUTO_TEST_CASE(subspans) {
    auto xs = make_span(chars);
    ACTOR_CHECK(equal(xs.first(6), xs));
    ACTOR_CHECK(equal(xs.last(6), xs));
    ACTOR_CHECK(equal(xs.subspan(0, 6), xs));
    ACTOR_CHECK(equal(xs.first(3), i8_list({'a', 'b', 'c'})));
    ACTOR_CHECK(equal(xs.last(3), i8_list({'d', 'e', 'f'})));
    ACTOR_CHECK(equal(xs.subspan(2, 2), i8_list({'c', 'd'})));
}

BOOST_AUTO_TEST_CASE(free_iterator_functions) {
    auto xs = make_span(chars);
    BOOST_CHECK_EQUAL(xs.begin(), begin(xs));
    BOOST_CHECK_EQUAL(xs.cbegin(), cbegin(xs));
    BOOST_CHECK_EQUAL(xs.end(), end(xs));
    BOOST_CHECK_EQUAL(xs.cend(), cend(xs));
}

BOOST_AUTO_TEST_CASE(as_bytes) {
    auto xs = make_span(chars);
    auto ys = make_span(shorts);
    BOOST_CHECK_EQUAL(as_bytes(xs).size(), chars.size());
    BOOST_CHECK_EQUAL(as_bytes(ys).size(), shorts.size() * 2);
    BOOST_CHECK_EQUAL(as_writable_bytes(xs).size(), chars.size());
    BOOST_CHECK_EQUAL(as_writable_bytes(ys).size(), shorts.size() * 2);
}

BOOST_AUTO_TEST_CASE(make_span) {
    auto xs = make_span(chars);
    auto ys = make_span(chars.data(), chars.size());
    auto zs = make_span(chars.data(), chars.data() + chars.size());
    ACTOR_CHECK(std::equal(xs.begin(), xs.end(), chars.begin()));
    ACTOR_CHECK(std::equal(ys.begin(), ys.end(), chars.begin()));
    ACTOR_CHECK(std::equal(zs.begin(), zs.end(), chars.begin()));
    BOOST_CHECK_EQUAL(end(xs), end(ys));
    BOOST_CHECK_EQUAL(end(ys), end(zs));
    BOOST_CHECK_EQUAL(begin(xs), begin(ys));
    BOOST_CHECK_EQUAL(begin(ys), begin(zs));
}

BOOST_AUTO_TEST_CASE(spans_are_convertible_from_compatible_containers) {
    std::vector<int> xs {1, 2, 3};
    span<const int> ys {xs};
    ACTOR_CHECK(std::equal(xs.begin(), xs.end(), ys.begin()));
}

BOOST_AUTO_TEST_SUITE_END()
