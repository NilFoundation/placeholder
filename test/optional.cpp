//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE optional

#include <nil/actor/optional.hpp>

#include "core-test.hpp"

using namespace nil::actor;

namespace {

    struct qwertz {
        qwertz(int x, int y) : x_(x), y_(y) {
            // nop
        }
        int x_;
        int y_;
    };

    bool operator==(const qwertz &lhs, const qwertz &rhs) {
        return lhs.x_ == rhs.x_ && lhs.y_ == rhs.y_;
    }

}    // namespace

BOOST_AUTO_TEST_CASE(empty) {
    optional<int> x;
    optional<int> y;
    ACTOR_CHECK(x == y);
    ACTOR_CHECK(!(x != y));
}

BOOST_AUTO_TEST_CASE(equality) {
    optional<int> x = 42;
    optional<int> y = 7;
    ACTOR_CHECK(x != y);
    ACTOR_CHECK(!(x == y));
}

BOOST_AUTO_TEST_CASE(ordering) {
    optional<int> x = 42;
    optional<int> y = 7;
    ACTOR_CHECK(x > y);
    ACTOR_CHECK(x >= y);
    ACTOR_CHECK(y < x);
    ACTOR_CHECK(y <= x);
    ACTOR_CHECK(!(y > x));
    ACTOR_CHECK(!(y >= x));
    ACTOR_CHECK(!(x < y));
    ACTOR_CHECK(!(x <= y));
    ACTOR_CHECK(x < 4711);
    ACTOR_CHECK(4711 > x);
    ACTOR_CHECK(4711 >= x);
    ACTOR_CHECK(!(x > 4711));
    ACTOR_CHECK(!(x >= 4711));
    ACTOR_CHECK(!(4211 < x));
    ACTOR_CHECK(!(4211 <= x));
}

BOOST_AUTO_TEST_CASE(custom_type_none) {
    optional<qwertz> x;
    ACTOR_CHECK(x == none);
}

BOOST_AUTO_TEST_CASE(custom_type_engaged) {
    qwertz obj {1, 2};
    optional<qwertz> x = obj;
    ACTOR_CHECK(x != none);
    ACTOR_CHECK(obj == x);
    ACTOR_CHECK(x == obj);
    ACTOR_CHECK(obj == *x);
    ACTOR_CHECK(*x == obj);
}
