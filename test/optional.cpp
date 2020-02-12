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

#define BOOST_TEST_MODULE optional_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <nil/actor/config.hpp>
#include <nil/actor/optional.hpp>

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

BOOST_AUTO_TEST_CASE(empty_test) {
    optional<int> x;
    optional<int> y;
    BOOST_CHECK(x == y);
    BOOST_CHECK(!(x != y));
}

BOOST_AUTO_TEST_CASE(equality_test) {
    optional<int> x = 42;
    optional<int> y = 7;
    BOOST_CHECK(x != y);
    BOOST_CHECK(!(x == y));
}

BOOST_AUTO_TEST_CASE(ordering_test) {
    optional<int> x = 42;
    optional<int> y = 7;
    BOOST_CHECK(x > y);
    BOOST_CHECK(x >= y);
    BOOST_CHECK(y < x);
    BOOST_CHECK(y <= x);
    BOOST_CHECK(!(y > x));
    BOOST_CHECK(!(y >= x));
    BOOST_CHECK(!(x < y));
    BOOST_CHECK(!(x <= y));
    BOOST_CHECK(x < 4711);
    BOOST_CHECK(4711 > x);
    BOOST_CHECK(4711 >= x);
    BOOST_CHECK(!(x > 4711));
    BOOST_CHECK(!(x >= 4711));
    BOOST_CHECK(!(4211 < x));
    BOOST_CHECK(!(4211 <= x));
}

BOOST_AUTO_TEST_CASE(custom_type_none_test) {
    optional<qwertz> x;
    BOOST_CHECK(x == none);
}

BOOST_AUTO_TEST_CASE(custom_type_engaged_test) {
    qwertz obj {1, 2};
    optional<qwertz> x = obj;
    BOOST_CHECK(x != none);
    BOOST_CHECK(obj == x);
    BOOST_CHECK(x == obj);
    BOOST_CHECK(obj == *x);
    BOOST_CHECK(*x == obj);
}
