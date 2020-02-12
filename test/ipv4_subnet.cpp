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

#define BOOST_TEST_MODULE ipv4_subnet_test

#include <boost/test/unit_test.hpp>

#include <nil/actor/config.hpp>
#include <nil/actor/ipv4_subnet.hpp>

using namespace nil::actor;

namespace {

    const auto addr = make_ipv4_address;

    ipv4_subnet operator/(ipv4_address a, uint8_t prefix) {
        return {a, prefix};
    }

}    // namespace

BOOST_AUTO_TEST_CASE(constructing_test) {
    ipv4_subnet zero {addr(0, 0, 0, 0), 32};
    BOOST_CHECK(zero.network_address() == addr(0, 0, 0, 0));
    BOOST_CHECK_EQUAL(zero.prefix_length(), 32u);
    ipv4_subnet local {addr(127, 0, 0, 0), 8};
    BOOST_CHECK(local.network_address() == addr(127, 0, 0, 0));
    BOOST_CHECK_EQUAL(local.prefix_length(), 8u);
}

BOOST_AUTO_TEST_CASE(equality_test) {
    auto a = addr(0xff, 0xff, 0xff, 0xff) / 19;
    auto b = addr(0xff, 0xff, 0xff, 0xab) / 19;
    auto net = addr(0xff, 0xff, 0xe0, 0x00);
    BOOST_CHECK(a.network_address() == net);
    BOOST_CHECK(a.network_address() == b.network_address());
    BOOST_CHECK_EQUAL(a.prefix_length(), b.prefix_length());
    BOOST_CHECK(a == b);
}

BOOST_AUTO_TEST_CASE(constains_test) {
    ipv4_subnet local {addr(127, 0, 0, 0), 8};
    BOOST_CHECK(local.contains(addr(127, 0, 0, 1)));
    BOOST_CHECK(local.contains(addr(127, 1, 2, 3)));
    BOOST_CHECK(local.contains(addr(127, 128, 0, 0) / 9));
    BOOST_CHECK(local.contains(addr(127, 0, 0, 0) / 8));
    BOOST_CHECK(!local.contains(addr(127, 0, 0, 0) / 7));
}

BOOST_AUTO_TEST_CASE(ordering_test) {
    BOOST_CHECK(addr(192, 168, 168, 0) / 24 == addr(192, 168, 168, 0) / 24);
    BOOST_CHECK(addr(192, 168, 168, 0) / 25 != addr(192, 168, 168, 0) / 24);
    BOOST_CHECK(addr(192, 168, 167, 0) / 24 < addr(192, 168, 168, 0) / 24);
    BOOST_CHECK(addr(192, 168, 168, 0) / 24 < addr(192, 168, 168, 0) / 25);
}
