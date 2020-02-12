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

#define BOOST_TEST_MODULE ipv6_subnet_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <nil/actor/test/dsl.hpp>

#include <nil/actor/ipv6_subnet.hpp>
#include <nil/actor/config.hpp>

using namespace nil::actor;

namespace {

    ipv6_subnet operator/(ipv6_address addr, uint8_t prefix) {
        return {addr, prefix};
    }

}    // namespace

BOOST_AUTO_TEST_CASE(constructing_test) {
    auto zero = ipv6_address() / 128;
    BOOST_CHECK(zero.network_address() == ipv6_address());
    BOOST_CHECK_EQUAL(zero.prefix_length(), 128u);
}

BOOST_AUTO_TEST_CASE(equality_test) {
    auto a = ipv6_address {{0xffff, 0xffff, 0xffff}, {}} / 27;
    auto b = ipv6_address {{0xffff, 0xffff, 0xabab}, {}} / 27;
    auto net = ipv6_address {{0xffff, 0xffe0}, {}};
    BOOST_CHECK(a.network_address() == net);
    BOOST_CHECK(a.network_address() == b.network_address());
    BOOST_CHECK_EQUAL(a.prefix_length(), b.prefix_length());
    BOOST_CHECK(a == b);
}

BOOST_AUTO_TEST_CASE(constains_test) {
    auto local = ipv6_address {{0xbebe, 0xbebe}, {}} / 32;
    BOOST_CHECK(local.contains(ipv6_address({0xbebe, 0xbebe, 0xbebe}, {})));
    BOOST_CHECK(!local.contains(ipv6_address({0xbebe, 0xbebf}, {})));
}

BOOST_AUTO_TEST_CASE(embedding_test) {
    ipv4_subnet v4_local {make_ipv4_address(127, 0, 0, 1), 8};
    ipv6_subnet local {v4_local};
    BOOST_CHECK(local.embeds_v4());
    BOOST_CHECK_EQUAL(local.prefix_length(), 104u);
}
