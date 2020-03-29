//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE ipv6_address

#include <nil/actor/ipv6_address.hpp>

#include "core-test.hpp"

#include <initializer_list>

#include <nil/actor/ipv4_address.hpp>

using namespace nil::actor;

namespace {

    using array_type = ipv6_address::array_type;

    ipv6_address addr(std::initializer_list<uint16_t> prefix, std::initializer_list<uint16_t> suffix = {}) {
        return ipv6_address {prefix, suffix};
    }

}    // namespace

BOOST_AUTO_TEST_CASE(constructing) {
    ipv6_address::array_type localhost_bytes {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};
    ipv6_address localhost {localhost_bytes};
    BOOST_CHECK_EQUAL(localhost.data(), localhost_bytes);
    BOOST_CHECK_EQUAL(localhost, addr({}, {0x01}));
}

BOOST_AUTO_TEST_CASE(comparison) {
    BOOST_CHECK_EQUAL(addr({1, 2, 3}), addr({1, 2, 3}));
    ACTOR_CHECK_NOT_EQUAL(addr({3, 2, 1}), addr({1, 2, 3}));
    BOOST_CHECK_EQUAL(addr({}, {0xFFFF, 0x7F00, 0x0001}), make_ipv4_address(127, 0, 0, 1));
}

BOOST_AUTO_TEST_CASE(from_string) {
    auto from_string = [](string_view str) {
        ipv6_address result;
        auto err = parse(str, result);
        if (err)
            BOOST_FAIL("error while parsing " << str << ": " << to_string(err));
        return result;
    };
    BOOST_CHECK_EQUAL(from_string("::1"), addr({}, {0x01}));
    BOOST_CHECK_EQUAL(from_string("::11"), addr({}, {0x11}));
    BOOST_CHECK_EQUAL(from_string("::112"), addr({}, {0x0112}));
    BOOST_CHECK_EQUAL(from_string("::1122"), addr({}, {0x1122}));
    BOOST_CHECK_EQUAL(from_string("::1:2"), addr({}, {0x01, 0x02}));
    BOOST_CHECK_EQUAL(from_string("::1:2"), addr({}, {0x01, 0x02}));
    BOOST_CHECK_EQUAL(from_string("1::1"), addr({0x01}, {0x01}));
    BOOST_CHECK_EQUAL(from_string("2a00:bdc0:e003::"), addr({0x2a00, 0xbdc0, 0xe003}, {}));
    BOOST_CHECK_EQUAL(from_string("1::"), addr({0x01}, {}));
    BOOST_CHECK_EQUAL(from_string("0.1.0.1"), addr({}, {0xFFFF, 0x01, 0x01}));
    BOOST_CHECK_EQUAL(from_string("::ffff:127.0.0.1"), addr({}, {0xFFFF, 0x7F00, 0x0001}));
    BOOST_CHECK_EQUAL(from_string("1:2:3:4:5:6:7:8"), addr({1, 2, 3, 4, 5, 6, 7, 8}));
    BOOST_CHECK_EQUAL(from_string("1:2:3:4::5:6:7:8"), addr({1, 2, 3, 4, 5, 6, 7, 8}));
    BOOST_CHECK_EQUAL(from_string("1:2:3:4:5:6:0.7.0.8"), addr({1, 2, 3, 4, 5, 6, 7, 8}));
    auto invalid = [](string_view str) {
        ipv6_address result;
        auto err = parse(str, result);
        return err != none;
    };
    ACTOR_CHECK(invalid("1:2:3:4:5:6:7:8:9"));
    ACTOR_CHECK(invalid("1:2:3:4::5:6:7:8:9"));
    ACTOR_CHECK(invalid("1:2:3::4:5:6::7:8:9"));
}

BOOST_AUTO_TEST_CASE(to_string) {
    BOOST_CHECK_EQUAL(to_string(addr({}, {0x01})), "::1");
    BOOST_CHECK_EQUAL(to_string(addr({0x01}, {0x01})), "1::1");
    BOOST_CHECK_EQUAL(to_string(addr({0x01})), "1::");
    BOOST_CHECK_EQUAL(to_string(addr({}, {0xFFFF, 0x01, 0x01})), "0.1.0.1");
}
