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

#define BOOST_TEST_MODULE ipv4_address_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <nil/actor/config.hpp>
#include <nil/actor/test/dsl.hpp>

#include <nil/actor/ipv4_address.hpp>
#include <nil/actor/ipv4_endpoint.hpp>

#include <nil/actor/detail/parse.hpp>
#include <nil/actor/detail/network_order.hpp>

using namespace nil::actor;
using nil::actor::detail::to_network_order;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<>
            struct print_log_value<ipv4_address> {
                void operator()(std::ostream &, ipv4_address const &) {
                }
            };

            template<>
            struct print_log_value<ipv4_endpoint> {
                void operator()(std::ostream &, ipv4_endpoint const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

namespace {

    ipv4_endpoint operator"" _ep(const char *str, size_t size) {
        ipv4_endpoint result;
        if (auto err = detail::parse(string_view {str, size}, result))
            BOOST_FAIL("unable to parse input: " << to_string(err));
        return result;
    }

    struct fixture {
        spawner_config cfg;
        spawner sys {cfg};

        template<class T>
        T roundtrip(T x) {
            byte_buffer buf;
            binary_serializer sink(sys, buf);
            if (auto err = sink(x))
                BOOST_FAIL("serialization failed: " << sys.render(err));
            binary_deserializer source(sys, make_span(buf));
            T y;
            if (auto err = source(y))
                BOOST_FAIL("deserialization failed: " << sys.render(err));
            return y;
        }
    };

#define CHECK_TO_STRING(addr) BOOST_CHECK_EQUAL(addr, nil::actor::to_string(addr##_ep))

#define CHECK_COMPARISON(addr1, addr2)         \
    BOOST_CHECK_GT(addr2##_ep, addr1##_ep);    \
    BOOST_CHECK_GE(addr2##_ep, addr1##_ep);    \
    BOOST_CHECK_GE(addr1##_ep, addr1##_ep);    \
    BOOST_CHECK_GE(addr2##_ep, addr2##_ep);    \
    BOOST_CHECK_EQUAL(addr1##_ep, addr1##_ep); \
    BOOST_CHECK_EQUAL(addr2##_ep, addr2##_ep); \
    BOOST_CHECK_LE(addr1##_ep, addr2##_ep);    \
    BOOST_CHECK_LE(addr1##_ep, addr1##_ep);    \
    BOOST_CHECK_LE(addr2##_ep, addr2##_ep);    \
    BOOST_CHECK_NE(addr1##_ep, addr2##_ep);    \
    BOOST_CHECK_NE(addr2##_ep, addr1##_ep);

#define CHECK_SERIALIZATION(addr) BOOST_CHECK_EQUAL(addr##_ep, roundtrip(addr##_ep))

}    // namespace

BOOST_FIXTURE_TEST_SUITE(ipv4_endpoint_tests, fixture)

BOOST_AUTO_TEST_CASE(constructing_assigning_and_hash_code) {
    const uint16_t port = 8888;
    auto addr = make_ipv4_address(127, 0, 0, 1);
    ipv4_endpoint ep1(addr, port);
    BOOST_CHECK_EQUAL(ep1.address(), addr);
    BOOST_CHECK_EQUAL(ep1.port(), port);
    ipv4_endpoint ep2;
    ep2.address(addr);
    ep2.port(port);
    BOOST_CHECK_EQUAL(ep2.address(), addr);
    BOOST_CHECK_EQUAL(ep2.port(), port);
    BOOST_CHECK_EQUAL(ep1, ep2);
    BOOST_CHECK_EQUAL(ep1.hash_code(), ep2.hash_code());
}

BOOST_AUTO_TEST_CASE(to_string) {
    CHECK_TO_STRING("127.0.0.1:8888");
    CHECK_TO_STRING("192.168.178.1:8888");
    CHECK_TO_STRING("255.255.255.1:17");
    CHECK_TO_STRING("192.168.178.1:8888");
    CHECK_TO_STRING("127.0.0.1:111");
    CHECK_TO_STRING("123.123.123.123:8888");
    CHECK_TO_STRING("127.0.0.1:8888");
}

BOOST_AUTO_TEST_CASE(comparison) {
    CHECK_COMPARISON("127.0.0.1:8888", "127.0.0.2:8888");
    CHECK_COMPARISON("192.168.178.1:8888", "245.114.2.89:8888");
    CHECK_COMPARISON("188.56.23.97:1211", "189.22.36.0:1211");
    CHECK_COMPARISON("0.0.0.0:8888", "255.255.255.1:8888");
    CHECK_COMPARISON("127.0.0.1:111", "127.0.0.1:8888");
    CHECK_COMPARISON("192.168.178.1:8888", "245.114.2.89:8888");
    CHECK_COMPARISON("123.123.123.123:8888", "123.123.123.123:8889");
}

BOOST_AUTO_TEST_CASE(serialization) {
    CHECK_SERIALIZATION("127.0.0.1:8888");
    CHECK_SERIALIZATION("192.168.178.1:8888");
    CHECK_SERIALIZATION("255.255.255.1:17");
    CHECK_SERIALIZATION("192.168.178.1:8888");
    CHECK_SERIALIZATION("127.0.0.1:111");
    CHECK_SERIALIZATION("123.123.123.123:8888");
    CHECK_SERIALIZATION("127.0.0.1:8888");
}

BOOST_AUTO_TEST_SUITE_END()