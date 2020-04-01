//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE ipv4_endpoint

#include <nil/actor/ipv4_endpoint.hpp>

#include <nil/actor/test/dsl.hpp>

#include <cassert>
#include <vector>

#include <nil/actor/spawner.hpp>
#include <nil/actor/spawner_config.hpp>
#include <nil/actor/binary_deserializer.hpp>
#include <nil/actor/binary_serializer.hpp>
#include <nil/actor/byte.hpp>
#include <nil/actor/byte_buffer.hpp>
#include <nil/actor/detail/parse.hpp>
#include <nil/actor/ipv4_address.hpp>
#include <nil/actor/span.hpp>

using namespace nil::actor;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<template<typename...> class P, typename... T>
            struct print_log_value<P<T...>> {
                void operator()(std::ostream &, P<T...> const &) {
                }
            };

            template<template<typename, std::size_t> class P, typename T, std::size_t S>
            struct print_log_value<P<T, S>> {
                void operator()(std::ostream &, P<T, S> const &) {
                }
            };
            template<>
            struct print_log_value<nil::actor::ipv4_address> {
                void operator()(std::ostream &, nil::actor::ipv4_address const &) {
                }
            };
            template<>
            struct print_log_value<nil::actor::ipv4_endpoint> {
                void operator()(std::ostream &, nil::actor::ipv4_endpoint const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

namespace {

    ipv4_endpoint operator"" _ep(const char *str, size_t size) {
        ipv4_endpoint result;
        if (auto err = detail::parse(string_view {str, size}, result))
            BOOST_FAIL("unable to parse input");
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

#define CHECK_TO_STRING(addr) BOOST_CHECK_EQUAL(addr, to_string(addr##_ep))

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

BOOST_AUTO_TEST_CASE(to_string_test) {
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
