//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt or
// http://opensource.org/licenses/BSD-3-Clause
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE ipv6_address_test

#include <initializer_list>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <nil/actor/config.hpp>
#include <nil/actor/test/dsl.hpp>

#include <nil/actor/detail/parse.hpp>

#include <nil/actor/ipv4_address.hpp>
#include <nil/actor/ipv4_endpoint.hpp>
#include <nil/actor/ipv6_address.hpp>
#include <nil/actor/ipv6_endpoint.hpp>

using namespace nil::actor;

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

            template<>
            struct print_log_value<ipv6_address> {
                void operator()(std::ostream &, ipv6_address const &) {
                }
            };

            template<>
            struct print_log_value<ipv6_endpoint> {
                void operator()(std::ostream &, ipv6_endpoint const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

namespace {

    ipv6_endpoint operator"" _ep(const char *str, size_t size) {
        ipv6_endpoint result;
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

BOOST_FIXTURE_TEST_SUITE(comparison_scope, fixture)

BOOST_AUTO_TEST_CASE(constructing_assigning_and_hash_code) {
    const uint16_t port = 8888;
    ipv6_address::array_type bytes {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    auto addr = ipv6_address {bytes};
    ipv6_endpoint ep1(addr, port);
    BOOST_CHECK_EQUAL(ep1.address(), addr);
    BOOST_CHECK_EQUAL(ep1.port(), port);
    ipv6_endpoint ep2;
    ep2.address(addr);
    ep2.port(port);
    BOOST_CHECK_EQUAL(ep2.address(), addr);
    BOOST_CHECK_EQUAL(ep2.port(), port);
    BOOST_CHECK_EQUAL(ep1, ep2);
    BOOST_CHECK_EQUAL(ep1.hash_code(), ep2.hash_code());
}

BOOST_AUTO_TEST_CASE(comparison_to_IPv4) {
    ipv4_endpoint v4 {ipv4_address({127, 0, 0, 1}), 8080};
    ipv6_endpoint v6 {v4.address(), v4.port()};
    BOOST_CHECK_EQUAL(v4, v6);
    BOOST_CHECK_EQUAL(v6, v4);
}

BOOST_AUTO_TEST_CASE(to_string) {
    CHECK_TO_STRING("[::1]:8888");
    CHECK_TO_STRING("[4e::d00:0:ed00:0:1]:1234");
    CHECK_TO_STRING("[::1]:1111");
    CHECK_TO_STRING("[4432::33:1]:8732");
    CHECK_TO_STRING("[::2]:8888");
    CHECK_TO_STRING("[4f::d00:12:ed00:0:1]:1234");
    CHECK_TO_STRING("[4f::1]:2222");
    CHECK_TO_STRING("[4432:8d::33:1]:8732");
    CHECK_TO_STRING("[4e::d00:0:ed00:0:1]:5678");
    CHECK_TO_STRING("[::1]:2221");
    CHECK_TO_STRING("[::1]:2222");
    CHECK_TO_STRING("[4432::33:1]:872");
    CHECK_TO_STRING("[4432::33:1]:999");
}

BOOST_AUTO_TEST_CASE(comparison) {
    CHECK_COMPARISON("[::1]:8888", "[::2]:8888");
    CHECK_COMPARISON("[4e::d00:0:ed00:0:1]:1234", "[4f::d00:12:ed00:0:1]:1234");
    CHECK_COMPARISON("[::1]:1111", "[4f::1]:2222");
    CHECK_COMPARISON("[4432::33:1]:8732", "[4432:8d::33:1]:8732");
    CHECK_COMPARISON("[::1]:1111", "[::1]:8888");
    CHECK_COMPARISON("[4e::d00:0:ed00:0:1]:1234", "[4e::d00:0:ed00:0:1]:5678");
    CHECK_COMPARISON("[::1]:2221", "[::1]:2222");
    CHECK_COMPARISON("[4432::33:1]:872", "[4432::33:1]:999");
}

BOOST_AUTO_TEST_CASE(serialization) {
    CHECK_SERIALIZATION("[::1]:8888");
    CHECK_SERIALIZATION("[4e::d00:0:ed00:0:1]:1234");
    CHECK_SERIALIZATION("[::1]:1111");
    CHECK_SERIALIZATION("[4432::33:1]:8732");
    CHECK_SERIALIZATION("[::2]:8888");
    CHECK_SERIALIZATION("[4f::d00:12:ed00:0:1]:1234");
    CHECK_SERIALIZATION("[4f::1]:2222");
    CHECK_SERIALIZATION("[4432:8d::33:1]:8732");
    CHECK_SERIALIZATION("[4e::d00:0:ed00:0:1]:5678");
    CHECK_SERIALIZATION("[::1]:2221");
    CHECK_SERIALIZATION("[::1]:2222");
    CHECK_SERIALIZATION("[4432::33:1]:872");
    CHECK_SERIALIZATION("[4432::33:1]:999");
}

BOOST_AUTO_TEST_SUITE_END()
