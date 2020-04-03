//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE ipv4_subnet

#include <nil/actor/ipv4_subnet.hpp>

#include <nil/actor/test/dsl.hpp>

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
            struct print_log_value<nil::actor::ipv4_subnet> {
                void operator()(std::ostream &, nil::actor::ipv4_subnet const &) {
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

    const auto addr = make_ipv4_address;

    ipv4_subnet operator/(ipv4_address addr, uint8_t prefix) {
        return {addr, prefix};
    }

}    // namespace

BOOST_AUTO_TEST_CASE(constructing) {
    ipv4_subnet zero {addr(0, 0, 0, 0), 32};
    BOOST_CHECK_EQUAL(zero.network_address(), addr(0, 0, 0, 0));
    BOOST_CHECK_EQUAL(zero.prefix_length(), 32u);
    ipv4_subnet local {addr(127, 0, 0, 0), 8};
    BOOST_CHECK_EQUAL(local.network_address(), addr(127, 0, 0, 0));
    BOOST_CHECK_EQUAL(local.prefix_length(), 8u);
}

BOOST_AUTO_TEST_CASE(equality) {
    auto a = addr(0xff, 0xff, 0xff, 0xff) / 19;
    auto b = addr(0xff, 0xff, 0xff, 0xab) / 19;
    auto net = addr(0xff, 0xff, 0xe0, 0x00);
    BOOST_CHECK_EQUAL(a.network_address(), net);
    BOOST_CHECK_EQUAL(a.network_address(), b.network_address());
    BOOST_CHECK_EQUAL(a.prefix_length(), b.prefix_length());
    BOOST_CHECK_EQUAL(a, b);
}

BOOST_AUTO_TEST_CASE(contains) {
    ipv4_subnet local {addr(127, 0, 0, 0), 8};
    BOOST_CHECK(local.contains(addr(127, 0, 0, 1)));
    BOOST_CHECK(local.contains(addr(127, 1, 2, 3)));
    BOOST_CHECK(local.contains(addr(127, 128, 0, 0) / 9));
    BOOST_CHECK(local.contains(addr(127, 0, 0, 0) / 8));
    BOOST_CHECK(!local.contains(addr(127, 0, 0, 0) / 7));
}

BOOST_AUTO_TEST_CASE(ordering) {
    BOOST_CHECK_EQUAL(addr(192, 168, 168, 0) / 24, addr(192, 168, 168, 0) / 24);
    BOOST_CHECK_NE(addr(192, 168, 168, 0) / 25, addr(192, 168, 168, 0) / 24);
    BOOST_CHECK_LT(addr(192, 168, 167, 0) / 24, addr(192, 168, 168, 0) / 24);
    BOOST_CHECK_LT(addr(192, 168, 168, 0) / 24, addr(192, 168, 168, 0) / 25);
}
