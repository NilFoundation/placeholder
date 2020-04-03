//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE detail.parser.read_floating_point

#include <nil/actor/detail/parser/read_floating_point.hpp>

#include <nil/actor/test/dsl.hpp>

#include <string>

#include <nil/actor/parser_state.hpp>
#include <nil/actor/string_view.hpp>
#include <nil/actor/variant.hpp>

using namespace nil::actor;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<template<typename...> class P, typename... T>
            struct print_log_value<P<T...>> {
                void operator()(std::ostream &, P<T...> const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

namespace {

    struct double_consumer {
        using value_type = double;

        void value(double y) {
            x = y;
        }

        double x;
    };

    optional<double> read(string_view str) {
        double_consumer consumer;
        string_parser_state ps {str.begin(), str.end()};
        detail::parser::read_floating_point(ps, consumer);
        if (ps.code != pec::success)
            return none;
        return consumer.x;
    }

}    // namespace

BOOST_AUTO_TEST_CASE(predecimal_only) {
    BOOST_CHECK_EQUAL(read("0"), 0.);
    BOOST_CHECK_EQUAL(read("+0"), 0.);
    BOOST_CHECK_EQUAL(read("-0"), 0.);
    BOOST_CHECK_EQUAL(read("1"), 1.);
    BOOST_CHECK_EQUAL(read("+1"), 1.);
    BOOST_CHECK_EQUAL(read("-1"), -1.);
    BOOST_CHECK_EQUAL(read("12"), 12.);
    BOOST_CHECK_EQUAL(read("+12"), 12.);
    BOOST_CHECK_EQUAL(read("-12"), -12.);
}

BOOST_AUTO_TEST_CASE(trailing_dot) {
    BOOST_CHECK_EQUAL(read("0."), 0.);
    BOOST_CHECK_EQUAL(read("1."), 1.);
    BOOST_CHECK_EQUAL(read("+1."), 1.);
    BOOST_CHECK_EQUAL(read("-1."), -1.);
    BOOST_CHECK_EQUAL(read("12."), 12.);
    BOOST_CHECK_EQUAL(read("+12."), 12.);
    BOOST_CHECK_EQUAL(read("-12."), -12.);
}

BOOST_AUTO_TEST_CASE(leading_dot) {
    BOOST_CHECK_EQUAL(read(".0"), .0);
    BOOST_CHECK_EQUAL(read(".1"), .1);
    BOOST_CHECK_EQUAL(read("+.1"), .1);
    BOOST_CHECK_EQUAL(read("-.1"), -.1);
    BOOST_CHECK_EQUAL(read(".12"), .12);
    BOOST_CHECK_EQUAL(read("+.12"), .12);
    BOOST_CHECK_EQUAL(read("-.12"), -.12);
}

BOOST_AUTO_TEST_CASE(regular_noation) {
    BOOST_CHECK_EQUAL(read("0.0"), .0);
    BOOST_CHECK_EQUAL(read("1.2"), 1.2);
    BOOST_CHECK_EQUAL(read("1.23"), 1.23);
    BOOST_CHECK_EQUAL(read("12.34"), 12.34);
}

BOOST_AUTO_TEST_CASE(scientific_noation) {
    BOOST_CHECK_EQUAL(read("1e2"), 1e2);
    BOOST_CHECK_EQUAL(read("+1e2"), 1e2);
    BOOST_CHECK_EQUAL(read("+1e+2"), 1e2);
    BOOST_CHECK_EQUAL(read("-1e2"), -1e2);
    BOOST_CHECK_EQUAL(read("-1e+2"), -1e2);
    BOOST_CHECK_EQUAL(read("12e-3"), 12e-3);
    BOOST_CHECK_EQUAL(read("+12e-3"), 12e-3);
    BOOST_CHECK_EQUAL(read("-12e-3"), -12e-3);
}
