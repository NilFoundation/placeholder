//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE detail.parser.read_bool

#include <nil/actor/detail/parser/read_bool.hpp>

#include <boost/test/unit_test.hpp>

#include <string>

#include <nil/actor/parser_state.hpp>
#include <nil/actor/pec.hpp>
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
            template<>
            struct print_log_value<pec> {
                void operator()(std::ostream &, pec const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

namespace {

    struct bool_parser_consumer {
        bool x;
        inline void value(bool y) {
            x = y;
        }
    };

    using res_t = variant<pec, bool>;

    struct bool_parser {
        res_t operator()(string_view str) {
            bool_parser_consumer f;
            string_parser_state res {str.begin(), str.end()};
            detail::parser::read_bool(res, f);
            if (res.code == pec::success)
                return f.x;
            return res.code;
        }
    };

    struct fixture {
        bool_parser p;
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(read_bool_tests, fixture)

BOOST_AUTO_TEST_CASE(valid_booleans) {
    BOOST_CHECK_EQUAL(get<bool>(p("true")), true);
    BOOST_CHECK_EQUAL(get<bool>(p("false")), false);
}

BOOST_AUTO_TEST_CASE(invalid_booleans) {
    BOOST_CHECK_EQUAL(get<pec>(p("")), pec::unexpected_eof);
    BOOST_CHECK_EQUAL(get<pec>(p("t")), pec::unexpected_eof);
    BOOST_CHECK_EQUAL(get<pec>(p("tr")), pec::unexpected_eof);
    BOOST_CHECK_EQUAL(get<pec>(p("tru")), pec::unexpected_eof);
    BOOST_CHECK_EQUAL(get<pec>(p(" true")), pec::unexpected_character);
    BOOST_CHECK_EQUAL(get<pec>(p("f")), pec::unexpected_eof);
    BOOST_CHECK_EQUAL(get<pec>(p("fa")), pec::unexpected_eof);
    BOOST_CHECK_EQUAL(get<pec>(p("fal")), pec::unexpected_eof);
    BOOST_CHECK_EQUAL(get<pec>(p("fals")), pec::unexpected_eof);
    BOOST_CHECK_EQUAL(get<pec>(p(" false")), pec::unexpected_character);
    BOOST_CHECK_EQUAL(get<pec>(p("tr\nue")), pec::unexpected_newline);
    BOOST_CHECK_EQUAL(get<pec>(p("trues")), pec::trailing_character);
}

BOOST_AUTO_TEST_SUITE_END()
