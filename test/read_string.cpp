//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE detail.parser.read_string

#include <nil/actor/detail/parser/read_string.hpp>

#include <boost/test/unit_test.hpp>

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

    struct string_parser_consumer {
        std::string x;
        inline void value(std::string y) {
            x = std::move(y);
        }
    };

    using res_t = variant<pec, std::string>;

    struct string_parser {
        res_t operator()(string_view str) {
            string_parser_consumer f;
            string_parser_state res {str.begin(), str.end()};
            detail::parser::read_string(res, f);
            if (res.code == pec::success)
                return f.x;
            return res.code;
        }
    };

    struct fixture {
        string_parser p;
    };

    // TODO: remove and use "..."s from the STL when switching to C++14
    std::string operator"" _s(const char *str, size_t str_len) {
        std::string result;
        result.assign(str, str_len);
        return result;
    }

}    // namespace

BOOST_FIXTURE_TEST_SUITE(read_string_tests, fixture)

BOOST_AUTO_TEST_CASE(empty_string) {
    BOOST_CHECK_EQUAL(p(R"("")"), ""_s);
    BOOST_CHECK_EQUAL(p(R"( "")"), ""_s);
    BOOST_CHECK_EQUAL(p(R"(  "")"), ""_s);
    BOOST_CHECK_EQUAL(p(R"("" )"), ""_s);
    BOOST_CHECK_EQUAL(p(R"(""  )"), ""_s);
    BOOST_CHECK_EQUAL(p(R"(  ""  )"), ""_s);
    BOOST_CHECK_EQUAL(p("\t \"\" \t\t\t "), ""_s);
}

BOOST_AUTO_TEST_CASE(non_empty_quoted_string) {
    BOOST_CHECK_EQUAL(p(R"("abc")"), "abc"_s);
    BOOST_CHECK_EQUAL(p(R"("a b c")"), "a b c"_s);
    BOOST_CHECK_EQUAL(p(R"(   "abcdefABCDEF"   )"), "abcdefABCDEF"_s);
}

BOOST_AUTO_TEST_CASE(quoted_string_with_escaped_characters) {
    BOOST_CHECK_EQUAL(p(R"("a\tb\tc")"), "a\tb\tc"_s);
    BOOST_CHECK_EQUAL(p(R"("a\nb\r\nc")"), "a\nb\r\nc"_s);
    BOOST_CHECK_EQUAL(p(R"("a\\b")"), "a\\b"_s);
}

BOOST_AUTO_TEST_CASE(unquoted_strings) {
    BOOST_CHECK_EQUAL(p(R"(foo)"), "foo"_s);
    BOOST_CHECK_EQUAL(p(R"( foo )"), "foo"_s);
    BOOST_CHECK_EQUAL(p(R"( 123 )"), "123"_s);
}

BOOST_AUTO_TEST_CASE(invalid_strings) {
    BOOST_CHECK_EQUAL(p(R"("abc)"), pec::unexpected_eof);
    BOOST_CHECK_EQUAL(p("\"ab\nc\""), pec::unexpected_newline);
    BOOST_CHECK_EQUAL(p(R"("abc" def)"), pec::trailing_character);
    BOOST_CHECK_EQUAL(p(R"( 123, )"), pec::trailing_character);
}

BOOST_AUTO_TEST_SUITE_END()
