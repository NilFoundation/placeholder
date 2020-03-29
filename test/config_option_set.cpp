//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE config_option_set

#include <map>
#include <string>
#include <vector>

#include <nil/actor/config.hpp>

#include "core-test.hpp"

#include <nil/actor/config_option_set.hpp>
#include <nil/actor/detail/move_if_not_ptr.hpp>
#include <nil/actor/settings.hpp>

using std::string;
using std::vector;

using namespace nil::actor;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<>
            struct print_log_value<nil::actor::pec> {
                void operator()(std::ostream &, nil::actor::pec const &) {
                }
            };
            template<template<typename, typename> class P, typename V, typename A>
            struct print_log_value<P<V, A>> {
                void operator()(std::ostream &, P<V, A> const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

namespace {

    struct fixture {
        config_option_set opts;

        template<class T>
        expected<T> read(std::vector<std::string> args) {
            settings cfg;
            auto res = opts.parse(cfg, std::move(args));
            if (res.first != pec::success)
                return res.first;
            if (auto x = get_if<T>(&cfg, key))
                return detail::move_if_not_ptr(x);
            return sec::invalid_argument;
        }

        std::string key = "value";
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(config_option_set_tests, fixture)

BOOST_AUTO_TEST_CASE(lookup) {
    opts.add<int>("opt1,1", "test option 1")
        .add<float>("test", "opt2,2", "test option 2")
        .add<bool>("test", "flag,fl3", "test flag");
    BOOST_CHECK_EQUAL(opts.size(), 3u);
    BOOST_TEST_MESSAGE("lookup by long name");
    BOOST_CHECK_NE(opts.cli_long_name_lookup("opt1"), nullptr);
    BOOST_CHECK_NE(opts.cli_long_name_lookup("test.opt2"), nullptr);
    BOOST_CHECK_NE(opts.cli_long_name_lookup("test.flag"), nullptr);
    BOOST_TEST_MESSAGE("lookup by short name");
    BOOST_CHECK_NE(opts.cli_short_name_lookup('1'), nullptr);
    BOOST_CHECK_NE(opts.cli_short_name_lookup('2'), nullptr);
    BOOST_CHECK_NE(opts.cli_short_name_lookup('f'), nullptr);
    BOOST_CHECK_NE(opts.cli_short_name_lookup('l'), nullptr);
    BOOST_CHECK_NE(opts.cli_short_name_lookup('3'), nullptr);
}

BOOST_AUTO_TEST_CASE(parse_with_ref_syncing) {
    using ls = vector<string>;        // list of strings
    using ds = dictionary<string>;    // dictionary of strings
    auto foo_i = 0;
    auto foo_f = 0.f;
    auto foo_b = false;
    auto bar_s = string {};
    auto bar_l = ls {};
    auto bar_d = ds {};
    opts.add<int>(foo_i, "foo", "i,i", "")
        .add<float>(foo_f, "foo", "f,f", "")
        .add<bool>(foo_b, "foo", "b,b", "")
        .add<string>(bar_s, "bar", "s,s", "")
        .add<vector<string>>(bar_l, "bar", "l,l", "")
        .add<dictionary<string>>(bar_d, "bar", "d,d", "");
    settings cfg;
    vector<string> args {"-i42", "-f", "1e12", "-shello", "--bar.l=[\"hello\", \"world\"]", "-d", "{a=\"a\",b=\"b\"}",
                         "-b"};
    BOOST_TEST_MESSAGE("parse arguments");
    auto res = opts.parse(cfg, args);
    BOOST_CHECK_EQUAL(res.first, pec::success);
    if (res.second != args.end())
        BOOST_FAIL("parser stopped at: " << *res.second);
    BOOST_TEST_MESSAGE("verify referenced values");
    BOOST_CHECK_EQUAL(foo_i, 42);
    BOOST_CHECK_EQUAL(foo_f, 1e12);
    BOOST_CHECK_EQUAL(foo_b, true);
    BOOST_CHECK_EQUAL(bar_s, "hello");
    BOOST_CHECK_EQUAL(bar_l, ls({"hello", "world"}));
    BOOST_CHECK_EQUAL(bar_d, ds({{"a", "a"}, {"b", "b"}}));
    BOOST_TEST_MESSAGE("verify dictionary content");
    BOOST_CHECK_EQUAL(get<int>(cfg, "foo.i"), 42);
}

BOOST_AUTO_TEST_CASE(string_parameters) {
    opts.add<std::string>("value,v", "some value");
    BOOST_TEST_MESSAGE("test string option with and without quotes");
    BOOST_CHECK_EQUAL(read<std::string>({"--value=\"foo\\tbar\""}), "foo\tbar");
    BOOST_CHECK_EQUAL(read<std::string>({"--value=foobar"}), "foobar");
    BOOST_CHECK_EQUAL(read<std::string>({"-v", "\"foobar\""}), "foobar");
    BOOST_CHECK_EQUAL(read<std::string>({"-v", "foobar"}), "foobar");
    BOOST_CHECK_EQUAL(read<std::string>({"-v\"foobar\""}), "foobar");
    BOOST_CHECK_EQUAL(read<std::string>({"-vfoobar"}), "foobar");
    BOOST_CHECK_EQUAL(read<std::string>({"--value=\"'abc'\""}), "'abc'");
    BOOST_CHECK_EQUAL(read<std::string>({"--value='abc'"}), "'abc'");
    BOOST_CHECK_EQUAL(read<std::string>({"-v", "\"'abc'\""}), "'abc'");
    BOOST_CHECK_EQUAL(read<std::string>({"-v", "'abc'"}), "'abc'");
    BOOST_CHECK_EQUAL(read<std::string>({"-v'abc'"}), "'abc'");
    BOOST_CHECK_EQUAL(read<std::string>({"--value=\"123\""}), "123");
    BOOST_CHECK_EQUAL(read<std::string>({"--value=123"}), "123");
    BOOST_CHECK_EQUAL(read<std::string>({"-v", "\"123\""}), "123");
    BOOST_CHECK_EQUAL(read<std::string>({"-v", "123"}), "123");
    BOOST_CHECK_EQUAL(read<std::string>({"-v123"}), "123");
}

BOOST_AUTO_TEST_CASE(flat_cli_options) {
    key = "foo.bar";
    opts.add<std::string>("?foo", "bar,b", "some value");
    BOOST_CHECK(opts.begin()->has_flat_cli_name());
    BOOST_CHECK_EQUAL(read<std::string>({"-b", "foobar"}), "foobar");
    BOOST_CHECK_EQUAL(read<std::string>({"--bar=foobar"}), "foobar");
    BOOST_CHECK_EQUAL(read<std::string>({"--foo.bar=foobar"}), "foobar");
}

BOOST_AUTO_TEST_CASE(flat_cli_parsing_with_nested_categories) {
    key = "foo.goo.bar";
    opts.add<std::string>("?foo.goo", "bar,b", "some value");
    BOOST_CHECK(opts.begin()->has_flat_cli_name());
    BOOST_CHECK_EQUAL(read<std::string>({"-b", "foobar"}), "foobar");
    BOOST_CHECK_EQUAL(read<std::string>({"--bar=foobar"}), "foobar");
    BOOST_CHECK_EQUAL(read<std::string>({"--foo.goo.bar=foobar"}), "foobar");
}

BOOST_AUTO_TEST_SUITE_END()
