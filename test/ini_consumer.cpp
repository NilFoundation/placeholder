//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE detail.ini_consumer

#include <nil/actor/detail/ini_consumer.hpp>

#include <nil/actor/test/dsl.hpp>

#include <nil/actor/detail/parser/read_ini.hpp>

using std::string;

using namespace nil::actor;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<>
            struct print_log_value<nil::actor::pec> {
                void operator()(std::ostream &, nil::actor::pec const &) {
                }
            };

            template<template<typename, typename> class P, typename K, typename V>
            struct print_log_value<P<K, V>> {
                void operator()(std::ostream &, P<K, V> const &) {
                }
            };

            template<template<typename> class V, typename T>
            struct print_log_value<V<T>> {
                void operator()(std::ostream &, V<T> const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

// List-of-strings.
using ls = std::vector<std::string>;

namespace {

    constexpr const string_view test_ini = R"(
is_server=true
port=4242
nodes=["sun", "venus", ]
[logger]
file-name = "foobar.ini" ; our file name
[scheduler] ; more settings
  timing  =  2us ; using microsecond resolution
)";

    constexpr const string_view test_ini2 = R"(
is_server = true
logger = {
  file-name = "foobar.ini"
}
port = 4242
scheduler = {
  timing = 2us,
}
nodes = ["sun", "venus"]
)";

    struct fixture {
        config_option_set options;
        settings config;

        fixture() {
            options.add<bool>("global", "is_server", "enables server mode")
                .add<uint16_t>("global", "port", "sets local or remote port")
                .add<ls>("global", "nodes", "list of remote nodes")
                .add<string>("logger", "file-name", "log output file")
                .add<int>("scheduler", "padding", "some integer")
                .add<timespan>("scheduler", "timing", "some timespan");
        }
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(ini_consumer_tests, fixture)

BOOST_AUTO_TEST_CASE(ini_value_consumer) {
    string_view str = R"("hello world")";
    detail::ini_value_consumer consumer;
    string_parser_state res {str.begin(), str.end()};
    detail::parser::read_ini_value(res, consumer);
    BOOST_CHECK_EQUAL(res.code, pec::success);
    BOOST_CHECK_EQUAL(get<string>(consumer.result), "hello world");
}

BOOST_AUTO_TEST_CASE(ini_consumer) {
    string_view str = test_ini;
    detail::ini_consumer consumer {options, config};
    string_parser_state res {str.begin(), str.end()};
    detail::parser::read_ini(res, consumer);
    BOOST_CHECK_EQUAL(res.code, pec::success);
    BOOST_CHECK_EQUAL(get<bool>(config, "is_server"), true);
    BOOST_CHECK_EQUAL(get<uint16_t>(config, "port"), 4242u);
    BOOST_CHECK_EQUAL(get<ls>(config, "nodes"), ls({"sun", "venus"}));
    BOOST_CHECK_EQUAL(get<string>(config, "logger.file-name"), "foobar.ini");
    BOOST_TEST_MESSAGE(config);
    BOOST_CHECK_EQUAL(get<timespan>(config, "scheduler.timing"), timespan(2000));
}

BOOST_AUTO_TEST_CASE(simplified_syntax) {
    BOOST_TEST_MESSAGE("read test_ini");
    {
        detail::ini_consumer consumer {options, config};
        string_parser_state res {test_ini.begin(), test_ini.end()};
        detail::parser::read_ini(res, consumer);
        BOOST_CHECK_EQUAL(res.code, pec::success);
    }
    settings config2;
    BOOST_TEST_MESSAGE("read test_ini2");
    {
        detail::ini_consumer consumer {options, config2};
        string_parser_state res {test_ini2.begin(), test_ini2.end()};
        detail::parser::read_ini(res, consumer);
        BOOST_CHECK_EQUAL(res.code, pec::success);
    }
    BOOST_CHECK_EQUAL(config, config2);
}

BOOST_AUTO_TEST_SUITE_END()
