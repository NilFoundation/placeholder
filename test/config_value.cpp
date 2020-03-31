//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE config_value

#include "core_test.hpp"

#include <list>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <nil/actor/spawner.hpp>
#include <nil/actor/spawner_config.hpp>
#include <nil/actor/detail/bounds_checker.hpp>
#include <nil/actor/none.hpp>
#include <nil/actor/pec.hpp>
#include <nil/actor/string_view.hpp>
#include <nil/actor/variant.hpp>

using std::string;

using namespace nil::actor;

using namespace std::string_literals;

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
            struct print_log_value<none_t> {
                void operator()(std::ostream &, none_t const &) {
                }
            };
            template<>
            struct print_log_value<error> {
                void operator()(std::ostream &, error const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

namespace {

    using list = config_value::list;

    using dictionary = config_value::dictionary;

    struct dictionary_builder {
        dictionary dict;

        template<class T>
        dictionary_builder &&add(string_view key, T &&value) && {
            dict.emplace(key, config_value {std::forward<T>(value)});
            return std::move(*this);
        }

        dictionary make() && {
            return std::move(dict);
        }

        config_value make_cv() && {
            return config_value {std::move(dict)};
        }
    };

    dictionary_builder dict() {
        return {};
    }

    template<class... Ts>
    config_value cfg_lst(Ts &&... xs) {
        config_value::list lst {config_value {std::forward<Ts>(xs)}...};
        return config_value {std::move(lst)};
    }

}    // namespace

BOOST_AUTO_TEST_CASE(default_constructed) {
    config_value x;
    BOOST_CHECK_EQUAL(holds_alternative<int64_t>(x), true);
    BOOST_CHECK_EQUAL(get<int64_t>(x), 0);
    BOOST_CHECK_EQUAL(x.type_name(), "integer"s);
}

BOOST_AUTO_TEST_CASE(positive_integer) {
    config_value x {4200};
    BOOST_CHECK_EQUAL(holds_alternative<int64_t>(x), true);
    BOOST_CHECK_EQUAL(get<int64_t>(x), 4200);
    BOOST_CHECK(get_if<int64_t>(&x) != nullptr);
    BOOST_CHECK_EQUAL(holds_alternative<uint64_t>(x), true);
    BOOST_CHECK_EQUAL(get<uint64_t>(x), 4200u);
    BOOST_CHECK_EQUAL(get_if<uint64_t>(&x), uint64_t {4200});
    BOOST_CHECK_EQUAL(holds_alternative<int>(x), true);
    BOOST_CHECK_EQUAL(get<int>(x), 4200);
    BOOST_CHECK_EQUAL(get_if<int>(&x), 4200);
    BOOST_CHECK_EQUAL(holds_alternative<int16_t>(x), true);
    BOOST_CHECK_EQUAL(get<int16_t>(x), 4200);
    BOOST_CHECK_EQUAL(get_if<int16_t>(&x), int16_t {4200});
    BOOST_CHECK_EQUAL(holds_alternative<int8_t>(x), false);
    BOOST_CHECK_EQUAL(get_if<int8_t>(&x), nil::actor::none);
}

BOOST_AUTO_TEST_CASE(negative_integer) {
    config_value x {-1};
    BOOST_CHECK_EQUAL(holds_alternative<int64_t>(x), true);
    BOOST_CHECK_EQUAL(get<int64_t>(x), -1);
    BOOST_CHECK(get_if<int64_t>(&x) != nullptr);
    BOOST_CHECK_EQUAL(holds_alternative<uint64_t>(x), false);
    BOOST_CHECK_EQUAL(get_if<uint64_t>(&x), none);
    BOOST_CHECK_EQUAL(holds_alternative<int>(x), true);
    BOOST_CHECK_EQUAL(get<int>(x), -1);
    BOOST_CHECK_EQUAL(get_if<int>(&x), -1);
    BOOST_CHECK_EQUAL(holds_alternative<int16_t>(x), true);
    BOOST_CHECK_EQUAL(get<int16_t>(x), -1);
    BOOST_CHECK_EQUAL(get_if<int16_t>(&x), int16_t {-1});
    BOOST_CHECK_EQUAL(holds_alternative<int8_t>(x), true);
    BOOST_CHECK_EQUAL(get_if<int8_t>(&x), int8_t {-1});
    BOOST_CHECK_EQUAL(holds_alternative<uint8_t>(x), false);
    BOOST_CHECK_EQUAL(get_if<uint8_t>(&x), none);
}

BOOST_AUTO_TEST_CASE(timespan_test) {
    timespan ns500 {500};
    config_value x {ns500};
    BOOST_CHECK_EQUAL(holds_alternative<timespan>(x), true);
    BOOST_CHECK_EQUAL(get<timespan>(x), ns500);
    BOOST_CHECK_NE(get_if<timespan>(&x), nullptr);
}

BOOST_AUTO_TEST_CASE(homogeneous_list) {
    using integer_list = std::vector<int64_t>;
    auto xs = make_config_value_list(1, 2, 3);
    auto ys = config_value {integer_list {1, 2, 3}};
    BOOST_CHECK_EQUAL(xs, ys);
    BOOST_CHECK_EQUAL(to_string(xs), "[1, 2, 3]");
    BOOST_CHECK_EQUAL(xs.type_name(), "list"s);
    BOOST_CHECK_EQUAL(holds_alternative<config_value::list>(xs), true);
    BOOST_CHECK_EQUAL(holds_alternative<integer_list>(xs), true);
    BOOST_CHECK_EQUAL(get<integer_list>(xs), integer_list({1, 2, 3}));
}

BOOST_AUTO_TEST_CASE(heterogeneous_list) {
    auto xs_value = make_config_value_list(1, "two", 3.0);
    auto &xs = xs_value.as_list();
    BOOST_CHECK_EQUAL(xs_value.type_name(), "list"s);
    BOOST_REQUIRE_EQUAL(xs.size(), 3u);
    BOOST_CHECK_EQUAL(get<int>(xs[0]), 1);
    BOOST_CHECK_EQUAL(get<std::string>(xs[1]), "two"s);
    BOOST_CHECK_EQUAL(get<float>(xs[2]), 3.0);
}

BOOST_AUTO_TEST_CASE(convert_to_list) {
    config_value x {int64_t {42}};
    BOOST_CHECK_EQUAL(x.type_name(), "integer"s);
    BOOST_CHECK_EQUAL(to_string(x), "42");
    x.convert_to_list();
    BOOST_CHECK_EQUAL(x.type_name(), "list"s);
    BOOST_CHECK_EQUAL(to_string(x), "[42]");
    x.convert_to_list();
    BOOST_CHECK_EQUAL(to_string(x), "[42]");
}

BOOST_AUTO_TEST_CASE(append_test) {
    config_value x {int64_t {1}};
    BOOST_CHECK_EQUAL(to_string(x), "1");
    x.append(config_value {int64_t {2}});
    BOOST_CHECK_EQUAL(to_string(x), "[1, 2]");
    x.append(config_value {"foo"});
    BOOST_CHECK_EQUAL(to_string(x), R"__([1, 2, "foo"])__");
}

BOOST_AUTO_TEST_CASE(homogeneous_dictionary) {
    using integer_map = nil::actor::dictionary<int64_t>;
    auto xs = dict()
                  .add("value-1", config_value {100000})
                  .add("value-2", config_value {2})
                  .add("value-3", config_value {3})
                  .add("value-4", config_value {4})
                  .make();
    integer_map ys {
        {"value-1", 100000},
        {"value-2", 2},
        {"value-3", 3},
        {"value-4", 4},
    };
    config_value xs_cv {xs};
    if (auto val = get_if<int64_t>(&xs, "value-1"))
        BOOST_CHECK_EQUAL(*val, int64_t {100000});
    else
        BOOST_FAIL("value-1 not an int64_t");
    BOOST_CHECK_EQUAL(get_if<int32_t>(&xs, "value-1"), int32_t {100000});
    BOOST_CHECK_EQUAL(get_if<int16_t>(&xs, "value-1"), none);
    BOOST_CHECK_EQUAL(get<int64_t>(xs, "value-1"), 100000);
    BOOST_CHECK_EQUAL(get<int32_t>(xs, "value-1"), 100000);
    BOOST_CHECK_EQUAL(get_if<integer_map>(&xs_cv), ys);
    BOOST_CHECK_EQUAL(get<integer_map>(xs_cv), ys);
}

BOOST_AUTO_TEST_CASE(heterogeneous_dictionary) {
    using string_list = std::vector<string>;
    auto xs = dict()
                  .add("scheduler",
                       dict().add("policy", config_value {"none"}).add("max-threads", config_value {2}).make_cv())
                  .add("nodes", dict().add("preload", cfg_lst("sun", "venus", "mercury", "earth", "mars")).make_cv())

                  .make();
    BOOST_CHECK_EQUAL(get<string>(xs, "scheduler.policy"), "none");
    BOOST_CHECK_EQUAL(get<int64_t>(xs, "scheduler.max-threads"), 2);
    BOOST_CHECK_EQUAL(get_if<double>(&xs, "scheduler.max-threads"), nullptr);
    string_list nodes {"sun", "venus", "mercury", "earth", "mars"};
    BOOST_CHECK_EQUAL(get<string_list>(xs, "nodes.preload"), nodes);
}

BOOST_AUTO_TEST_CASE(successful_parsing) {
    // Store the parsed value on the stack, because the unit test framework takes
    // references when comparing values. Since we call get<T>() on the result of
    // parse(), we would end up with a reference to a temporary.
    config_value parsed;
    auto parse = [&](const string &str) -> config_value & {
        auto x = config_value::parse(str);
        if (!x)
            BOOST_FAIL("cannot parse " << str << ": assumed a result but error " << to_string(x.error()));
        parsed = std::move(*x);
        return parsed;
    };
    using di = nil::actor::dictionary<int>;    // Dictionary-of-integers.
    using ls = std::vector<string>;            // List-of-strings.
    using li = std::vector<int>;               // List-of-integers.
    using lli = std::vector<li>;               // List-of-list-of-integers.
    using std::chrono::milliseconds;
    BOOST_CHECK_EQUAL(get<int64_t>(parse("123")), 123);
    BOOST_CHECK_EQUAL(get<int64_t>(parse("+123")), 123);
    BOOST_CHECK_EQUAL(get<int64_t>(parse("-1")), -1);
    BOOST_CHECK_EQUAL(get<double>(parse("1.")), 1.);
    BOOST_CHECK_EQUAL(get<string>(parse("\"abc\"")), "abc");
    BOOST_CHECK_EQUAL(get<string>(parse("abc")), "abc");
    BOOST_CHECK_EQUAL(get<li>(parse("[1, 2, 3]")), li({1, 2, 3}));
    BOOST_CHECK_EQUAL(get<ls>(parse("[\"abc\", \"def\", \"ghi\"]")), ls({"abc", "def", "ghi"}));
    BOOST_CHECK_EQUAL(get<lli>(parse("[[1, 2], [3]]")), lli({li {1, 2}, li {3}}));
    BOOST_CHECK_EQUAL(get<timespan>(parse("10ms")), milliseconds(10));
    BOOST_CHECK_EQUAL(get<di>(parse("{a=1,b=2}")), di({{"a", 1}, {"b", 2}}));
}

BOOST_AUTO_TEST_CASE(unsuccessful_parsing) {
    auto parse = [](const string &str) {
        auto x = config_value::parse(str);
        if (x)
            BOOST_FAIL("assumed an error but got a result");
        return std::move(x.error());
    };
    BOOST_CHECK_EQUAL(parse("10msb"), pec::trailing_character);
    BOOST_CHECK_EQUAL(parse("10foo"), pec::trailing_character);
    BOOST_CHECK_EQUAL(parse("[1,"), pec::unexpected_eof);
    BOOST_CHECK_EQUAL(parse("{a=,"), pec::unexpected_character);
    BOOST_CHECK_EQUAL(parse("{a=1,"), pec::unexpected_eof);
    BOOST_CHECK_EQUAL(parse("{a=1 b=2}"), pec::unexpected_character);
}

BOOST_AUTO_TEST_CASE(conversion_to_simple_tuple) {
    using tuple_type = std::tuple<size_t, std::string>;
    config_value x {42};
    x.as_list().emplace_back("hello world");
    BOOST_REQUIRE(holds_alternative<tuple_type>(x));
    BOOST_REQUIRE_NE(get_if<tuple_type>(&x), none);
    BOOST_CHECK_EQUAL(get<tuple_type>(x), std::make_tuple(size_t {42}, "hello world"s));
}

BOOST_AUTO_TEST_CASE(conversion_to_nested_tuple) {
    using inner_tuple_type = std::tuple<int, int>;
    using tuple_type = std::tuple<size_t, inner_tuple_type>;
    config_value x {42};
    x.as_list().emplace_back(make_config_value_list(2, 40));
    BOOST_REQUIRE(holds_alternative<tuple_type>(x));
    BOOST_REQUIRE_NE(get_if<tuple_type>(&x), none);
    BOOST_CHECK_EQUAL(get<tuple_type>(x), std::make_tuple(size_t {42}, std::make_tuple(2, 40)));
}

BOOST_AUTO_TEST_CASE(conversion_to_std_vector) {
    using list_type = std::vector<int>;
    auto xs = make_config_value_list(1, 2, 3, 4);
    BOOST_CHECK(holds_alternative<list_type>(xs));
    auto ys = get_if<list_type>(&xs);
    BOOST_REQUIRE(ys);
    BOOST_CHECK_EQUAL(*ys, list_type({1, 2, 3, 4}));
}

BOOST_AUTO_TEST_CASE(conversion_to_std_list) {
    using list_type = std::list<int>;
    auto xs = make_config_value_list(1, 2, 3, 4);
    BOOST_CHECK(holds_alternative<list_type>(xs));
    auto ys = get_if<list_type>(&xs);
    BOOST_REQUIRE(ys);
    BOOST_CHECK_EQUAL(*ys, list_type({1, 2, 3, 4}));
}

BOOST_AUTO_TEST_CASE(conversion_to_std_set) {
    using list_type = std::set<int>;
    auto xs = make_config_value_list(1, 2, 3, 4);
    BOOST_CHECK(holds_alternative<list_type>(xs));
    auto ys = get_if<list_type>(&xs);
    BOOST_REQUIRE(ys);
    BOOST_CHECK_EQUAL(*ys, list_type({1, 2, 3, 4}));
}

BOOST_AUTO_TEST_CASE(conversion_to_std_unordered_set) {
    using list_type = std::unordered_set<int>;
    auto xs = make_config_value_list(1, 2, 3, 4);
    BOOST_CHECK(holds_alternative<list_type>(xs));
    auto ys = get_if<list_type>(&xs);
    BOOST_REQUIRE(ys);
    BOOST_CHECK_EQUAL(*ys, list_type({1, 2, 3, 4}));
}

BOOST_AUTO_TEST_CASE(conversion_to_std_map) {
    using map_type = std::map<std::string, int>;
    auto xs = dict().add("a", 1).add("b", 2).add("c", 3).add("d", 4).make_cv();
    BOOST_CHECK(holds_alternative<map_type>(xs));
    auto ys = get_if<map_type>(&xs);
    BOOST_REQUIRE(ys);
    BOOST_CHECK_EQUAL(*ys, map_type({{"a", 1}, {"b", 2}, {"c", 3}, {"d", 4}}));
}

BOOST_AUTO_TEST_CASE(conversion_to_std_multimap) {
    using map_type = std::multimap<std::string, int>;
    auto xs = dict().add("a", 1).add("b", 2).add("c", 3).add("d", 4).make_cv();
    BOOST_CHECK(holds_alternative<map_type>(xs));
    auto ys = get_if<map_type>(&xs);
    BOOST_REQUIRE(ys);
    BOOST_CHECK_EQUAL(*ys, map_type({{"a", 1}, {"b", 2}, {"c", 3}, {"d", 4}}));
}

BOOST_AUTO_TEST_CASE(conversion_to_std_unordered_map) {
    using map_type = std::unordered_map<std::string, int>;
    auto xs = dict().add("a", 1).add("b", 2).add("c", 3).add("d", 4).make_cv();
    BOOST_CHECK(holds_alternative<map_type>(xs));
    auto ys = get_if<map_type>(&xs);
    BOOST_REQUIRE(ys);
    BOOST_CHECK_EQUAL(*ys, map_type({{"a", 1}, {"b", 2}, {"c", 3}, {"d", 4}}));
}

BOOST_AUTO_TEST_CASE(conversion_to_std_unordered_multimap) {
    using map_type = std::unordered_multimap<std::string, int>;
    auto xs = dict().add("a", 1).add("b", 2).add("c", 3).add("d", 4).make_cv();
    BOOST_CHECK(holds_alternative<map_type>(xs));
    auto ys = get_if<map_type>(&xs);
    BOOST_REQUIRE(ys);
    BOOST_CHECK_EQUAL(*ys, map_type({{"a", 1}, {"b", 2}, {"c", 3}, {"d", 4}}));
}
