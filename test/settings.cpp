//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE settings

#include <nil/actor/settings.hpp>

#include "core_test.hpp"

#include <string>

#include <nil/actor/none.hpp>
#include <nil/actor/optional.hpp>

using namespace std::string_literals;

using namespace nil::actor;

namespace {

    struct fixture {
        settings x;

        void fill() {
            x["hello"] = "world";
            x["one"].as_dictionary()["two"].as_dictionary()["three"] = 4;
            auto &logger = x["logger"].as_dictionary();
            logger["component-blacklist"] = make_config_value_list("caf");
            logger["console"] = "none";
            logger["console-format"] = "%m";
            logger["console-verbosity"] = "trace";
            logger["file-format"] = "%r %c %p %a %t %C %M %F:%L %m%n";
            logger["inline-output"] = false;
            auto &middleman = x["middleman"].as_dictionary();
            middleman["app-identifiers"] = make_config_value_list("generic-caf-app");
            middleman["enable-automatic-connections"] = false;
            middleman["heartbeat-interval"] = 0;
            middleman["max-consecutive-reads"] = 50;
            middleman["workers"] = 3;
            auto &stream = x["stream"].as_dictionary();
            stream["credit-round-interval"] = timespan {10000000};    // 10ms;
            stream["desired-batch-complexity"] = timespan {50000};    // 50us;
            stream["max-batch-delay"] = timespan {5000000};           // 5ms;
        }
    };

    const config_value &unpack(const settings &x, string_view key) {
        auto i = x.find(key);
        if (i == x.end())
            BOOST_FAIL("key not found in dictionary: " << key);
        return i->second;
    }

    template<class... Ts>
    const config_value &unpack(const settings &x, string_view key, const char *next_key, Ts... keys) {
        auto i = x.find(key);
        if (i == x.end())
            BOOST_FAIL("key not found in dictionary: " << key);
        if (!holds_alternative<settings>(i->second))
            BOOST_FAIL("value is not a dictionary: " << key);
        return unpack(get<settings>(i->second), {next_key, strlen(next_key)}, keys...);
    }

    struct foobar {
        int foo = 0;
        int bar = 0;
    };

}    // namespace

namespace nil {
    namespace actor {

        // Enable users to configure foobar's like this:
        // my-value {
        //   foo = 42
        //   bar = 23
        // }
        template<>
        struct config_value_access<foobar> {
            static bool is(const config_value &x) {
                auto dict = nil::actor::get_if<config_value::dictionary>(&x);
                if (dict != nullptr) {
                    return nil::actor::get_if<int>(dict, "foo") != none && nil::actor::get_if<int>(dict, "bar") != none;
                }
                return false;
            }

            static optional<foobar> get_if(const config_value *x) {
                foobar result;
                if (!is(*x))
                    return none;
                const auto &dict = nil::actor::get<config_value::dictionary>(*x);
                result.foo = nil::actor::get<int>(dict, "foo");
                result.bar = nil::actor::get<int>(dict, "bar");
                return result;
            }

            static foobar get(const config_value &x) {
                auto result = get_if(&x);
                if (!result)
                    ACTOR_RAISE_ERROR("invalid type found");
                return std::move(*result);
            }
        };

    }    // namespace actor
}    // namespace nil

BOOST_FIXTURE_TEST_SUITE(settings_tests, fixture)

BOOST_AUTO_TEST_CASE(put_test) {
    put(x, "foo", "bar");
    put(x, "logger.console", "none");
    put(x, "one.two.three", "four");
    BOOST_CHECK_EQUAL(x.size(), 3u);
    BOOST_CHECK(x.contains("foo"));
    BOOST_CHECK(x.contains("logger"));
    BOOST_CHECK(x.contains("one"));
    BOOST_CHECK_EQUAL(get<std::string>(unpack(x, "foo")), "bar"s);
    BOOST_CHECK_EQUAL(get<std::string>(unpack(x, "logger", "console")), "none"s);
    BOOST_CHECK_EQUAL(get<std::string>(unpack(x, "one", "two", "three")), "four"s);
    put(x, "logger.console", "trace");
    BOOST_CHECK_EQUAL(get<std::string>(unpack(x, "logger", "console")), "trace"s);
}

BOOST_AUTO_TEST_CASE(put_missing_test) {
    put_missing(x, "foo", "bar");
    put_missing(x, "logger.console", "none");
    put_missing(x, "one.two.three", "four");
    BOOST_CHECK_EQUAL(x.size(), 3u);
    BOOST_CHECK(x.contains("foo"));
    BOOST_CHECK(x.contains("logger"));
    BOOST_CHECK(x.contains("one"));
    BOOST_CHECK_EQUAL(get<std::string>(unpack(x, "foo")), "bar"s);
    BOOST_CHECK_EQUAL(get<std::string>(unpack(x, "logger", "console")), "none"s);
    BOOST_CHECK_EQUAL(get<std::string>(unpack(x, "one", "two", "three")), "four"s);
    put_missing(x, "logger.console", "trace");
    BOOST_CHECK_EQUAL(get<std::string>(unpack(x, "logger", "console")), "none"s);
}

BOOST_AUTO_TEST_CASE(put_list_test) {
    put_list(x, "integers").emplace_back(42);
    BOOST_CHECK(x.contains("integers"));
    BOOST_CHECK_EQUAL(unpack(x, "integers"), make_config_value_list(42));
    put_list(x, "foo.bar").emplace_back("str");
    BOOST_CHECK_EQUAL(unpack(x, "foo", "bar"), make_config_value_list("str"));
    put_list(x, "one.two.three").emplace_back(4);
    BOOST_CHECK_EQUAL(unpack(x, "one", "two", "three"), make_config_value_list(4));
}

BOOST_AUTO_TEST_CASE(put_dictionary_test) {
    put_dictionary(x, "logger").emplace("console", "none");
    BOOST_CHECK(x.contains("logger"));
    BOOST_CHECK_EQUAL(get<std::string>(unpack(x, "logger", "console")), "none"s);
    put_dictionary(x, "foo.bar").emplace("value", 42);
    BOOST_CHECK_EQUAL(get<int>(unpack(x, "foo", "bar", "value")), 42);
    put_dictionary(x, "one.two.three").emplace("four", "five");
    BOOST_CHECK_EQUAL(get<std::string>(unpack(x, "one", "two", "three", "four")), "five"s);
}

BOOST_AUTO_TEST_CASE(get_and_get_if_test) {
    fill();
    BOOST_CHECK(get_if(&x, "hello") != nullptr);
    BOOST_CHECK(get<std::string>(x, "hello") == "world"s);
    BOOST_CHECK(get_if(&x, "logger.console") != nullptr);
    BOOST_CHECK(get_if<std::string>(&x, "logger.console") != nullptr);
    BOOST_CHECK(get<std::string>(x, "logger.console") == "none"s);
    BOOST_CHECK(get_if(&x, "one.two.three") != nullptr);
    BOOST_CHECK(get_if<std::string>(&x, "one.two.three") == nullptr);
    BOOST_REQUIRE(get_if<int>(&x, "one.two.three") != none);
    BOOST_CHECK(get<int>(x, "one.two.three") == 4);
}

BOOST_AUTO_TEST_CASE(get_or_test) {
    fill();
    BOOST_CHECK_EQUAL(get_or(x, "hello", "nobody"), "world"s);
    BOOST_CHECK_EQUAL(get_or(x, "goodbye", "nobody"), "nobody"s);
}

BOOST_AUTO_TEST_CASE(custom_type) {
    put(x, "my-value.foo", 42);
    put(x, "my-value.bar", 24);
    BOOST_REQUIRE(holds_alternative<foobar>(x, "my-value"));
    BOOST_REQUIRE(get_if<foobar>(&x, "my-value") != nil::actor::none);
    auto fb = get<foobar>(x, "my-value");
    BOOST_CHECK_EQUAL(fb.foo, 42);
    BOOST_CHECK_EQUAL(fb.bar, 24);
}

BOOST_AUTO_TEST_SUITE_END()
