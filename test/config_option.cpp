//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE config_option

#include <nil/actor/config_option.hpp>

#include "core-test.hpp"

#include <nil/actor/make_config_option.hpp>
#include <nil/actor/config_value.hpp>
#include <nil/actor/expected.hpp>

using namespace nil::actor;

using std::string;

namespace {

    constexpr string_view category = "category";
    constexpr string_view name = "name";
    constexpr string_view explanation = "explanation";

    template<class T>
    constexpr int64_t overflow() {
        return static_cast<int64_t>(std::numeric_limits<T>::max()) + 1;
    }

    template<class T>
    constexpr int64_t underflow() {
        return static_cast<int64_t>(std::numeric_limits<T>::min()) - 1;
    }

    template<class T>
    optional<T> read(string_view arg) {
        auto co = make_config_option<T>(category, name, explanation);
        auto res = co.parse(arg);
        if (res && holds_alternative<T>(*res)) {
            if (co.check(*res) != none)
                BOOST_ERROR("co.parse() produced the wrong type!");
            return get<T>(*res);
        }
        return none;
    }

    // Unsigned integers.
    template<class T>
    void check_integer_options(std::true_type) {
        using std::to_string;
        // Run tests for positive integers.
        T xzero = 0;
        T xmax = std::numeric_limits<T>::max();
        BOOST_CHECK_EQUAL(read<T>(to_string(xzero)), xzero);
        BOOST_CHECK_EQUAL(read<T>(to_string(xmax)), xmax);
        BOOST_CHECK_EQUAL(read<T>(to_string(overflow<T>())), none);
    }

    // Signed integers.
    template<class T>
    void check_integer_options(std::false_type) {
        using std::to_string;
        // Run tests for positive integers.
        std::true_type tk;
        check_integer_options<T>(tk);
        // Run tests for negative integers.
        auto xmin = std::numeric_limits<T>::min();
        BOOST_CHECK_EQUAL(read<T>(to_string(xmin)), xmin);
        BOOST_CHECK_EQUAL(read<T>(to_string(underflow<T>())), none);
    }

    // only works with an integral types and double
    template<class T>
    void check_integer_options() {
        std::integral_constant<bool, std::is_unsigned<T>::value> tk;
        check_integer_options<T>(tk);
    }

    void compare(const config_option &lhs, const config_option &rhs) {
        BOOST_CHECK_EQUAL(lhs.category(), rhs.category());
        BOOST_CHECK_EQUAL(lhs.long_name(), rhs.long_name());
        BOOST_CHECK_EQUAL(lhs.short_names(), rhs.short_names());
        BOOST_CHECK_EQUAL(lhs.description(), rhs.description());
        BOOST_CHECK_EQUAL(lhs.full_name(), rhs.full_name());
    }

}    // namespace

BOOST_AUTO_TEST_CASE(copy_constructor) {
    auto one = make_config_option<int>("cat1", "one", "option 1");
    auto two = one;
    compare(one, two);
}

BOOST_AUTO_TEST_CASE(copy_assignment) {
    auto one = make_config_option<int>("cat1", "one", "option 1");
    auto two = make_config_option<int>("cat2", "two", "option 2");
    two = one;
    compare(one, two);
}

BOOST_AUTO_TEST_CASE(type_bool) {
    BOOST_CHECK_EQUAL(read<bool>("true"), true);
    BOOST_CHECK_EQUAL(read<bool>("false"), false);
    BOOST_CHECK_EQUAL(read<bool>("0"), none);
    BOOST_CHECK_EQUAL(read<bool>("1"), none);
}

BOOST_AUTO_TEST_CASE(type int8_t) {
    check_integer_options<int8_t>();
}

BOOST_AUTO_TEST_CASE(type uint8_t) {
    check_integer_options<uint8_t>();
}

BOOST_AUTO_TEST_CASE(type int16_t) {
    check_integer_options<int16_t>();
}

BOOST_AUTO_TEST_CASE(type uint16_t) {
    check_integer_options<uint16_t>();
}

BOOST_AUTO_TEST_CASE(type int32_t) {
    check_integer_options<int32_t>();
}

BOOST_AUTO_TEST_CASE(type uint32_t) {
    check_integer_options<uint32_t>();
}

BOOST_AUTO_TEST_CASE(type uint64_t) {
    BOOST_CHECK_EQUAL(unbox(read<uint64_t>("0")), 0u);
    BOOST_CHECK_EQUAL(read<uint64_t>("-1"), none);
}

BOOST_AUTO_TEST_CASE(type int64_t) {
    BOOST_CHECK_EQUAL(unbox(read<int64_t>("-1")), -1);
    BOOST_CHECK_EQUAL(unbox(read<int64_t>("0")), 0);
    BOOST_CHECK_EQUAL(unbox(read<int64_t>("1")), 1);
}

BOOST_AUTO_TEST_CASE(type_float) {
    BOOST_CHECK_EQUAL(unbox(read<float>("-1.0")), -1.0f);
    BOOST_CHECK_EQUAL(unbox(read<float>("-0.1")), -0.1f);
    BOOST_CHECK_EQUAL(read<float>("0"), 0.f);
    BOOST_CHECK_EQUAL(read<float>("\"0.1\""), none);
}

BOOST_AUTO_TEST_CASE(type_double) {
    BOOST_CHECK_EQUAL(unbox(read<double>("-1.0")), -1.0);
    BOOST_CHECK_EQUAL(unbox(read<double>("-0.1")), -0.1);
    BOOST_CHECK_EQUAL(read<double>("0"), 0.);
    BOOST_CHECK_EQUAL(read<double>("\"0.1\""), none);
}

BOOST_AUTO_TEST_CASE(type_string) {
    BOOST_CHECK_EQUAL(unbox(read<string>("foo")), "foo");
    BOOST_CHECK_EQUAL(unbox(read<string>("\"foo\"")), "foo");
}

BOOST_AUTO_TEST_CASE(type_timespan) {
    timespan dur {500};
    BOOST_CHECK_EQUAL(unbox(read<timespan>("500ns")), dur);
}

BOOST_AUTO_TEST_CASE(lists) {
    using int_list = std::vector<int>;
    BOOST_CHECK_EQUAL(read<int_list>("[]"), int_list({}));
    BOOST_CHECK_EQUAL(read<int_list>("1, 2, 3"), int_list({1, 2, 3}));
    BOOST_CHECK_EQUAL(read<int_list>("[1, 2, 3]"), int_list({1, 2, 3}));
}

BOOST_AUTO_TEST_CASE(flat CLI parsing) {
    auto x = make_config_option<std::string>("?foo", "bar,b", "test option");
    BOOST_CHECK_EQUAL(x.category(), "foo");
    BOOST_CHECK_EQUAL(x.long_name(), "bar");
    BOOST_CHECK_EQUAL(x.short_names(), "b");
    BOOST_CHECK_EQUAL(x.full_name(), "foo.bar");
    BOOST_CHECK_EQUAL(x.has_flat_cli_name(), true);
}

BOOST_AUTO_TEST_CASE(flat CLI parsing with nested categories) {
    auto x = make_config_option<std::string>("?foo.goo", "bar,b", "test option");
    BOOST_CHECK_EQUAL(x.category(), "foo.goo");
    BOOST_CHECK_EQUAL(x.long_name(), "bar");
    BOOST_CHECK_EQUAL(x.short_names(), "b");
    BOOST_CHECK_EQUAL(x.full_name(), "foo.goo.bar");
    BOOST_CHECK_EQUAL(x.has_flat_cli_name(), true);
}

BOOST_AUTO_TEST_CASE(find_by_long_opt) {
    auto needle = make_config_option<std::string>("?foo", "bar,b", "test option");
    auto check = [&](std::vector<string> args, bool found_opt, bool has_opt) {
        auto res = find_by_long_name(needle, std::begin(args), std::end(args));
        BOOST_CHECK_EQUAL(res.first != std::end(args), found_opt);
        if (has_opt)
            BOOST_CHECK_EQUAL(res.second, "val2");
        else
            BOOST_CHECK(res.second.empty());
    };
    // Well formed, find val2.
    check({"--foo=val1", "--bar=val2", "--baz=val3"}, true, true);
    // Dashes missing, no match.
    check({"--foo=val1", "bar=val2", "--baz=val3"}, false, false);
    // Equal missing.
    check({"--fooval1", "--barval2", "--bazval3"}, false, false);
    // Option value missing.
    check({"--foo=val1", "--bar=", "--baz=val3"}, true, false);
    // With prefix 'caf#'.
    check({"--caf#foo=val1", "--caf#bar=val2", "--caf#baz=val3"}, true, true);
    // Option not included.
    check({"--foo=val1", "--b4r=val2", "--baz=val3"}, false, false);
    // Option not included, with prefix.
    check({"--caf#foo=val1", "--caf#b4r=val2", "--caf#baz=val3"}, false, false);
    // No options to look through.
    check({}, false, false);
}
