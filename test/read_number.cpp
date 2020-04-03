//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE detail.parser.read_number

#include <boost/test/unit_test.hpp>

#include <nil/actor/test/core_test.hpp>

#include <string>

#include <nil/actor/detail/parser/read_number.hpp>
#include <nil/actor/detail/parser/add_ascii.hpp>
#include <nil/actor/detail/parser/sub_ascii.hpp>

#include <nil/actor/expected.hpp>
#include <nil/actor/parser_state.hpp>
#include <nil/actor/pec.hpp>
#include <nil/actor/string_view.hpp>
#include <nil/actor/variant.hpp>
#include <nil/actor/config_value.hpp>
#include <nil/actor/init_global_meta_objects.hpp>

using namespace nil::actor;

namespace {

    struct equality_operator {
        static constexpr bool default_value = false;

        template<class T,
                 class U,
                 detail::enable_if_t<((std::is_floating_point<T>::value && std::is_convertible<U, double>::value) ||
                                      (std::is_floating_point<U>::value && std::is_convertible<T, double>::value)) &&
                                         detail::is_comparable<T, U>::value,
                                     int> = 0>
        bool operator()(const T &t, const U &u) const {
            auto x = static_cast<long double>(t);
            auto y = static_cast<long double>(u);
            auto max = std::max(std::abs(x), std::abs(y));
            auto dif = std::abs(x - y);
            return dif <= max * 1e-5l;
        }

        template<class T,
                 class U,
                 detail::enable_if_t<!((std::is_floating_point<T>::value && std::is_convertible<U, double>::value) ||
                                       (std::is_floating_point<U>::value && std::is_convertible<T, double>::value)) &&
                                         detail::is_comparable<T, U>::value,
                                     int> = 0>
        bool operator()(const T &x, const U &y) const {
            return x == y;
        }

        template<class T, class U, typename std::enable_if<!detail::is_comparable<T, U>::value, int>::type = 0>
        bool operator()(const T &, const U &) const {
            return default_value;
        }
    };

    struct inequality_operator {
        static constexpr bool default_value = true;

        template<class T,
                 class U,
                 typename std::enable_if<(std::is_floating_point<T>::value || std::is_floating_point<U>::value) &&
                                             detail::is_comparable<T, U>::value,
                                         int>::type = 0>
        bool operator()(const T &x, const U &y) const {
            equality_operator f;
            return !f(x, y);
        }

        template<class T,
                 class U,
                 typename std::enable_if<!std::is_floating_point<T>::value && !std::is_floating_point<U>::value &&
                                             detail::is_comparable<T, U>::value,
                                         int>::type = 0>
        bool operator()(const T &x, const U &y) const {
            return x != y;
        }

        template<class T, class U, typename std::enable_if<!detail::is_comparable<T, U>::value, int>::type = 0>
        bool operator()(const T &, const U &) const {
            return default_value;
        }
    };

    template<class F, class T>
    struct comparison_unbox_helper {
        const F &f;
        const T &rhs;

        template<class U>
        bool operator()(const U &lhs) const {
            return f(lhs, rhs);
        }
    };

    template<class Operator>
    class comparison {
    public:
        // -- default case -----------------------------------------------------------

        template<class T, class U>
        bool operator()(const T &x, const U &y) const {
            std::integral_constant<bool, SumType<T>()> lhs_is_sum_type;
            std::integral_constant<bool, SumType<U>()> rhs_is_sum_type;
            return cmp(x, y, lhs_is_sum_type, rhs_is_sum_type);
        }

    private:
        // -- automagic unboxing of sum types ----------------------------------------

        template<class T, class U>
        bool cmp(const T &x, const U &y, std::false_type, std::false_type) const {
            Operator f;
            return f(x, y);
        }

        template<class T, class U>
        bool cmp(const T &x, const U &y, std::true_type, std::false_type) const {
            Operator f;
            auto inner_x = nil::actor::get_if<U>(&x);
            return inner_x ? f(*inner_x, y) : Operator::default_value;
        }

        template<class T, class U>
        bool cmp(const T &x, const U &y, std::false_type, std::true_type) const {
            Operator f;
            auto inner_y = nil::actor::get_if<T>(&y);
            return inner_y ? f(x, *inner_y) : Operator::default_value;
        }

        template<class T, class U>
        bool cmp(const T &x, const U &y, std::true_type, std::true_type) const {
            comparison_unbox_helper<comparison, U> f {*this, y};
            return visit(f, x);
        }
    };

    using equal_to = comparison<equality_operator>;

    using not_equal_to = comparison<inequality_operator>;

    struct number_consumer {
        variant<int64_t, double> x;
        void value(double y) {
            x = y;
        }
        void value(int64_t y) {
            x = y;
        }
    };

    struct range_consumer {
        std::vector<int64_t> xs;
        void value(double) {
            BOOST_FAIL("range consumer called with a double");
        }
        void value(int64_t y) {
            xs.emplace_back(y);
        }
    };

    struct res_t {
        variant<pec, double, int64_t> val;
        template<class T>
        res_t(T &&x) : val(std::forward<T>(x)) {
            // nop
        }
    };

    std::string to_string(const res_t &x) {
        return nil::actor::visit([](auto &y) { return deep_to_string(y); }, x.val);
    }

    bool operator==(const res_t &x, const res_t &y) {
        if (x.val.index() != y.val.index())
            return false;
        // Implements a safe equal comparison for double.
        equal_to f;
        using nil::actor::get;
        using nil::actor::holds_alternative;
        if (holds_alternative<pec>(x.val))
            return f(get<pec>(x.val), get<pec>(y.val));
        if (holds_alternative<double>(x.val))
            return f(get<double>(x.val), get<double>(y.val));
        return f(get<int64_t>(x.val), get<int64_t>(y.val));
    }

    struct numbers_parser {
        res_t operator()(string_view str) {
            number_consumer f;
            string_parser_state res {str.begin(), str.end()};
            detail::parser::read_number(res, f);
            if (res.code == pec::success)
                return f.x;
            return res.code;
        }
    };

    struct range_parser {
        expected<std::vector<int64_t>> operator()(string_view str) {
            range_consumer f;
            string_parser_state res {str.begin(), str.end()};
            detail::parser::read_number(res, f, std::true_type {}, std::true_type {});
            if (res.code == pec::success)
                return std::move(f.xs);
            return make_error(res);
        }
    };

    template<class T>
    typename std::enable_if<std::is_integral<T>::value, res_t>::type res(T x) {
        return {static_cast<int64_t>(x)};
    }

    template<class T>
    typename std::enable_if<std::is_floating_point<T>::value, res_t>::type res(T x) {
        return {static_cast<double>(x)};
    }

    struct fixture {
        numbers_parser p;
        range_parser r;
    };

}    // namespace

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<template<typename...> class P, typename... T>
            struct print_log_value<P<T...>> {
                void operator()(std::ostream &, P<T...> const &) {
                }
            };
            template<>
            struct print_log_value<res_t> {
                void operator()(std::ostream &, res_t const &) {
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

#define CHECK_NUMBER(x) BOOST_CHECK_EQUAL(p(#x), res(x))

BOOST_FIXTURE_TEST_SUITE(read_number_tests, fixture)

BOOST_AUTO_TEST_CASE(add_ascii_unsigned) {
    using detail::parser::add_ascii;
    auto rd = [](string_view str) -> expected<uint8_t> {
        uint8_t x = 0;
        for (auto c : str)
            if (!add_ascii<10>(x, c))
                return pec::integer_overflow;
        return x;
    };
    for (int i = 0; i < 256; ++i)
        BOOST_CHECK_EQUAL(rd(std::to_string(i)), static_cast<uint8_t>(i));
    for (int i = 256; i < 513; ++i)
        BOOST_CHECK_EQUAL(rd(std::to_string(i)), pec::integer_overflow);
}

BOOST_AUTO_TEST_CASE(add_ascii_signed_test) {
    auto rd = [](string_view str) -> expected<int8_t> {
        int8_t x = 0;
        for (auto c : str)
            if (!detail::parser::add_ascii<10>(x, c))
                return pec::integer_overflow;
        return x;
    };
    for (int i = 0; i < 128; ++i)
        BOOST_CHECK_EQUAL(rd(std::to_string(i)), static_cast<int8_t>(i));
    for (int i = 128; i < 513; ++i)
        BOOST_CHECK_EQUAL(rd(std::to_string(i)), pec::integer_overflow);
}

BOOST_AUTO_TEST_CASE(sub_ascii_test) {
    auto rd = [](string_view str) -> expected<int8_t> {
        int8_t x = 0;
        for (auto c : str)
            if (!detail::parser::sub_ascii<10>(x, c))
                return pec::integer_underflow;
        return x;
    };
    // Using sub_ascii in this way behaves as if we'd prefix the number with a
    // minus sign, i.e., "123" will result in -123.
    for (int i = 1; i < 129; ++i)
        BOOST_CHECK_EQUAL(rd(std::to_string(i)), static_cast<int8_t>(-i));
    for (int i = 129; i < 513; ++i)
        BOOST_CHECK_EQUAL(rd(std::to_string(i)), pec::integer_underflow);
}

BOOST_AUTO_TEST_CASE(binary_numbers) {
    /* TODO: use this implementation when switching to C++14
    CHECK_NUMBER(0b0);
    CHECK_NUMBER(0b10);
    CHECK_NUMBER(0b101);
    CHECK_NUMBER(0B1001);
    CHECK_NUMBER(-0b0);
    CHECK_NUMBER(-0b101);
    CHECK_NUMBER(-0B1001);
    */
    BOOST_CHECK_EQUAL(p("0b0"), res(0));
    BOOST_CHECK_EQUAL(p("0b10"), res(2));
    BOOST_CHECK_EQUAL(p("0b101"), res(5));
    BOOST_CHECK_EQUAL(p("0B1001"), res(9));
    BOOST_CHECK_EQUAL(p("-0b0"), res(0));
    BOOST_CHECK_EQUAL(p("-0b101"), res(-5));
    BOOST_CHECK_EQUAL(p("-0B1001"), res(-9));
}

BOOST_AUTO_TEST_CASE(octal_numbers) {
    // valid numbers
    CHECK_NUMBER(00);
    CHECK_NUMBER(010);
    CHECK_NUMBER(0123);
    CHECK_NUMBER(0777);
    CHECK_NUMBER(-00);
    CHECK_NUMBER(-0123);
    // invalid numbers
    BOOST_CHECK_EQUAL(p("018"), pec::trailing_character);
}

BOOST_AUTO_TEST_CASE(decimal_numbers) {
    CHECK_NUMBER(0);
    CHECK_NUMBER(10);
    CHECK_NUMBER(123);
    CHECK_NUMBER(-0);
    CHECK_NUMBER(-123);
}

BOOST_AUTO_TEST_CASE(hexadecimal_numbers) {
    // valid numbers
    CHECK_NUMBER(0x0);
    CHECK_NUMBER(0x10);
    CHECK_NUMBER(0X123);
    CHECK_NUMBER(0xAF01);
    CHECK_NUMBER(-0x0);
    CHECK_NUMBER(-0x123);
    CHECK_NUMBER(-0xaf01);
    // invalid numbers
    BOOST_CHECK_EQUAL(p("0xFG"), pec::trailing_character);
    BOOST_CHECK_EQUAL(p("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), pec::integer_overflow);
    BOOST_CHECK_EQUAL(p("-0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), pec::integer_underflow);
}

BOOST_AUTO_TEST_CASE(floating_point_numbers) {
    CHECK_NUMBER(0.0);
    CHECK_NUMBER(.0);
    CHECK_NUMBER(0.);
    CHECK_NUMBER(1.1);
    CHECK_NUMBER(.1);
    CHECK_NUMBER(1.);
    CHECK_NUMBER(0.123);
    CHECK_NUMBER(.123);
    CHECK_NUMBER(123.456);
    CHECK_NUMBER(-0.0);
    CHECK_NUMBER(-.0);
    CHECK_NUMBER(-0.);
    CHECK_NUMBER(-1.1);
    CHECK_NUMBER(-.1);
    CHECK_NUMBER(-1.);
    CHECK_NUMBER(-0.123);
    CHECK_NUMBER(-.123);
    CHECK_NUMBER(-123.456);
}

BOOST_AUTO_TEST_CASE(integer_mantissa_with_positive_exponent) {
    CHECK_NUMBER(321E1);
    CHECK_NUMBER(321e1);
    CHECK_NUMBER(321e+1);
    CHECK_NUMBER(123e2);
    CHECK_NUMBER(-4e2);
    CHECK_NUMBER(1e1);
    CHECK_NUMBER(1e2);
    CHECK_NUMBER(1e3);
    CHECK_NUMBER(1e4);
    CHECK_NUMBER(1e5);
    CHECK_NUMBER(1e6);
}

BOOST_AUTO_TEST_CASE(integer_mantissa_with_negative_exponent) {
    // valid numbers
    CHECK_NUMBER(321E-1);
    CHECK_NUMBER(321e-1);
    CHECK_NUMBER(123e-2);
    CHECK_NUMBER(-4e-2);
    CHECK_NUMBER(1e-1);
    CHECK_NUMBER(1e-2);
    CHECK_NUMBER(1e-3);
    CHECK_NUMBER(1e-4);
    CHECK_NUMBER(1e-5);
    CHECK_NUMBER(1e-6);
    // invalid numbers
    BOOST_CHECK_EQUAL(p("-9.9999e-e511"), pec::unexpected_character);
    BOOST_CHECK_EQUAL(p("-9.9999e-511"), pec::exponent_underflow);
}

BOOST_AUTO_TEST_CASE(fractional_mantissa_with_positive_exponent) {
    CHECK_NUMBER(3.21E1);
    CHECK_NUMBER(3.21e+1);
    CHECK_NUMBER(3.21e+1);
    CHECK_NUMBER(12.3e2);
    CHECK_NUMBER(-0.001e3);
    CHECK_NUMBER(0.0001e5);
    CHECK_NUMBER(-42.001e3);
    CHECK_NUMBER(42.0001e5);
}

BOOST_AUTO_TEST_CASE(fractional_mantissa_with_negative_exponent) {
    CHECK_NUMBER(3.21E-1);
    CHECK_NUMBER(3.21e-1);
    CHECK_NUMBER(12.3e-2);
    CHECK_NUMBER(-0.001e-3);
    CHECK_NUMBER(-0.0001e-5);
    CHECK_NUMBER(-42.001e-3);
    CHECK_NUMBER(-42001e-6);
    CHECK_NUMBER(-42.0001e-5);
}

#define CHECK_RANGE(expr, ...) BOOST_CHECK_EQUAL(r(expr), std::vector<int64_t>({__VA_ARGS__}))

BOOST_AUTO_TEST_CASE(a_range_from_n_to_n_is_just_n) {
    CHECK_RANGE("0..0", 0);
    CHECK_RANGE("1..1", 1);
    CHECK_RANGE("2..2", 2);
    CHECK_RANGE("101..101", 101);
    CHECK_RANGE("101..101..1", 101);
    CHECK_RANGE("101..101..2", 101);
    CHECK_RANGE("101..101..-1", 101);
    CHECK_RANGE("101..101..-2", 101);
}

BOOST_AUTO_TEST_CASE(ranges_are_either_ascending_or_descending) {
    CHECK_RANGE("0..1", 0, 1);
    CHECK_RANGE("0..2", 0, 1, 2);
    CHECK_RANGE("0..3", 0, 1, 2, 3);
    CHECK_RANGE("3..0", 3, 2, 1, 0);
    CHECK_RANGE("3..1", 3, 2, 1);
    CHECK_RANGE("3..2", 3, 2);
}

BOOST_AUTO_TEST_CASE(ranges_can_use_positive_step_values) {
    CHECK_RANGE("2..6..2", 2, 4, 6);
    CHECK_RANGE("3..8..3", 3, 6);
}

BOOST_AUTO_TEST_CASE(ranges_can_use_negative_step_values) {
    CHECK_RANGE("6..2..-2", 6, 4, 2);
    CHECK_RANGE("8..3..-3", 8, 5);
}

BOOST_AUTO_TEST_CASE(ranges_can_use_signed_integers) {
    CHECK_RANGE("+2..+6..+2", 2, 4, 6);
    CHECK_RANGE("+6..+2..-2", 6, 4, 2);
    CHECK_RANGE("+2..-2..-2", 2, 0, -2);
    CHECK_RANGE("-2..+2..+2", -2, 0, 2);
}

#define CHECK_ERR(expr, enum_value)                                      \
    if (auto res = r(expr)) {                                            \
        BOOST_FAIL("expected expression to produce to an error");        \
    } else {                                                             \
        auto &err = res.error();                                         \
        BOOST_CHECK(err.category() == error_category<pec>::value);       \
        BOOST_CHECK_EQUAL(err.code(), static_cast<uint8_t>(enum_value)); \
    }

BOOST_AUTO_TEST_CASE(the_parser_rejects_invalid_step_values) {
    nil::actor::init_global_meta_objects<nil::actor::id_block::core_test>();
    nil::actor::init_global_meta_objects<nil::actor::id_block::core_module>();

    CHECK_ERR("-2..+2..-2", pec::invalid_range_expression);
    CHECK_ERR("+2..-2..+2", pec::invalid_range_expression);
}

BOOST_AUTO_TEST_SUITE_END()
