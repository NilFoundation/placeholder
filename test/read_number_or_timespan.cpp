//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE detail.parser.read_number_or_timespan

#include <nil/actor/detail/parser/read_number_or_timespan.hpp>

#include <boost/test/unit_test.hpp>

#include <string>

#include <nil/actor/parser_state.hpp>
#include <nil/actor/string_view.hpp>
#include <nil/actor/variant.hpp>

using namespace nil::actor;
using namespace std::chrono;

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

    struct number_or_timespan_parser_consumer {
        variant<int64_t, double, timespan> x;
        template<class T>
        void value(T y) {
            x = y;
        }
    };

    struct res_t {
        variant<pec, double, int64_t, timespan> val;
        template<class T>
        res_t(T &&x) : val(std::forward<T>(x)) {
            // nop
        }
    };

    std::string to_string(const res_t &x) {
        return deep_to_string(x.val);
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
        if (holds_alternative<int64_t>(x.val))
            return f(get<int64_t>(x.val), get<int64_t>(y.val));
        return f(get<timespan>(x.val), get<timespan>(y.val));
    }

    struct number_or_timespan_parser {
        res_t operator()(string_view str) {
            number_or_timespan_parser_consumer f;
            string_parser_state res {str.begin(), str.end()};
            detail::parser::read_number_or_timespan(res, f);
            if (res.code == pec::success)
                return f.x;
            return res.code;
        }
    };

    struct fixture {
        number_or_timespan_parser p;
    };

    template<class T>
    typename std::enable_if<std::is_integral<T>::value, res_t>::type res(T x) {
        return {static_cast<int64_t>(x)};
    }

    template<class T>
    typename std::enable_if<std::is_floating_point<T>::value, res_t>::type res(T x) {
        return {static_cast<double>(x)};
    }

    template<class Rep, class Period>
    res_t res(std::chrono::duration<Rep, Period> x) {
        return std::chrono::duration_cast<timespan>(x);
    }

}    // namespace

namespace boost {
    namespace test_tools {
        namespace tt_detail {
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

BOOST_FIXTURE_TEST_SUITE(read_number_or_timespan_tests, fixture)

BOOST_AUTO_TEST_CASE(valid_numbers_and_timespans) {
    BOOST_CHECK_EQUAL(p("123"), res(123));
    BOOST_CHECK_EQUAL(p("123.456"), res(123.456));
    BOOST_CHECK_EQUAL(p("123s"), res(seconds(123)));
    BOOST_CHECK_EQUAL(p("123ns"), res(nanoseconds(123)));
    BOOST_CHECK_EQUAL(p("123ms"), res(milliseconds(123)));
    BOOST_CHECK_EQUAL(p("123us"), res(microseconds(123)));
    BOOST_CHECK_EQUAL(p("123min"), res(minutes(123)));
}

BOOST_AUTO_TEST_CASE(invalid_timespans) {
    BOOST_CHECK_EQUAL(p("12.3s"), pec::fractional_timespan);
    BOOST_CHECK_EQUAL(p("12.3n"), pec::fractional_timespan);
    BOOST_CHECK_EQUAL(p("12.3ns"), pec::fractional_timespan);
    BOOST_CHECK_EQUAL(p("12.3m"), pec::fractional_timespan);
    BOOST_CHECK_EQUAL(p("12.3ms"), pec::fractional_timespan);
    BOOST_CHECK_EQUAL(p("12.3n"), pec::fractional_timespan);
    BOOST_CHECK_EQUAL(p("12.3ns"), pec::fractional_timespan);
    BOOST_CHECK_EQUAL(p("12.3mi"), pec::fractional_timespan);
    BOOST_CHECK_EQUAL(p("12.3min"), pec::fractional_timespan);
    BOOST_CHECK_EQUAL(p("123ss"), pec::trailing_character);
    BOOST_CHECK_EQUAL(p("123m"), pec::unexpected_eof);
    BOOST_CHECK_EQUAL(p("123mi"), pec::unexpected_eof);
    BOOST_CHECK_EQUAL(p("123u"), pec::unexpected_eof);
    BOOST_CHECK_EQUAL(p("123n"), pec::unexpected_eof);
}

BOOST_AUTO_TEST_SUITE_END()
