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
        nil::actor::test::equal_to f;
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
