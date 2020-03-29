//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE detail.parser.read_timespan

#include <nil/actor/detail/parser/read_timespan.hpp>

#include <nil/actor/test/dsl.hpp>

#include <chrono>

#include <nil/actor/parser_state.hpp>
#include <nil/actor/string_view.hpp>
#include <nil/actor/variant.hpp>

using namespace nil::actor;

namespace {

    using std::chrono::duration_cast;

    timespan operator"" _ns(unsigned long long x) {
        return duration_cast<timespan>(std::chrono::nanoseconds(x));
    }

    timespan operator"" _us(unsigned long long x) {
        return duration_cast<timespan>(std::chrono::microseconds(x));
    }

    timespan operator"" _ms(unsigned long long x) {
        return duration_cast<timespan>(std::chrono::milliseconds(x));
    }

    timespan operator"" _s(unsigned long long x) {
        return duration_cast<timespan>(std::chrono::seconds(x));
    }

    timespan operator"" _h(unsigned long long x) {
        return duration_cast<timespan>(std::chrono::hours(x));
    }

    struct timespan_consumer {
        using value_type = timespan;

        void value(timespan y) {
            x = y;
        }

        timespan x;
    };

    optional<timespan> read(string_view str) {
        timespan_consumer consumer;
        string_parser_state ps {str.begin(), str.end()};
        detail::parser::read_timespan(ps, consumer);
        if (ps.code != pec::success)
            return none;
        return consumer.x;
    }

}    // namespace

BOOST_AUTO_TEST_CASE(todo) {
    BOOST_CHECK_EQUAL(read("12ns"), 12_ns);
    BOOST_CHECK_EQUAL(read("34us"), 34_us);
    BOOST_CHECK_EQUAL(read("56ms"), 56_ms);
    BOOST_CHECK_EQUAL(read("78s"), 78_s);
    BOOST_CHECK_EQUAL(read("60min"), 1_h);
    BOOST_CHECK_EQUAL(read("90h"), 90_h);
}
