//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#include <nil/actor/config.hpp>

#define BOOST_TEST_MODULE inbound_path_test

#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <nil/actor/inbound_path.hpp>

using namespace std;
using namespace nil::actor;

namespace {

    template<class... Ts>
    void print(const char *format, Ts... xs) {
        char buf[200];
        snprintf(buf, 200, format, xs...);
        BOOST_TEST_MESSAGE(buf);
    }

    struct fixture {
        inbound_path::stats_t x;

        void calculate(int32_t total_items, int32_t total_time) {
            int32_t c = 1000;
            int32_t d = 100;
            int32_t n = total_items;
            int32_t t = total_time;
            int32_t m = t > 0 ? std::max((c * n) / t, 1) : 1;
            int32_t b = t > 0 ? std::max((d * n) / t, 1) : 1;
            print("with a cycle C = %ldns, desired complexity D = %ld,", c, d);
            print("number of items N = %ld, and time delta t = %ld:", n, t);
            print("- throughput M = max(C * N / t, 1) = max(%ld * %ld / %ld, 1) = %ld", c, n, t, m);
            print("- items/batch B = max(D * N / t, 1) = max(%ld * %ld / %ld, 1) = %ld", d, n, t, b);
            auto cr = x.calculate(timespan(c), timespan(d));
            BOOST_CHECK_EQUAL(cr.items_per_batch, b);
            BOOST_CHECK_EQUAL(cr.max_throughput, m);
        }

        void store(int32_t batch_size, int32_t calculation_time_ns) {
            inbound_path::stats_t::measurement m {batch_size, timespan {calculation_time_ns}};
            x.store(m);
        }
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(inbound_path_tests, fixture)

BOOST_AUTO_TEST_CASE(default_constructed_test) {
    calculate(0, 0);
}

BOOST_AUTO_TEST_CASE(one_store_test) {
    BOOST_TEST_MESSAGE("store a measurement for 500ns with batch size of 50");
    store(50, 500);
    calculate(50, 500);
}

BOOST_AUTO_TEST_CASE(multiple_stores_test) {
    BOOST_TEST_MESSAGE("store a measurement: (50, 500ns), (60, 400ns), (40, 600ns)");
    store(50, 500);
    store(40, 600);
    store(60, 400);
    calculate(150, 1500);
}

BOOST_AUTO_TEST_SUITE_END()
