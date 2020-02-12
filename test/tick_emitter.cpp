//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt or
// http://opensource.org/licenses/BSD-3-Clause
//---------------------------------------------------------------------------//

// This test simulates a complex multiplexing over multiple layers of WDRR
// scheduled queues. The goal is to reduce the complex mailbox management of
// ACTOR to its bare bones in order to test whether the multiplexing of stream
// traffic and asynchronous messages works as intended.
//
// The setup is a fixed WDRR queue with three nestes queues. The first nested
// queue stores asynchronous messages, the second one upstream messages, and
// the last queue is a dynamic WDRR queue storing downstream messages.
//
// We mock just enough of an actor to use the streaming classes and put them to
// work in a pipeline with 2 or 3 stages.

#define BOOST_TEST_MODULE tick_emitter_test

#include <boost/test/unit_test.hpp>

#include <vector>

#include <boost/integer/common_factor_rt.hpp>

#include <nil/actor/timestamp.hpp>
#include <nil/actor/deep_to_string.hpp>

#include <nil/actor/detail/tick_emitter.hpp>

using std::vector;

using namespace nil::actor;

using time_point = nil::actor::detail::tick_emitter::time_point;

namespace {

    timespan credit_interval {200};
    timespan force_batch_interval {50};

}    // namespace

BOOST_AUTO_TEST_CASE(start_and_stop_test) {
    detail::tick_emitter x;
    detail::tick_emitter y {time_point {timespan {100}}};
    detail::tick_emitter z;
    z.start(time_point {timespan {100}});
    BOOST_CHECK_EQUAL(x.started(), false);
    BOOST_CHECK_EQUAL(y.started(), true);
    BOOST_CHECK_EQUAL(z.started(), true);
    for (auto t : {&x, &y, &z}) {
        t->stop();
    }
    BOOST_CHECK_EQUAL(x.started(), false);
    BOOST_CHECK_EQUAL(y.started(), false);
    BOOST_CHECK_EQUAL(z.started(), false);
}

BOOST_AUTO_TEST_CASE(ticks_test) {
    auto cycle = boost::integer::gcd(credit_interval.count(), force_batch_interval.count());
    BOOST_CHECK_EQUAL(cycle, 50);
    auto force_batch_frequency = static_cast<size_t>(force_batch_interval.count() / cycle);
    auto credit_frequency = static_cast<size_t>(credit_interval.count() / cycle);
    detail::tick_emitter tctrl {time_point {timespan {100}}};
    tctrl.interval(timespan {cycle});
    vector<size_t> ticks;
    size_t force_batch_triggers = 0;
    size_t credit_triggers = 0;
    auto f = [&](size_t tick_id) {
        ticks.push_back(tick_id);
        if (tick_id % force_batch_frequency == 0) {
            ++force_batch_triggers;
        }
        if (tick_id % credit_frequency == 0) {
            ++credit_triggers;
        }
    };
    BOOST_TEST_MESSAGE("trigger 4 ticks");
    tctrl.update(time_point {timespan {300}}, f);
    BOOST_CHECK_EQUAL(deep_to_string(ticks), "[1, 2, 3, 4]");
    BOOST_CHECK_EQUAL(force_batch_triggers, 4lu);
    BOOST_CHECK_EQUAL(credit_triggers, 1lu);
    BOOST_TEST_MESSAGE("trigger 3 more ticks");
    tctrl.update(time_point {timespan {475}}, f);
    BOOST_CHECK_EQUAL(deep_to_string(ticks), "[1, 2, 3, 4, 5, 6, 7]");
    BOOST_CHECK_EQUAL(force_batch_triggers, 7lu);
    BOOST_CHECK_EQUAL(credit_triggers, 1lu);
}

BOOST_AUTO_TEST_CASE(timeouts_test) {
    timespan interval {50};
    time_point start {timespan {100}};
    auto now = start;
    detail::tick_emitter tctrl {now};
    tctrl.interval(interval);
    BOOST_TEST_MESSAGE("advance until the first 5-tick-period ends");
    now += interval * 5;
    auto bitmask = tctrl.timeouts(now, {5, 7});
    BOOST_CHECK_EQUAL(bitmask, 0x01u);
    BOOST_TEST_MESSAGE("advance until the first 7-tick-period ends");
    now += interval * 2;
    bitmask = tctrl.timeouts(now, {5, 7});
    BOOST_CHECK_EQUAL(bitmask, 0x02u);
    BOOST_TEST_MESSAGE("advance until both tick period ends");
    now += interval * 7;
    bitmask = tctrl.timeouts(now, {5, 7});
    BOOST_CHECK_EQUAL(bitmask, 0x03u);
    BOOST_TEST_MESSAGE("advance until both tick period end multiple times");
    now += interval * 21;
    bitmask = tctrl.timeouts(now, {5, 7});
    BOOST_CHECK_EQUAL(bitmask, 0x03u);
    BOOST_TEST_MESSAGE("advance without any timeout");
    now += interval * 1;
    bitmask = tctrl.timeouts(now, {5, 7});
    BOOST_CHECK_EQUAL(bitmask, 0x00u);
}

BOOST_AUTO_TEST_CASE(next_timeout_test) {
    timespan interval {50};
    time_point start {timespan {100}};
    auto now = start;
    detail::tick_emitter tctrl {now};
    tctrl.interval(interval);
    BOOST_TEST_MESSAGE("advance until the first 5-tick-period ends");
    auto next = tctrl.next_timeout(now, {5, 7});
    BOOST_CHECK(next == start + timespan(5 * interval));
    BOOST_TEST_MESSAGE("advance until the first 7-tick-period ends");
    now = start + timespan(5 * interval);
    next = tctrl.next_timeout(now, {5, 7});
    BOOST_CHECK(next == start + timespan(7 * interval));
    BOOST_TEST_MESSAGE("advance until the second 5-tick-period ends");
    now = start + timespan(7 * interval);
    next = tctrl.next_timeout(now, {5, 7});
    BOOST_CHECK(next == start + timespan((2 * 5) * interval));
    BOOST_TEST_MESSAGE("advance until the second 7-tick-period ends");
    now = start + timespan(11 * interval);
    next = tctrl.next_timeout(now, {5, 7});
    BOOST_CHECK(next == start + timespan((2 * 7) * interval));
}
