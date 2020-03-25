//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE simple_timeout_test

#include <nil/actor/test/dsl.hpp>

#include <boost/chrono/duration.hpp>

#include <memory>

#include <nil/actor/after.hpp>
#include <nil/actor/all.hpp>

using namespace nil::actor;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<>
            struct print_log_value<duration> {
                void operator()(std::ostream &o, duration const &d) {
                    o << to_string(d);
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

namespace {

    using ms = std::chrono::milliseconds;

    using reset_atom = atom_constant<atom("reset")>;
    using timer = typed_actor<reacts_to<reset_atom>>;

    struct timer_state {
        bool had_reset = false;
    };

    timer::behavior_type timer_impl(timer::stateful_pointer<timer_state> self) {
        self->delayed_send(self, ms(100), reset_atom::value);
        return {[=](reset_atom) {
                    BOOST_TEST_MESSAGE("timer reset");
                    self->state.had_reset = true;
                },
                after(ms(600)) >>
                    [=] {
                        BOOST_TEST_MESSAGE("timer expired");
                        BOOST_REQUIRE(self->state.had_reset);
                        self->quit();
                    }};
    }

    timer::behavior_type timer_impl2(timer::pointer self) {
        auto had_reset = std::make_shared<bool>(false);
        delayed_anon_send(self, ms(100), reset_atom::value);
        return {[=](reset_atom) {
                    BOOST_TEST_MESSAGE("timer reset");
                    *had_reset = true;
                },
                after(ms(600)) >>
                    [=] {
                        BOOST_TEST_MESSAGE("timer expired");
                        BOOST_REQUIRE(*had_reset);
                        self->quit();
                    }};
    }

}    // namespace

BOOST_FIXTURE_TEST_SUITE(simple_timeout_tests, test_coordinator_fixture<>)

BOOST_AUTO_TEST_CASE(duration_conversion_test) {
    duration d1 {time_unit::milliseconds, 100};
    std::chrono::milliseconds d2 {100};
    duration d3 {d2};
    BOOST_CHECK_EQUAL(d1.count, static_cast<uint64_t>(d2.count()));
    BOOST_CHECK_EQUAL(d1, d3);
}

BOOST_AUTO_TEST_CASE(single_timeout_test) {
    sys.spawn(timer_impl);
}

BOOST_AUTO_TEST_CASE(single_anon_timeout_test) {
    sys.spawn(timer_impl2);
}

BOOST_AUTO_TEST_SUITE_END()
