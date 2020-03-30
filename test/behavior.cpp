//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE behavior

#include <nil/actor/config.hpp>

#include "core_test.hpp"

#include <functional>

#include <nil/actor/send.hpp>
#include <nil/actor/behavior.hpp>
#include <nil/actor/spawner.hpp>
#include <nil/actor/message_handler.hpp>
#include <nil/actor/event_based_actor.hpp>
#include <nil/actor/spawner_config.hpp>

using namespace nil::actor;

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
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

namespace {

    class nocopy_fun {
    public:
        nocopy_fun() = default;

        nocopy_fun(nocopy_fun &&) = default;

        nocopy_fun &operator=(nocopy_fun &&) = default;

        nocopy_fun(const nocopy_fun &) = delete;

        nocopy_fun &operator=(const nocopy_fun &) = delete;

        int operator()(int x, int y) {
            return x + y;
        }
    };

    struct fixture {
        message m1 = make_message(1);
        message m2 = make_message(1, 2);
        message m3 = make_message(1, 2, 3);
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(behavior_tests, fixture)

BOOST_AUTO_TEST_CASE(default_construct) {
    behavior f;
    BOOST_CHECK_EQUAL(f(m1), none);
    BOOST_CHECK_EQUAL(f(m2), none);
    BOOST_CHECK_EQUAL(f(m3), none);
}

BOOST_AUTO_TEST_CASE(nocopy_function_object) {
    behavior f {nocopy_fun {}};
    BOOST_CHECK_EQUAL(f(m1), none);
    BOOST_CHECK_EQUAL(to_string(f(m2)), "*(3)");
    BOOST_CHECK_EQUAL(f(m3), none);
}

BOOST_AUTO_TEST_CASE(single_lambda_construct) {
    behavior f {[](int x) { return x + 1; }};
    BOOST_CHECK_EQUAL(to_string(f(m1)), "*(2)");
    BOOST_CHECK_EQUAL(f(m2), none);
    BOOST_CHECK_EQUAL(f(m3), none);
}

BOOST_AUTO_TEST_CASE(multiple_lambda_construct) {
    behavior f {[](int x) { return x + 1; }, [](int x, int y) { return x * y; }};
    BOOST_CHECK_EQUAL(to_string(f(m1)), "*(2)");
    BOOST_CHECK_EQUAL(to_string(f(m2)), "*(2)");
    BOOST_CHECK_EQUAL(f(m3), none);
}

BOOST_AUTO_TEST_CASE(become_empty_behavior) {
    spawner_config cfg {};
    spawner sys {cfg};
    auto make_bhvr = [](event_based_actor *self) -> behavior { return {[=](int) { self->become(behavior {}); }}; };
    anon_send(sys.spawn(make_bhvr), int {5});
}

BOOST_AUTO_TEST_SUITE_END()
