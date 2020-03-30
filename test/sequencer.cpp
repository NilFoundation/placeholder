//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE decorator.sequencer

#include <nil/actor/decorator/sequencer.hpp>

#include <boost/test/unit_test.hpp>

#include <nil/actor/all.hpp>

#define ERROR_HANDLER [&](error &err) { BOOST_FAIL(system.render(err)); }

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
            struct print_log_value<node_id> {
                void operator()(std::ostream &, node_id const &) {
                }
            };
            template<>
            struct print_log_value<actor_addr> {
                void operator()(std::ostream &, actor_addr const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

namespace {

    behavior testee(event_based_actor *self) {
        return {
            [](int v) { return 2 * v; },
            [=] { self->quit(); },
        };
    }

    using first_stage = typed_actor<replies_to<int>::with<double, double>>;
    using second_stage = typed_actor<replies_to<double, double>::with<double>>;

    first_stage::behavior_type typed_first_stage() {
        return {
            [](int i) { return std::make_tuple(i * 2.0, i * 4.0); },
        };
    }

    second_stage::behavior_type typed_second_stage() {
        return {
            [](double x, double y) { return x * y; },
        };
    }

    struct fixture {
        fixture() : system(cfg), self(system, true) {
            // nop
        }

        template<class Actor>
        static bool exited(const Actor &handle) {
            auto ptr = actor_cast<abstract_actor *>(handle);
            auto dptr = dynamic_cast<monitorable_actor *>(ptr);
            BOOST_REQUIRE(dptr != nullptr);
            return dptr->getf(abstract_actor::is_terminated_flag);
        }

        spawner_config cfg;
        spawner system;
        scoped_actor self;
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(sequencer_tests, fixture)

BOOST_AUTO_TEST_CASE(identity) {
    spawner_config cfg_g;
    spawner system_of_g {cfg_g};
    spawner_config cfg_f;
    spawner system_of_f {cfg_f};
    auto g = system_of_g.spawn(typed_first_stage);
    auto f = system_of_f.spawn(typed_second_stage);
    BOOST_CHECK_EQUAL(system_of_g.registry().running(), 1u);
    auto h = f * g;
    BOOST_CHECK_EQUAL(system_of_g.registry().running(), 1u);
    BOOST_CHECK_EQUAL(&h->home_system(), &g->home_system());

    BOOST_CHECK_EQUAL(h->node(), g->node());
    BOOST_CHECK_NE(h->id(), g->id());
    BOOST_CHECK_NE(h.address(), g.address());
    BOOST_CHECK_EQUAL(h->message_types(), g->home_system().message_types(h));
}

// spawned dead if `g` is already dead upon spawning
BOOST_AUTO_TEST_CASE(lifetime_1a) {
    auto g = system.spawn(testee);
    auto f = system.spawn(testee);
    anon_send_exit(g, exit_reason::kill);
    self->wait_for(g);
    auto h = f * g;
    BOOST_CHECK(exited(h));
}

// spawned dead if `f` is already dead upon spawning
BOOST_AUTO_TEST_CASE(lifetime_1b) {
    auto g = system.spawn(testee);
    auto f = system.spawn(testee);
    anon_send_exit(f, exit_reason::kill);
    self->wait_for(f);
    auto h = f * g;
    BOOST_CHECK(exited(h));
}

// `f.g` exits when `g` exits
BOOST_AUTO_TEST_CASE(lifetime_2a) {
    auto g = system.spawn(testee);
    auto f = system.spawn(testee);
    auto h = f * g;
    self->monitor(h);
    anon_send(g, message {});
}

// `f.g` exits when `f` exits
BOOST_AUTO_TEST_CASE(lifetime_2b) {
    auto g = system.spawn(testee);
    auto f = system.spawn(testee);
    auto h = f * g;
    self->monitor(h);
    anon_send(f, message {});
}

BOOST_AUTO_TEST_CASE(request_response_promise) {
    auto g = system.spawn(testee);
    auto f = system.spawn(testee);
    auto h = f * g;
    anon_send_exit(h, exit_reason::kill);
    BOOST_CHECK(exited(h));
    self->request(h, infinite, 1)
        .receive([](int) { BOOST_CHECK(false); },
                 [](error err) { BOOST_CHECK_EQUAL(err.code(), static_cast<uint8_t>(sec::request_receiver_down)); });
}

// single composition of distinct actors
BOOST_AUTO_TEST_CASE(dot_composition_1) {
    auto first = system.spawn(typed_first_stage);
    auto second = system.spawn(typed_second_stage);
    auto first_then_second = second * first;
    self->request(first_then_second, infinite, 42)
        .receive([](double res) { BOOST_CHECK_EQUAL(res, (42 * 2.0) * (42 * 4.0)); }, ERROR_HANDLER);
}

// multiple self composition
BOOST_AUTO_TEST_CASE(dot_composition_2) {
    auto dbl_actor = system.spawn(testee);
    auto dbl_x4_actor = dbl_actor * dbl_actor * dbl_actor * dbl_actor;
    self->request(dbl_x4_actor, infinite, 1).receive([](int v) { BOOST_CHECK_EQUAL(v, 16); }, ERROR_HANDLER);
}

BOOST_AUTO_TEST_SUITE_END()