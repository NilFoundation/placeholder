//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE stateful_actor

#include <nil/actor/stateful_actor.hpp>

#include "core_test.hpp"

#include <nil/actor/event_based_actor.hpp>

using namespace nil::actor;

using namespace std::string_literals;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<template<typename...> class P, typename... T>
            struct print_log_value<P<T...>> {
                void operator()(std::ostream &, P<T...> const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

namespace {

    using typed_adder_actor = typed_actor<reacts_to<add_atom, int>, replies_to<get_atom>::with<int>>;

    struct counter {
        int value = 0;
    };

    behavior adder(stateful_actor<counter> *self) {
        return {
            [=](add_atom, int x) { self->state.value += x; },
            [=](get_atom) { return self->state.value; },
        };
    }

    class adder_class : public stateful_actor<counter> {
    public:
        adder_class(actor_config &cfg) : stateful_actor<counter>(cfg) {
            // nop
        }

        behavior make_behavior() override {
            return adder(this);
        }
    };

    typed_adder_actor::behavior_type typed_adder(typed_adder_actor::stateful_pointer<counter> self) {
        return {
            [=](add_atom, int x) { self->state.value += x; },
            [=](get_atom) { return self->state.value; },
        };
    }

    class typed_adder_class : public typed_adder_actor::stateful_base<counter> {
    public:
        using super = typed_adder_actor::stateful_base<counter>;

        typed_adder_class(actor_config &cfg) : super(cfg) {
            // nop
        }

        behavior_type make_behavior() override {
            return typed_adder(this);
        }
    };

    struct fixture : test_coordinator_fixture<> {
        fixture() {
            // nop
        }

        template<class ActorUnderTest>
        void test_adder(ActorUnderTest aut) {
            inject((add_atom, int), from(self).to(aut).with(add_atom_v, 7));
            inject((add_atom, int), from(self).to(aut).with(add_atom_v, 4));
            inject((add_atom, int), from(self).to(aut).with(add_atom_v, 9));
            inject((get_atom), from(self).to(aut).with(get_atom_v));
            expect((int), from(aut).to(self).with(20));
        }

        template<class State>
        void test_name(const char *expected) {
            auto aut = sys.spawn([](stateful_actor<State> *self) -> behavior {
                return {
                    [=](get_atom) {
                        self->quit();
                        return self->name();
                    },
                };
            });
            inject((get_atom), from(self).to(aut).with(get_atom_v));
            expect((std::string), from(aut).to(self).with(expected));
        }
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(dynamic_stateful_actor_tests, fixture)

BOOST_AUTO_TEST_CASE(stateful_actors_can_be_dynamically_typed) {
    test_adder(sys.spawn(adder));
    test_adder(sys.spawn<typed_adder_class>());
}

BOOST_AUTO_TEST_CASE(stateful_actors_can_be_statically_typed) {
    test_adder(sys.spawn(typed_adder));
    test_adder(sys.spawn<adder_class>());
}

BOOST_AUTO_TEST_CASE(stateful_actors_without_explicit_name_use_the_name_of_the_parent) {
    struct state {
        // empty
    };
    test_name<state>("scheduled_actor");
}

BOOST_AUTO_TEST_CASE(states_with_C_string_names_override_the_default_name) {
    struct state {
        const char *name = "testee";
    };
    test_name<state>("testee");
}

BOOST_AUTO_TEST_CASE(states_with_STL_string_names_override_the_default_name) {
    struct state {
        std::string name = "testee2";
    };
    test_name<state>("testee2");
}

BOOST_AUTO_TEST_CASE(states_can_accept_constructor_arguments_and_provide_a_behavior) {
    struct state_type {
        int x;
        int y;
        state_type(int x, int y) : x(x), y(y) {
            // nop
        }
        behavior make_behavior() {
            return {
                [=](int x, int y) {
                    this->x = x;
                    this->y = y;
                },
            };
        }
    };
    using actor_type = stateful_actor<state_type>;
    auto testee = sys.spawn<actor_type>(10, 20);
    auto &state = deref<actor_type>(testee).state;
    BOOST_CHECK_EQUAL(state.x, 10);
    BOOST_CHECK_EQUAL(state.y, 20);
    inject((int, int), to(testee).with(1, 2));
    BOOST_CHECK_EQUAL(state.x, 1);
    BOOST_CHECK_EQUAL(state.y, 2);
}

BOOST_AUTO_TEST_CASE(states_optionally_take_the_self_pointer_as_first_argument) {
    struct state_type {
        event_based_actor *self;
        int x;
        const char *name = "testee";
        state_type(event_based_actor *self, int x) : self(self), x(x) {
            // nop
        }
        behavior make_behavior() {
            return {
                [=](get_atom) { return self->name(); },
            };
        }
    };
    using actor_type = stateful_actor<state_type>;
    auto testee = sys.spawn<actor_type>(10);
    auto &state = deref<actor_type>(testee).state;
    BOOST_CHECK(state.self == &deref<actor_type>(testee));
    BOOST_CHECK_EQUAL(state.x, 10);
    inject((get_atom), from(self).to(testee).with(get_atom_v));
    expect((std::string), from(testee).to(self).with("testee"s));
}

BOOST_AUTO_TEST_CASE(typed_actors_can_use_typed_actor_pointer_as_self_pointer) {
    struct state_type {
        using self_pointer = typed_adder_actor::pointer_view;
        self_pointer self;
        const char *name = "testee";
        int value;
        state_type(self_pointer self, int x) : self(self), value(x) {
            // nop
        }
        auto make_behavior() {
            return make_typed_behavior([=](add_atom, int x) { value += x; }, [=](get_atom) { return value; });
        }
    };
    using actor_type = typed_adder_actor::stateful_base<state_type>;
    auto testee = sys.spawn<actor_type>(10);
    auto &state = deref<actor_type>(testee).state;
    BOOST_CHECK(state.self == &deref<actor_type>(testee));
    BOOST_CHECK_EQUAL(state.value, 10);
    inject((add_atom, int), from(self).to(testee).with(add_atom_v, 1));
    inject((get_atom), from(self).to(testee).with(get_atom_v));
    expect((int), from(testee).to(self).with(11));
}

BOOST_AUTO_TEST_SUITE_END()
