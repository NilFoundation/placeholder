//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
//
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE stateful_actor_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <nil/actor/config.hpp>
#include <nil/actor/all.hpp>

#define ERROR_HANDLER [&](error &err) { BOOST_FAIL(system.render(err)); }

using namespace std;
using namespace nil::actor;

namespace {

    using typed_adder_actor = typed_actor<reacts_to<add_atom, int>, replies_to<get_atom>::with<int>>;

    struct counter {
        int value = 0;
        local_actor *self_;
    };

    behavior adder(stateful_actor<counter> *self) {
        return {[=](add_atom, int x) { self->state.value += x; }, [=](get_atom) { return self->state.value; }};
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
        return {[=](add_atom, int x) { self->state.value += x; }, [=](get_atom) { return self->state.value; }};
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

    struct fixture {
        spawner_config cfg;
        spawner system;

        fixture() : system(cfg) {
            // nop
        }

        template<class ActorUnderTest>
        void test_adder(ActorUnderTest aut) {
            scoped_actor self {system};
            self->send(aut, add_atom::value, 7);
            self->send(aut, add_atom::value, 4);
            self->send(aut, add_atom::value, 9);
            self->request(aut, infinite, get_atom::value)
                .receive([](int x) { BOOST_CHECK_EQUAL(x, 20); }, ERROR_HANDLER);
        }

        template<class State>
        void test_name(const char *expected) {
            auto aut = system.spawn([](stateful_actor<State> *self) -> behavior {
                return [=](get_atom) {
                    self->quit();
                    return self->name();
                };
            });
            scoped_actor self {system};
            self->request(aut, infinite, get_atom::value)
                .receive([&](const string &str) { BOOST_CHECK_EQUAL(str, expected); }, ERROR_HANDLER);
        }
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(dynamic_stateful_actor_tests, fixture)

BOOST_AUTO_TEST_CASE(dynamic_stateful_actor_test) {
    BOOST_REQUIRE(monitored + monitored == monitored);
    test_adder(system.spawn(adder));
}

BOOST_AUTO_TEST_CASE(typed_stateful_actor_test) {
    test_adder(system.spawn(typed_adder));
}

BOOST_AUTO_TEST_CASE(dynamic_stateful_actor_class_test) {
    test_adder(system.spawn<adder_class>());
}

BOOST_AUTO_TEST_CASE(typed_stateful_actor_class_test) {
    test_adder(system.spawn<typed_adder_class>());
}

BOOST_AUTO_TEST_CASE(no_name_test) {
    struct state {
        // empty
    };
    test_name<state>("scheduled_actor");
}

BOOST_AUTO_TEST_CASE(char_name_test) {
    struct state {
        const char *name = "testee";
    };
    test_name<state>("testee");
}

BOOST_AUTO_TEST_CASE(string_name_test) {
    struct state {
        string name = "testee2";
    };
    test_name<state>("testee2");
}

BOOST_AUTO_TEST_SUITE_END()
