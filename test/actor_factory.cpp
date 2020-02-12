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

#define BOOST_TEST_MODULE actor_factory_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <nil/actor/all.hpp>
#include <nil/actor/config.hpp>
#include <nil/actor/actor_registry.hpp>

using namespace nil::actor;

using std::endl;

namespace {

    using down_atom = atom_constant<atom("down")>;

    struct fixture {
        spawner_config cfg;

        void test_spawn(message args, bool expect_fail = false) {
            spawner system {cfg};
            scoped_actor self {system};
            BOOST_TEST_MESSAGE("set aut");
            strong_actor_ptr res;
            std::set<std::string> ifs;
            scoped_execution_unit context {&system};
            actor_config actor_cfg {&context};
            auto aut = system.spawn<actor>("test_actor", std::move(args));
            if (expect_fail) {
                BOOST_REQUIRE(!aut);
                return;
            }
            BOOST_REQUIRE(aut);
            self->wait_for(*aut);
            BOOST_TEST_MESSAGE("aut done");
        }
    };

    struct test_actor_no_args : event_based_actor {
        using event_based_actor::event_based_actor;
    };

    struct test_actor_one_arg : event_based_actor {
        test_actor_one_arg(actor_config &conf, int value) : event_based_actor(conf) {
            BOOST_CHECK_EQUAL(value, 42);
        }
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(add_actor_type_tests, fixture)

BOOST_AUTO_TEST_CASE(fun_no_args_test) {
    auto test_actor_one_arg = [] { BOOST_TEST_MESSAGE("inside test_actor"); };
    cfg.add_actor_type("test_actor", test_actor_one_arg);
    test_spawn(make_message());
    BOOST_TEST_MESSAGE("test_spawn done");
}

BOOST_AUTO_TEST_CASE(fun_no_args_selfptr_test) {
    auto test_actor_one_arg = [](event_based_actor *) { BOOST_TEST_MESSAGE("inside test_actor"); };
    cfg.add_actor_type("test_actor", test_actor_one_arg);
    test_spawn(make_message());
}

BOOST_AUTO_TEST_CASE(fun_one_arg_test) {
    auto test_actor_one_arg = [](int i) { BOOST_CHECK_EQUAL(i, 42); };
    cfg.add_actor_type("test_actor", test_actor_one_arg);
    test_spawn(make_message(42));
}

BOOST_AUTO_TEST_CASE(fun_one_arg_selfptr_test) {
    auto test_actor_one_arg = [](event_based_actor *, int i) { BOOST_CHECK_EQUAL(i, 42); };
    cfg.add_actor_type("test_actor", test_actor_one_arg);
    test_spawn(make_message(42));
}

BOOST_AUTO_TEST_CASE(class_no_arg_invalid_test) {
    cfg.add_actor_type<test_actor_no_args>("test_actor");
    test_spawn(make_message(42), true);
}

BOOST_AUTO_TEST_CASE(class_no_arg_valid_test) {
    cfg.add_actor_type<test_actor_no_args>("test_actor");
    test_spawn(make_message());
}

BOOST_AUTO_TEST_CASE(class_one_arg_invalid_test) {
    cfg.add_actor_type<test_actor_one_arg, const int &>("test_actor");
    test_spawn(make_message(), true);
}

BOOST_AUTO_TEST_CASE(class_one_arg_valid_test) {
    cfg.add_actor_type<test_actor_one_arg, const int &>("test_actor");
    test_spawn(make_message(42));
}

BOOST_AUTO_TEST_SUITE_END()
