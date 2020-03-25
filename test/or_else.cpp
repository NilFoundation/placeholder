//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt or
// http://opensource.org/licenses/BSD-3-Clause
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE or_else_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <nil/actor/config.hpp>
#include <nil/actor/all.hpp>

#define ERROR_HANDLER [&](error &err) { BOOST_FAIL(system.render(err)); }

using namespace nil::actor;

namespace {

    using a_atom = atom_constant<atom("a")>;
    using b_atom = atom_constant<atom("b")>;
    using c_atom = atom_constant<atom("c")>;

    message_handler handle_a() {
        return [](a_atom) { return 1; };
    }

    message_handler handle_b() {
        return [](b_atom) { return 2; };
    }

    message_handler handle_c() {
        return [](c_atom) { return 3; };
    }

    struct fixture {
        fixture() : system(cfg) {
            // nop
        }

        spawner_config cfg;
        spawner system;

        void run_testee(const actor &testee) {
            scoped_actor self {system};
            self->request(testee, infinite, a_atom::value)
                .receive([](int i) { BOOST_CHECK_EQUAL(i, 1); }, ERROR_HANDLER);
            self->request(testee, infinite, b_atom::value)
                .receive([](int i) { BOOST_CHECK_EQUAL(i, 2); }, ERROR_HANDLER);
            self->request(testee, infinite, c_atom::value)
                .receive([](int i) { BOOST_CHECK_EQUAL(i, 3); }, ERROR_HANDLER);
            self->send_exit(testee, exit_reason::user_shutdown);
            self->await_all_other_actors_done();
        }
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(atom_tests, fixture)

BOOST_AUTO_TEST_CASE(composition1_test) {
    run_testee(system.spawn([=] { return handle_a().or_else(handle_b()).or_else(handle_c()); }));
}

BOOST_AUTO_TEST_CASE(composition2_test) {
    run_testee(system.spawn([=] { return handle_a().or_else(handle_b()).or_else([](c_atom) { return 3; }); }));
}

BOOST_AUTO_TEST_CASE(composition3_test) {
    run_testee(system.spawn(
        [=] { return message_handler {[](a_atom) { return 1; }}.or_else(handle_b()).or_else(handle_c()); }));
}

BOOST_AUTO_TEST_SUITE_END()
