//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE or_else

#include <nil/actor/test/dsl.hpp>

#include <nil/actor/all.hpp>

#define ERROR_HANDLER [&](error &err) { BOOST_FAIL(system.render(err)); }

using namespace nil::actor;

namespace {

    message_handler handle_a() {
        return {
            [](int8_t) { return "a"; },
        };
    }

    message_handler handle_b() {
        return {
            [](int16_t) { return "b"; },
        };
    }

    message_handler handle_c() {
        return {
            [](int32_t) { return "c"; },
        };
    }

    struct fixture {
        fixture() : mi(), system(cfg) {
            // nop
        }

        meta_initializer mi;
        spawner_config cfg;
        spawner system;

        void run_testee(const actor &testee) {
            scoped_actor self {system};
            self->request(testee, infinite, int8_t {1})
                .receive([](const std::string &str) { BOOST_CHECK_EQUAL(str, "a"); }, ERROR_HANDLER);
            self->request(testee, infinite, int16_t {1})
                .receive([](const std::string &str) { BOOST_CHECK_EQUAL(str, "b"); }, ERROR_HANDLER);
            self->request(testee, infinite, int32_t {1})
                .receive([](const std::string &str) { BOOST_CHECK_EQUAL(str, "c"); }, ERROR_HANDLER);
            self->send_exit(testee, exit_reason::user_shutdown);
        }
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(atom_tests, fixture)

BOOST_AUTO_TEST_CASE(composition1) {
    run_testee(system.spawn([=] { return handle_a().or_else(handle_b()).or_else(handle_c()); }));
}

BOOST_AUTO_TEST_CASE(composition2) {
    run_testee(system.spawn([=] { return handle_a().or_else(handle_b()).or_else([](int32_t) { return "c"; }); }));
}

BOOST_AUTO_TEST_CASE(composition3) {
    run_testee(system.spawn(
        [=] { return message_handler {[](int8_t) { return "a"; }}.or_else(handle_b()).or_else(handle_c()); }));
}

BOOST_AUTO_TEST_SUITE_END()
