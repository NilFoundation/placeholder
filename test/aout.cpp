//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE aout

#include "core_test.hpp"

#include <nil/actor/all.hpp>

using namespace nil::actor;

using std::endl;

namespace {

    constexpr const char *global_redirect = ":test";
    constexpr const char *local_redirect = ":test2";

    constexpr const char *chatty_line = "hi there!:)";
    constexpr const char *chattier_line = "hello there, fellow friend!:)";

    void chatty_actor(event_based_actor *self) {
        aout(self) << chatty_line << endl;
    }

    void chattier_actor(event_based_actor *self, const std::string &fn) {
        aout(self) << chatty_line << endl;
        actor_ostream::redirect(self, fn);
        aout(self) << chattier_line << endl;
    }

    struct fixture {
        fixture() : system(cfg) {
            // nop
        }

        spawner_config cfg;
        spawner system;
        scoped_actor self {system, true};
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(adapter_tests, fixture)

BOOST_AUTO_TEST_CASE(redirect_aout_globally) {
    self->join(system.groups().get_local(global_redirect));
    actor_ostream::redirect_all(system, global_redirect);
    system.spawn(chatty_actor);
    self->receive([](const std::string &virtual_file, std::string &line) {
        // drop trailing '\n'
        if (!line.empty())
            line.pop_back();
        BOOST_CHECK_EQUAL(virtual_file, ":test");
        BOOST_CHECK_EQUAL(line, chatty_line);
    });
    self->await_all_other_actors_done();
    BOOST_CHECK_EQUAL(self->mailbox().size(), 0u);
}

BOOST_AUTO_TEST_CASE(global_and_local_redirect) {
    self->join(system.groups().get_local(global_redirect));
    self->join(system.groups().get_local(local_redirect));
    actor_ostream::redirect_all(system, global_redirect);
    system.spawn(chatty_actor);
    system.spawn(chattier_actor, local_redirect);
    std::vector<std::pair<std::string, std::string>> expected {
        {":test", chatty_line}, {":test", chatty_line}, {":test2", chattier_line}};
    std::vector<std::pair<std::string, std::string>> lines;
    int i = 0;
    self->receive_for(i, 3)([&](std::string &virtual_file, std::string &line) {
        // drop trailing '\n'
        if (!line.empty())
            line.pop_back();
        lines.emplace_back(std::move(virtual_file), std::move(line));
    });
    BOOST_CHECK(std::is_permutation(lines.begin(), lines.end(), expected.begin()));
    self->await_all_other_actors_done();
    BOOST_CHECK_EQUAL(self->mailbox().size(), 0u);
}

BOOST_AUTO_TEST_SUITE_END()
