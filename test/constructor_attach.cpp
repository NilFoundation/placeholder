//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE constructor_attach_test

#include <boost/test/unit_test.hpp>

#include <nil/actor/all.hpp>
#include <nil/actor/config.hpp>

using namespace nil::actor;

namespace {

    using die_atom = atom_constant<atom("die")>;
    using done_atom = atom_constant<atom("done")>;

    class testee : public event_based_actor {
    public:
        testee(actor_config &cfg, actor buddy) : event_based_actor(cfg) {
            attach_functor([=](const error &reason) { send(buddy, done_atom::value, reason); });
        }

        behavior make_behavior() override {
            return {[=](die_atom) { quit(exit_reason::user_shutdown); }};
        }
    };

    class actor_spawner : public event_based_actor {
    public:
        actor_spawner(actor_config &cfg) : event_based_actor(cfg), downs_(0), testee_(spawn<testee, monitored>(this)) {
            set_down_handler([=](down_msg &msg) {
                BOOST_CHECK(msg.reason == exit_reason::user_shutdown);
                BOOST_CHECK(msg.source == testee_.address());
                if (++downs_ == 2) {
                    quit(msg.reason);
                }
            });
        }

        behavior make_behavior() override {
            return {[=](done_atom, const error &reason) {
                        BOOST_CHECK(reason == exit_reason::user_shutdown);
                        if (++downs_ == 2) {
                            quit(reason);
                        }
                    },
                    [=](die_atom x) { return delegate(testee_, x); }};
        }

        void on_exit() override {
            destroy(testee_);
        }

    private:
        int downs_;
        actor testee_;
    };

}    // namespace

BOOST_AUTO_TEST_CASE(constructor_attach_test) {
    spawner_config cfg;
    spawner system {cfg};
    anon_send(system.spawn<actor_spawner>(), die_atom::value);
}