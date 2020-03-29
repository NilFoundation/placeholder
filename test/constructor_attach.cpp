//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE constructor_attach

#include <nil/actor/all.hpp>

#include "core-test.hpp"

using namespace nil::actor;

namespace {

    class testee : public event_based_actor {
    public:
        testee(actor_config &cfg, actor buddy) : event_based_actor(cfg) {
            attach_functor([=](const error &rsn) { send(buddy, ok_atom_v, rsn); });
        }

        behavior make_behavior() override {
            return {
                [=](delete_atom) { quit(exit_reason::user_shutdown); },
            };
        }
    };

    class spawner : public event_based_actor {
    public:
        spawner(actor_config &cfg) : event_based_actor(cfg), downs_(0), testee_(spawn<testee, monitored>(this)) {
            set_down_handler([=](down_msg &msg) {
                BOOST_CHECK_EQUAL(msg.reason, exit_reason::user_shutdown);
                BOOST_CHECK_EQUAL(msg.source, testee_.address());
                if (++downs_ == 2)
                    quit(msg.reason);
            });
        }

        behavior make_behavior() override {
            return {
                [=](ok_atom, const error &reason) {
                    BOOST_CHECK_EQUAL(reason, exit_reason::user_shutdown);
                    if (++downs_ == 2) {
                        quit(reason);
                    }
                },
                [=](delete_atom x) { return delegate(testee_, x); },
            };
        }

        void on_exit() override {
            destroy(testee_);
        }

    private:
        int downs_;
        actor testee_;
    };

}    // namespace

BOOST_AUTO_TEST_CASE(constructor_attach) {
    spawner_config cfg;
    spawner system {cfg};
    anon_send(system.spawn<spawner>(), delete_atom_v);
}
