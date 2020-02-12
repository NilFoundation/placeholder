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

#define BOOST_TEST_MODULE serial_reply_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <nil/actor/config.hpp>
#include <nil/actor/all.hpp>

using namespace nil::actor;

namespace {

    using hi_atom = atom_constant<atom("hi")>;
    using ho_atom = atom_constant<atom("ho")>;
    using sub0_atom = atom_constant<atom("sub0")>;
    using sub1_atom = atom_constant<atom("sub1")>;
    using sub2_atom = atom_constant<atom("sub2")>;
    using sub3_atom = atom_constant<atom("sub3")>;
    using sub4_atom = atom_constant<atom("sub4")>;

}    // namespace

BOOST_AUTO_TEST_CASE(test_serial_reply_test) {
    spawner_config cfg;
    spawner system {cfg};
    auto mirror_behavior = [=](event_based_actor *self) -> behavior {
        self->set_default_handler(reflect);
        return {[] {
            // nop
        }};
    };
    auto master = system.spawn([=](event_based_actor *self) {
        BOOST_TEST_MESSAGE("ID of master: " << self->id());
        // spawn 5 mirror actors
        auto c0 = self->spawn<linked>(mirror_behavior);
        auto c1 = self->spawn<linked>(mirror_behavior);
        auto c2 = self->spawn<linked>(mirror_behavior);
        auto c3 = self->spawn<linked>(mirror_behavior);
        auto c4 = self->spawn<linked>(mirror_behavior);
        self->become([=](hi_atom) mutable {
            auto rp = self->make_response_promise();
            BOOST_TEST_MESSAGE("received 'hi there'");
            self->request(c0, infinite, sub0_atom::value).then([=](sub0_atom) mutable {
                BOOST_TEST_MESSAGE("received 'sub0'");
                self->request(c1, infinite, sub1_atom::value).then([=](sub1_atom) mutable {
                    BOOST_TEST_MESSAGE("received 'sub1'");
                    self->request(c2, infinite, sub2_atom::value).then([=](sub2_atom) mutable {
                        BOOST_TEST_MESSAGE("received 'sub2'");
                        self->request(c3, infinite, sub3_atom::value).then([=](sub3_atom) mutable {
                            BOOST_TEST_MESSAGE("received 'sub3'");
                            self->request(c4, infinite, sub4_atom::value).then([=](sub4_atom) mutable {
                                BOOST_TEST_MESSAGE("received 'sub4'");
                                rp.deliver(ho_atom::value);
                            });
                        });
                    });
                });
            });
        });
    });
    scoped_actor self {system};
    BOOST_TEST_MESSAGE("ID of main: " << self->id());
    self->request(master, infinite, hi_atom::value)
        .receive([](ho_atom) { BOOST_TEST_MESSAGE("received 'ho'"); },
                 [&](const error &err) { BOOST_ERROR("Error: " << self->system().render(err)); });
    BOOST_REQUIRE(self->mailbox().size() == 0);
}
