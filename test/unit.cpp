//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE unit

#include <nil/actor/unit.hpp>

#include "core-test.hpp"

#include <nil/actor/spawner.hpp>
#include <nil/actor/spawner_config.hpp>
#include <nil/actor/event_based_actor.hpp>
#include <nil/actor/scoped_actor.hpp>

using namespace nil::actor;

behavior testee(event_based_actor *self) {
    return {
        [](add_atom) -> result<unit_t> { return unit; },
        [](get_atom) -> result<void> { return {}; },
        [](put_atom) -> unit_t { return unit; },
        [](resolve_atom) -> void {},
        [=](update_atom) -> result<unit_t> {
            auto rp = self->make_response_promise<unit_t>();
            rp.deliver(unit);
            return rp;
        },
    };
}

BOOST_AUTO_TEST_CASE(unit_results) {
    spawner_config cfg;
    spawner sys {cfg};
    scoped_actor self {sys};
    auto aut = sys.spawn(testee);
    message as[] = {
        make_message(add_atom_v),     make_message(get_atom_v),    make_message(put_atom_v),
        make_message(resolve_atom_v), make_message(update_atom_v),
    };
    for (auto a : as) {
        self->request(aut, infinite, a)
            .receive([&] { ACTOR_MESSAGE("actor under test correctly replied to " << to_string(a)); },
                     [&](const error &) { BOOST_FAIL("actor under test failed at input " << to_string(a)); });
    }
}
