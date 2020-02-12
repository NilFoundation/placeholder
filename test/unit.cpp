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

#define BOOST_TEST_MODULE unit_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <nil/actor/spawner.hpp>
#include <nil/actor/spawner_config.hpp>
#include <nil/actor/atom.hpp>
#include <nil/actor/event_based_actor.hpp>
#include <nil/actor/scoped_actor.hpp>
#include <nil/actor/unit.hpp>

using namespace nil::actor;

using unit_res_atom = atom_constant<atom("unitRes")>;
using void_res_atom = atom_constant<atom("voidRes")>;
using unit_raw_atom = atom_constant<atom("unitRaw")>;
using void_raw_atom = atom_constant<atom("voidRaw")>;
using typed_unit_atom = atom_constant<atom("typedUnit")>;

behavior testee(event_based_actor *self) {
    return {[](unit_res_atom) -> result<unit_t> { return unit; }, [](void_res_atom) -> result<void> { return {}; },
            [](unit_raw_atom) -> unit_t { return unit; }, [](void_raw_atom) -> void {},
            [=](typed_unit_atom) -> result<unit_t> {
                auto rp = self->make_response_promise<unit_t>();
                rp.deliver(unit);
                return rp;
            }};
}

BOOST_AUTO_TEST_CASE(unit_results_test) {
    spawner_config cfg;
    spawner sys {cfg};
    scoped_actor self {sys};
    auto aut = sys.spawn(testee);
    atom_value as[] = {unit_res_atom::value, void_res_atom::value, unit_raw_atom::value, void_raw_atom::value,
                       typed_unit_atom::value};
    for (auto a : as) {
        self->request(aut, infinite, a)
            .receive([&] { BOOST_TEST_MESSAGE("actor under test correctly replied to " << to_string(a)); },
                     [&](const error &) { BOOST_FAIL("actor under test failed at input " << to_string(a)); });
    }
}
