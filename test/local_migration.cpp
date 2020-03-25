//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE local_migration_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <nil/actor/config.hpp>

/* --- "disabled" (see #199) ---

#include <nil/actor/all.hpp>

#include <nil/actor/actor_registry.hpp>

using namespace nil::actor;

using std::endl;

namespace {

struct migratable_state {
  int value = 0;
  static const char* name;
};

const char* migratable_state::name = "migratable_actor";

template <class Processor>
void serialize(Processor& proc, migratable_state& x, const unsigned int) {
  proc & x.value;
}

struct migratable_actor : stateful_actor<migratable_state> {
  migratable_actor(actor_config& cfg) : stateful_actor<migratable_state>(cfg) {
    // nop
  }

  behavior make_behavior() override {
    return {
      [=](get_atom) {
        return state.value;
      },
      [=](put_atom, int value) {
        state.value = value;
      }
    };
  }
};

// always migrates to `dest`
behavior pseudo_mm(event_based_actor* self, const actor& dest) {
  return {
    [=](migrate_atom, const std::string& name, std::vector<char>& buf) {
      BOOST_CHECK(name == "migratable_actor");
      self->delegate(dest, sys_atom::value, migrate_atom::value,
                     std::move(buf));
    }
  };
}

} // namespace <anonymous>

BOOST_AUTO_TEST_CASE(migrate_locally_test) {
  spawner system;
  auto a = system.spawn<migratable_actor>();
  auto b = system.spawn<migratable_actor>();
  auto mm1 = system.spawn(pseudo_mm, b);
  { // Lifetime scope of scoped_actor
    scoped_actor self{system};
    self->send(a, put_atom::value, 42);
    // migrate from a to b
    self->request(a, infinite, sys_atom::value,
                  migrate_atom::value, mm1).receive(
      [&](ok_atom, const actor_addr& dest) {
        BOOST_CHECK(dest == b);
      }
    );
    self->request(a, infinite, get_atom::value).receive(
      [&](int result) {
        BOOST_CHECK(result == 42);
        BOOST_CHECK(self->current_sender() == b.address());
      }
    );
    auto mm2 = system.spawn(pseudo_mm, a);
    self->send(b, put_atom::value, 23);
    // migrate back from b to a
    self->request(b, infinite, sys_atom::value,
                  migrate_atom::value, mm2).receive(
      [&](ok_atom, const actor_addr& dest) {
        BOOST_CHECK(dest == a);
      }
    );
    self->request(b, infinite, get_atom::value).receive(
      [&](int result) {
        BOOST_CHECK(result == 23);
        BOOST_CHECK(self->current_sender() == a.address());
      }
    );
    self->send_exit(a, exit_reason::kill);
    self->send_exit(b, exit_reason::kill);
    self->send_exit(mm1, exit_reason::kill);
    self->send_exit(mm2, exit_reason::kill);
    self->await_all_other_actors_done();
  }
}
*/

BOOST_AUTO_TEST_CASE(migrate_locally_test) {
    // nop
}
