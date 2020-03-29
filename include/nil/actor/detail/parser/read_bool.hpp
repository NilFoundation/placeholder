//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <cstdint>
#include <string>

#include <nil/actor/config.hpp>
#include <nil/actor/detail/parser/chars.hpp>
#include <nil/actor/detail/parser/is_char.hpp>
#include <nil/actor/detail/scope_guard.hpp>
#include <nil/actor/pec.hpp>

ACTOR_PUSH_UNUSED_LABEL_WARNING

#include <nil/actor/detail/parser/fsm.hpp>

namespace nil::actor::detail::parser {

    /// Reads a boolean.
    template<class State, class Consumer>
    void read_bool(State &ps, Consumer &&consumer) {
        bool res = false;
        auto g = make_scope_guard([&] {
            if (ps.code <= pec::trailing_character)
                consumer.value(std::move(res));
        });
        // clang-format off
  start();
  state(init) {
    transition(has_f, 'f')
    transition(has_t, 't')
  }
  state(has_f) {
    transition(has_fa, 'a')
  }
  state(has_fa) {
    transition(has_fal, 'l')
  }
  state(has_fal) {
    transition(has_fals, 's')
  }
  state(has_fals) {
    transition(done, 'e', res = false)
  }
  state(has_t) {
    transition(has_tr, 'r')
  }
  state(has_tr) {
    transition(has_tru, 'u')
  }
  state(has_tru) {
    transition(done, 'e', res = true)
  }
  term_state(done) {
    // nop
  }
  fin();
        // clang-format on
    }

}    // namespace nil::actor::detail::parser

#include <nil/actor/detail/parser/fsm_undef.hpp>

ACTOR_POP_WARNINGS
