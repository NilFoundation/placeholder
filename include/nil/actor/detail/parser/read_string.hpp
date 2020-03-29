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
#include <nil/actor/detail/scope_guard.hpp>
#include <nil/actor/pec.hpp>

ACTOR_PUSH_UNUSED_LABEL_WARNING

#include <nil/actor/detail/parser/fsm.hpp>

namespace nil::actor::detail::parser {

    /// Reads a quoted or unquoted string. Quoted strings allow escaping, while
    /// unquoted strings may only include alphanumeric characters.
    template<class State, class Consumer>
    void read_string(State &ps, Consumer &&consumer) {
        std::string res;
        auto g = nil::actor::detail::make_scope_guard([&] {
            if (ps.code <= pec::trailing_character)
                consumer.value(std::move(res));
        });
        // clang-format off
  start();
  state(init) {
    transition(init, " \t")
    transition(read_chars, '"')
    transition(read_unquoted_chars, alphanumeric_chars, res += ch)
  }
  state(read_chars) {
    transition(escape, '\\')
    transition(done, '"')
    error_transition(pec::unexpected_newline, '\n')
    transition(read_chars, any_char, res += ch)
  }
  state(escape) {
    transition(read_chars, 'n', res += '\n')
    transition(read_chars, 'r', res += '\r')
    transition(read_chars, 't', res += '\t')
    transition(read_chars, '\\', res += '\\')
    transition(read_chars, '"', res += '"')
    error_transition(pec::invalid_escape_sequence)
  }
  term_state(read_unquoted_chars) {
    transition(read_unquoted_chars, alphanumeric_chars, res += ch)
    epsilon(done)
  }
  term_state(done) {
    transition(done, " \t")
  }
  fin();
        // clang-format on
    }

}    // namespace nil::actor::detail::parser

#include <nil/actor/detail/parser/fsm_undef.hpp>

ACTOR_POP_WARNINGS
