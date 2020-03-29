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

#include <nil/actor/config.hpp>
#include <nil/actor/detail/parser/add_ascii.hpp>
#include <nil/actor/detail/parser/chars.hpp>
#include <nil/actor/detail/parser/is_char.hpp>
#include <nil/actor/detail/parser/is_digit.hpp>
#include <nil/actor/detail/parser/sub_ascii.hpp>
#include <nil/actor/detail/scope_guard.hpp>
#include <nil/actor/ipv4_address.hpp>
#include <nil/actor/pec.hpp>

ACTOR_PUSH_UNUSED_LABEL_WARNING

#include <nil/actor/detail/parser/fsm.hpp>

namespace nil::actor::detail::parser {

    struct read_ipv4_octet_consumer {
        std::array<uint8_t, 4> bytes;
        size_t octets = 0;

        void value(uint8_t octet) {
            bytes[octets++] = octet;
        }
    };

    template<class State, class Consumer>
    void read_ipv4_octet(State &ps, Consumer &consumer) {
        uint8_t res = 0;
        // Reads the a decimal place.
        auto rd_decimal = [&](char c) { return add_ascii<10>(res, c); };
        // Computes the result on success.
        auto g = nil::actor::detail::make_scope_guard([&] {
            if (ps.code <= pec::trailing_character)
                consumer.value(res);
        });
        // clang-format off
  start();
  state(init) {
    transition(read, decimal_chars, rd_decimal(ch), pec::integer_overflow)
  }
  term_state(read) {
    transition(read, decimal_chars, rd_decimal(ch), pec::integer_overflow)
  }
  fin();
        // clang-format on
    }

    /// Reads a number, i.e., on success produces either an `int64_t` or a
    /// `double`.
    template<class State, class Consumer>
    void read_ipv4_address(State &ps, Consumer &&consumer) {
        read_ipv4_octet_consumer f;
        auto g = make_scope_guard([&] {
            if (ps.code <= pec::trailing_character) {
                ipv4_address result {f.bytes};
                consumer.value(std::move(result));
            }
        });
        // clang-format off
  start();
  state(init) {
    fsm_epsilon(read_ipv4_octet(ps, f), rd_dot, decimal_chars)
  }
  state(rd_dot) {
    transition(rd_oct, '.')
  }
  state(rd_oct) {
    fsm_epsilon_if(f.octets < 3, read_ipv4_octet(ps, f), rd_dot, decimal_chars)
    fsm_epsilon_if(f.octets == 3, read_ipv4_octet(ps, f), done, decimal_chars)
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
