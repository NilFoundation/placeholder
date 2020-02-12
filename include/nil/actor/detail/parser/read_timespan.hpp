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

#pragma once

#include <chrono>
#include <cstdint>
#include <string>

#include <nil/actor/config.hpp>
#include <nil/actor/detail/parser/read_signed_integer.hpp>
#include <nil/actor/detail/parser/state.hpp>
#include <nil/actor/detail/scope_guard.hpp>
#include <nil/actor/optional.hpp>
#include <nil/actor/pec.hpp>
#include <nil/actor/timestamp.hpp>

ACTOR_PUSH_UNUSED_LABEL_WARNING

#include <nil/actor/detail/parser/fsm.hpp>

namespace nil {
    namespace actor {
        namespace detail {
            namespace parser {

                /// Reads a timespan.
                template<class Iterator, class Sentinel, class Consumer>
                void read_timespan(state<Iterator, Sentinel> &ps, Consumer &&consumer, optional<int64_t> num = none) {
                    using namespace std::chrono;
                    struct interim_consumer {
                        using value_type = int64_t;

                        void value(value_type y) {
                            x = y;
                        }

                        value_type x = 0;
                    };
                    interim_consumer ic;
                    timespan result;
                    auto g = make_scope_guard([&] {
                        if (ps.code <= pec::trailing_character)
                            consumer.value(std::move(result));
                    });
                    // clang-format off
  start();
  state(init) {
    epsilon_if(num, has_integer, any_char, ic.x = *num)
    fsm_epsilon(read_signed_integer(ps, ic), has_integer)
  }
  state(has_integer) {
    transition(have_u, 'u')
    transition(have_n, 'n')
    transition(have_m, 'm')
    transition(done, 's', result = seconds(ic.x))
    transition(done, 'h', result = hours(ic.x))
  }
  state(have_u) {
    transition(done, 's', result = microseconds(ic.x))
  }
  state(have_n) {
    transition(done, 's', result = nanoseconds(ic.x))
  }
  state(have_m) {
    transition(have_mi, 'i')
    transition(done, 's', result = milliseconds(ic.x))
  }
  state(have_mi) {
    transition(done, 'n', result = minutes(ic.x))
  }
  term_state(done) {
    // nop
  }
  fin();
                    // clang-format on
                }

            }    // namespace parser
        }        // namespace detail
    }            // namespace actor
}    // namespace nil

#include <nil/actor/detail/parser/fsm_undef.hpp>

ACTOR_POP_WARNINGS
