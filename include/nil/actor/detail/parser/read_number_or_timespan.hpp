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
#include <nil/actor/detail/parser/chars.hpp>
#include <nil/actor/detail/parser/is_char.hpp>
#include <nil/actor/detail/parser/read_number.hpp>
#include <nil/actor/detail/parser/read_timespan.hpp>
#include <nil/actor/detail/parser/state.hpp>
#include <nil/actor/detail/scope_guard.hpp>
#include <nil/actor/none.hpp>
#include <nil/actor/optional.hpp>
#include <nil/actor/pec.hpp>
#include <nil/actor/timestamp.hpp>
#include <nil/actor/variant.hpp>

ACTOR_PUSH_UNUSED_LABEL_WARNING

#include <nil/actor/detail/parser/fsm.hpp>

namespace nil {
    namespace actor {
        namespace detail {
            namespace parser {

                /// Reads a number or a duration, i.e., on success produces an `int64_t`, a
                /// `double`, or a `timespan`.
                template<class Iterator, class Sentinel, class Consumer>
                void read_number_or_timespan(state<Iterator, Sentinel> &ps, Consumer &consumer) {
                    using namespace std::chrono;
                    struct interim_consumer {
                        variant<none_t, int64_t, double> interim;
                        void value(int64_t x) {
                            interim = x;
                        }
                        void value(double x) {
                            interim = x;
                        }
                    };
                    interim_consumer ic;
                    auto has_int = [&] { return holds_alternative<int64_t>(ic.interim); };
                    auto has_dbl = [&] { return holds_alternative<double>(ic.interim); };
                    auto get_int = [&] { return get<int64_t>(ic.interim); };
                    auto g = make_scope_guard([&] {
                        if (ps.code <= pec::trailing_character) {
                            if (has_dbl())
                                consumer.value(get<double>(ic.interim));
                            else if (has_int())
                                consumer.value(get_int());
                        }
                    });
                    // clang-format off
  start();
  state(init) {
    fsm_epsilon(read_number(ps, ic), has_number)
  }
  term_state(has_number) {
    epsilon_if(has_int(), has_integer)
    epsilon_if(has_dbl(), has_double)
  }
  term_state(has_double) {
    error_transition(pec::fractional_timespan, "unmsh")
  }
  term_state(has_integer) {
    fsm_epsilon(read_timespan(ps, consumer, get_int()),
                done, "unmsh", g.disable())
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
