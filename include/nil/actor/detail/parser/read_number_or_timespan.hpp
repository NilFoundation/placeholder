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

#include <chrono>
#include <cstdint>
#include <string>

#include <nil/actor/config.hpp>
#include <nil/actor/detail/parser/chars.hpp>
#include <nil/actor/detail/parser/is_char.hpp>
#include <nil/actor/detail/parser/read_number.hpp>
#include <nil/actor/detail/parser/read_timespan.hpp>
#include <nil/actor/detail/scope_guard.hpp>
#include <nil/actor/none.hpp>
#include <nil/actor/optional.hpp>
#include <nil/actor/pec.hpp>
#include <nil/actor/timestamp.hpp>
#include <nil/actor/variant.hpp>

ACTOR_PUSH_UNUSED_LABEL_WARNING

#include <nil/actor/detail/parser/fsm.hpp>

namespace nil::actor::detail::parser {

    /// Reads a number or a duration, i.e., on success produces an `int64_t`, a
    /// `double`, or a `timespan`.
    template<class State, class Consumer, class EnableRange = std::false_type>
    void read_number_or_timespan(State &ps, Consumer &consumer, EnableRange enable_range = {}) {
        using namespace std::chrono;
        struct interim_consumer {
            size_t invocations = 0;
            Consumer *outer = nullptr;
            variant<none_t, int64_t, double> interim;
            void value(int64_t x) {
                switch (++invocations) {
                    case 1:
                        interim = x;
                        break;
                    case 2:
                        ACTOR_ASSERT(holds_alternative<int64_t>(interim));
                        outer->value(get<int64_t>(interim));
                        interim = none;
                        [[fallthrough]];
                    default:
                        outer->value(x);
                }
            }
            void value(double x) {
                interim = x;
            }
        };
        interim_consumer ic;
        ic.outer = &consumer;
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
        static constexpr std::true_type enable_float = std::true_type {};
        // clang-format off
  start();
  state(init) {
    fsm_epsilon(read_number(ps, ic, enable_float, enable_range), has_number)
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

}    // namespace nil::actor::detail::parser

#include <nil/actor/detail/parser/fsm_undef.hpp>

ACTOR_POP_WARNINGS
