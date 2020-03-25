//---------------------------------------------------------------------------//
// Copyright (c) 2011-2017 Dominik Charousset
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <nil/actor/stream_finalize_trait.hpp>
#include <nil/actor/stream_slot.hpp>
#include <nil/actor/stream_stage_driver.hpp>
#include <nil/actor/stream_stage_trait.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            /// Default implementation for a `stream_stage_driver` that hardwires `message`
            /// as result type and implements `process` and `finalize` using user-provided
            /// function objects (usually lambdas).
            template<class Input, class DownstreamManager, class Process, class Finalize>
            class stream_stage_driver_impl final : public stream_stage_driver<Input, DownstreamManager> {
            public:
                // -- member types -----------------------------------------------------------

                using super = stream_stage_driver<Input, DownstreamManager>;

                using typename super::input_type;

                using typename super::output_type;

                using typename super::stream_type;

                using trait = stream_stage_trait_t<Process>;

                using state_type = typename trait::state;

                template<class Init>
                stream_stage_driver_impl(DownstreamManager &out, Init init, Process f, Finalize fin) :
                    super(out), process_(std::move(f)), fin_(std::move(fin)) {
                    init(state_);
                }

                void process(downstream<output_type> &out, std::vector<input_type> &batch) override {
                    trait::process::invoke(process_, state_, out, batch);
                }

                void finalize(const error &err) override {
                    stream_finalize_trait<Finalize, state_type>::invoke(fin_, state_, err);
                }

            private:
                state_type state_;
                Process process_;
                Finalize fin_;
            };

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
