//---------------------------------------------------------------------------//
// Copyright (c) 2011-2017 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <nil/actor/none.hpp>
#include <nil/actor/stream_finalize_trait.hpp>
#include <nil/actor/stream_sink_driver.hpp>
#include <nil/actor/stream_sink_trait.hpp>

namespace nil::actor::detail {

    /// Identifies an unbound sequence of messages.
    template<class Input, class Process, class Finalize>
    class stream_sink_driver_impl final : public stream_sink_driver<Input> {
    public:
        // -- member types -----------------------------------------------------------

        using super = stream_sink_driver<Input>;

        using typename super::input_type;

        using trait = stream_sink_trait_t<Process>;

        using state_type = typename trait::state;

        template<class Init>
        stream_sink_driver_impl(Init init, Process f, Finalize fin) : process_(std::move(f)), fin_(std::move(fin)) {
            init(state_);
        }

        void process(std::vector<input_type> &xs) override {
            return trait::process::invoke(process_, state_, xs);
        }

        void finalize(const error &err) override {
            stream_finalize_trait<Finalize, state_type>::invoke(fin_, state_, err);
        }

    private:
        Process process_;
        Finalize fin_;
        state_type state_;
    };

}    // namespace nil::actor::detail