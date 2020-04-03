//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <nil/actor/detail/stream_sink_driver_impl.hpp>
#include <nil/actor/detail/stream_sink_impl.hpp>
#include <nil/actor/fwd.hpp>
#include <nil/actor/make_sink_result.hpp>
#include <nil/actor/policy/arg.hpp>
#include <nil/actor/stream.hpp>
#include <nil/actor/stream_sink.hpp>

namespace nil {
    namespace actor {

        /// Attaches a new stream sink to `self` by creating a default stream sink /
        /// manager from given callbacks.
        /// @param self Points to the hosting actor.
        /// @param xs Additional constructor arguments for `Driver`.
        /// @returns The new `stream_manager`, an inbound slot, and an outbound slot.
        template<class Driver, class... Ts>
        make_sink_result<typename Driver::input_type>
            attach_stream_sink(scheduled_actor *self, stream<typename Driver::input_type> in, Ts &&... xs) {
            auto mgr = detail::make_stream_sink<Driver>(self, std::forward<Ts>(xs)...);
            auto slot = mgr->add_inbound_path(in);
            return {slot, std::move(mgr)};
        }

        /// Attaches a new stream sink to `self` by creating a default stream sink
        /// manager from given callbacks.
        /// @param self Points to the hosting actor.
        /// @param in Stream handshake from upstream path.
        /// @param init Function object for initializing the state of the sink.
        /// @param fun Processing function.
        /// @param fin Optional cleanup handler.
        /// @returns The new `stream_manager` and the inbound slot.
        template<class In, class Init, class Fun, class Finalize = unit_t, class Trait = stream_sink_trait_t<Fun>>
        make_sink_result<In> attach_stream_sink(scheduled_actor *self, stream<In> in, Init init, Fun fun,
                                                Finalize fin = {}) {
            using driver = detail::stream_sink_driver_impl<In, Fun, Finalize>;
            return attach_stream_sink<driver>(self, in, std::move(init), std::move(fun), std::move(fin));
        }

    }    // namespace actor
}    // namespace nil
