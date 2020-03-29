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

#include <tuple>

#include <nil/actor/fwd.hpp>
#include <nil/actor/intrusive_ptr.hpp>
#include <nil/actor/logger.hpp>
#include <nil/actor/outbound_path.hpp>
#include <nil/actor/stream_manager.hpp>

#include <nil/actor/detail/type_traits.hpp>

namespace nil {
    namespace actor {

        template<class DownstreamManager>
        class stream_source : public virtual stream_manager {
        public:
            // -- member types -----------------------------------------------------------

            using output_type = typename DownstreamManager::output_type;

            // -- constructors, destructors, and assignment operators --------------------

            stream_source(scheduled_actor *self) : stream_manager(self), out_(this) {
                // nop
            }

            bool idle() const noexcept override {
                // A source is idle if it can't make any progress on its downstream or if
                // it's not producing new data despite having credit.
                auto some_credit = [](const outbound_path &x) { return x.open_credit > 0; };
                return out_.stalled() || (out_.buffered() == 0 && out_.all_paths(some_credit));
            }

            DownstreamManager &out() override {
                return out_;
            }

            /// Creates a new output path to the current sender.
            outbound_stream_slot<output_type> add_outbound_path() {
                ACTOR_LOG_TRACE("");
                return this->add_unchecked_outbound_path<output_type>();
            }

            /// Creates a new output path to the current sender with custom handshake.
            template<class... Ts>
            outbound_stream_slot<output_type, detail::strip_and_convert_t<Ts>...>
                add_outbound_path(std::tuple<Ts...> xs) {
                ACTOR_LOG_TRACE(ACTOR_ARG(xs));
                return this->add_unchecked_outbound_path<output_type>(std::move(xs));
            }

            /// Creates a new output path to the current sender.
            template<class Handle>
            outbound_stream_slot<output_type> add_outbound_path(const Handle &next) {
                ACTOR_LOG_TRACE(ACTOR_ARG(next));
                return this->add_unchecked_outbound_path<output_type>(next);
            }

            /// Creates a new output path to the current sender with custom handshake.
            template<class Handle, class... Ts>
            outbound_stream_slot<output_type, detail::strip_and_convert_t<Ts>...>
                add_outbound_path(const Handle &next, std::tuple<Ts...> xs) {
                ACTOR_LOG_TRACE(ACTOR_ARG(next) << ACTOR_ARG(xs));
                return this->add_unchecked_outbound_path<output_type>(next, std::move(xs));
            }

        protected:
            DownstreamManager out_;
        };

        template<class DownstreamManager>
        using stream_source_ptr = intrusive_ptr<stream_source<DownstreamManager>>;

    }    // namespace actor
}    // namespace nil
