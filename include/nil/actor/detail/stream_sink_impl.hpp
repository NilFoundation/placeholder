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

#include <nil/actor/config.hpp>
#include <nil/actor/logger.hpp>
#include <nil/actor/make_counted.hpp>
#include <nil/actor/message_id.hpp>
#include <nil/actor/sec.hpp>
#include <nil/actor/stream_manager.hpp>
#include <nil/actor/stream_sink.hpp>

#include <nil/actor/policy/arg.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            template<class Driver>
            class stream_sink_impl : public Driver::sink_type {
            public:
                using super = typename Driver::sink_type;

                using driver_type = Driver;

                using input_type = typename driver_type::input_type;

                template<class... Ts>
                stream_sink_impl(scheduled_actor *self, Ts &&... xs) :
                    stream_manager(self), super(self), driver_(std::forward<Ts>(xs)...) {
                    // nop
                }

                using super::handle;

                void handle(inbound_path *, downstream_msg::batch &x) override {
                    ACTOR_LOG_TRACE(ACTOR_ARG(x));
                    using vec_type = std::vector<input_type>;
                    if (x.xs.match_elements<vec_type>()) {
                        driver_.process(x.xs.get_mutable_as<vec_type>(0));
                        return;
                    }
                    ACTOR_LOG_ERROR("received unexpected batch type (dropped)");
                }

                int32_t acquire_credit(inbound_path *path, int32_t desired) override {
                    return driver_.acquire_credit(path, desired);
                }

                bool congested() const noexcept override {
                    return driver_.congested();
                }

            protected:
                void finalize(const error &reason) override {
                    driver_.finalize(reason);
                }

                driver_type driver_;
            };

            template<class Driver, class... Ts>
            typename Driver::sink_ptr_type make_stream_sink(scheduled_actor *self, Ts &&... xs) {
                using impl = stream_sink_impl<Driver>;
                return make_counted<impl>(self, std::forward<Ts>(xs)...);
            }

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
