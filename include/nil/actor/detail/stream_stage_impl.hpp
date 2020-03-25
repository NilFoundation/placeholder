//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#pragma once

#include <nil/actor/downstream.hpp>
#include <nil/actor/logger.hpp>
#include <nil/actor/make_counted.hpp>
#include <nil/actor/outbound_path.hpp>
#include <nil/actor/sec.hpp>
#include <nil/actor/stream_manager.hpp>
#include <nil/actor/stream_stage.hpp>
#include <nil/actor/stream_stage_trait.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            template<class Driver>
            class stream_stage_impl : public Driver::stage_type {
            public:
                // -- member types -----------------------------------------------------------

                using super = typename Driver::stage_type;

                using driver_type = Driver;

                using downstream_manager_type = typename Driver::downstream_manager_type;

                using input_type = typename driver_type::input_type;

                using output_type = typename driver_type::output_type;

                // -- constructors, destructors, and assignment operators --------------------

                template<class... Ts>
                stream_stage_impl(scheduled_actor *self, Ts &&... xs) :
                    stream_manager(self), super(self), driver_(this->out_, std::forward<Ts>(xs)...) {
                    // nop
                }

                // -- implementation of virtual functions ------------------------------------

                using super::handle;

                void handle(inbound_path *, downstream_msg::batch &x) override {
                    ACTOR_LOG_TRACE(ACTOR_ARG(x));
                    using vec_type = std::vector<input_type>;
                    if (x.xs.match_elements<vec_type>()) {
                        downstream<output_type> ds {this->out_.buf()};
                        driver_.process(ds, x.xs.get_mutable_as<vec_type>(0));
                        return;
                    }
                    ACTOR_LOG_ERROR("received unexpected batch type (dropped)");
                }

                bool congested() const noexcept override {
                    return driver_.congested();
                }

                int32_t acquire_credit(inbound_path *path, int32_t desired) override {
                    return driver_.acquire_credit(path, desired);
                }

            protected:
                void finalize(const error &reason) override {
                    driver_.finalize(reason);
                }

                driver_type driver_;
            };

            template<class Driver, class... Ts>
            typename Driver::stage_ptr_type make_stream_stage(scheduled_actor *self, Ts &&... xs) {
                using impl = stream_stage_impl<Driver>;
                return make_counted<impl>(self, std::forward<Ts>(xs)...);
            }

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
