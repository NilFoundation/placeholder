//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#include <nil/actor/message_id.hpp>
#include <nil/actor/event_based_actor.hpp>

#include <nil/actor/detail/pretty_type_name.hpp>

namespace nil {
    namespace actor {

        event_based_actor::event_based_actor(actor_config &cfg) : extended_base(cfg) {
            // nop
        }

        event_based_actor::~event_based_actor() {
            // nop
        }

        void event_based_actor::initialize() {
            ACTOR_LOG_TRACE(ACTOR_ARG2("subtype", detail::pretty_type_name(typeid(*this)).c_str()));
            extended_base::initialize();
            setf(is_initialized_flag);
            auto bhvr = make_behavior();
            ACTOR_LOG_DEBUG_IF(!bhvr, "make_behavior() did not return a behavior:" << ACTOR_ARG2("alive", alive()));
            if (bhvr) {
                // make_behavior() did return a behavior instead of using become()
                ACTOR_LOG_DEBUG("make_behavior() did return a valid behavior");
                become(std::move(bhvr));
            }
        }

        behavior event_based_actor::make_behavior() {
            ACTOR_LOG_TRACE("");
            behavior res;
            if (initial_behavior_fac_) {
                res = initial_behavior_fac_(this);
                initial_behavior_fac_ = nullptr;
            }
            return res;
        }

    }    // namespace actor
}    // namespace nil
