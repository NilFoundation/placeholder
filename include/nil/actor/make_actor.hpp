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

#include <type_traits>

#include <nil/actor/actor_control_block.hpp>
#include <nil/actor/actor_storage.hpp>
#include <nil/actor/fwd.hpp>
#include <nil/actor/infer_handle.hpp>
#include <nil/actor/intrusive_ptr.hpp>
#include <nil/actor/logger.hpp>
#include <nil/actor/ref_counted.hpp>

namespace nil {
    namespace actor {

        template<class T, class R = infer_handle_from_class_t<T>, class... Ts>
        R make_actor(actor_id aid, node_id nid, spawner *sys, Ts &&... xs) {
#if ACTOR_LOG_LEVEL >= ACTOR_LOG_LEVEL_DEBUG
            actor_storage<T> *ptr = nullptr;
            if (logger::current_logger()->accepts(ACTOR_LOG_LEVEL_DEBUG, ACTOR_LOG_FLOW_COMPONENT)) {
                std::string args;
                args = deep_to_string(std::forward_as_tuple(xs...));
                ptr = new actor_storage<T>(aid, std::move(nid), sys, std::forward<Ts>(xs)...);
                ACTOR_LOG_SPAWN_EVENT(ptr->data, args);
            } else {
                ptr = new actor_storage<T>(aid, std::move(nid), sys, std::forward<Ts>(xs)...);
            }
#else
            auto ptr = new actor_storage<T>(aid, std::move(nid), sys, std::forward<Ts>(xs)...);
#endif
            return {&(ptr->ctrl), false};
        }

    }    // namespace actor
}    // namespace nil
