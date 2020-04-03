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

#include <vector>

#include <nil/actor/actor_cast.hpp>
#include <nil/actor/actor_clock.hpp>
#include <nil/actor/actor_control_block.hpp>
#include <nil/actor/actor_profiler.hpp>
#include <nil/actor/fwd.hpp>
#include <nil/actor/mailbox_element.hpp>
#include <nil/actor/message_id.hpp>
#include <nil/actor/no_stages.hpp>

namespace nil::actor::detail {

    template<class Self, class SelfHandle, class Handle, class... Ts>
    void profiled_send(Self *self, SelfHandle &&src, const Handle &dst, message_id msg_id,
                       std::vector<strong_actor_ptr> stages, execution_unit *context, Ts &&... xs) {
        ACTOR_IGNORE_UNUSED(self);
        if (dst) {
            auto element =
                make_mailbox_element(std::forward<SelfHandle>(src), msg_id, std::move(stages), std::forward<Ts>(xs)...);
            ACTOR_BEFORE_SENDING(self, *element);
            dst->enqueue(std::move(element), context);
        }
    }

    template<class Self, class SelfHandle, class Handle, class... Ts>
    void profiled_send(Self *self, SelfHandle &&src, const Handle &dst, actor_clock &clock,
                       actor_clock::time_point timeout, message_id msg_id, Ts &&... xs) {
        ACTOR_IGNORE_UNUSED(self);
        if (dst) {
            if constexpr (std::is_same<Handle, group>::value) {
                clock.schedule_message(timeout, dst, std::forward<SelfHandle>(src),
                                       make_message(std::forward<Ts>(xs)...));
            } else {
                auto element =
                    make_mailbox_element(std::forward<SelfHandle>(src), msg_id, no_stages, std::forward<Ts>(xs)...);
                ACTOR_BEFORE_SENDING_SCHEDULED(self, timeout, *element);
                clock.schedule_message(timeout, actor_cast<strong_actor_ptr>(dst), std::move(element));
            }
        }
    }
}    // namespace nil::actor::detail