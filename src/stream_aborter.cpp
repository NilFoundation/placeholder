//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#include <nil/actor/stream_aborter.hpp>

#include <nil/actor/actor.hpp>
#include <nil/actor/actor_cast.hpp>
#include <nil/actor/downstream_msg.hpp>
#include <nil/actor/logger.hpp>
#include <nil/actor/message.hpp>
#include <nil/actor/no_stages.hpp>
#include <nil/actor/system_messages.hpp>
#include <nil/actor/upstream_msg.hpp>

namespace nil {
    namespace actor {

        stream_aborter::~stream_aborter() {
            // nop
        }

        void stream_aborter::actor_exited(const error &rsn, execution_unit *host) {
            ACTOR_ASSERT(observed_ != observer_);
            auto observer = actor_cast<strong_actor_ptr>(observer_);
            if (observer != nullptr) {
                stream_slots slots {0, slot_};
                mailbox_element_ptr ptr;
                if (mode_ == source_aborter) {
                    using msg_type = downstream_msg::forced_close;
                    ptr = make_mailbox_element(nullptr, make_message_id(), no_stages,
                                               nil::actor::make<msg_type>(slots, observed_, rsn));
                } else {
                    using msg_type = upstream_msg::forced_drop;
                    ptr = make_mailbox_element(nullptr, make_message_id(), no_stages,
                                               nil::actor::make<msg_type>(slots, observed_, rsn));
                }
                observer->enqueue(std::move(ptr), host);
            }
        }

        bool stream_aborter::matches(const attachable::token &what) {
            if (what.subtype != attachable::token::stream_aborter)
                return false;
            auto &ot = *reinterpret_cast<const token *>(what.ptr);
            return ot.observer == observer_ && ot.slot == slot_;
        }

        stream_aborter::stream_aborter(actor_addr &&observed, actor_addr &&observer, stream_slot slot, mode m) :
            observed_(std::move(observed)), observer_(std::move(observer)), slot_(slot), mode_(m) {
            // nop
        }

        void stream_aborter::add(strong_actor_ptr observed, actor_addr observer, stream_slot slot, mode m) {
            ACTOR_LOG_TRACE(ACTOR_ARG(observed) << ACTOR_ARG(observer) << ACTOR_ARG(slot));
            auto ptr = make_stream_aborter(observed->address(), std::move(observer), slot, m);
            observed->get()->attach(std::move(ptr));
        }

        void stream_aborter::del(strong_actor_ptr observed, const actor_addr &observer, stream_slot slot, mode m) {
            ACTOR_LOG_TRACE(ACTOR_ARG(observed) << ACTOR_ARG(observer) << ACTOR_ARG(slot));
            token tk {observer, slot, m};
            observed->get()->detach(tk);
        }

        attachable_ptr make_stream_aborter(actor_addr observed, actor_addr observer, stream_slot slot,
                                           stream_aborter::mode m) {
            return attachable_ptr {new stream_aborter(std::move(observed), std::move(observer), slot, m)};
        }

    }    // namespace actor
}    // namespace nil
