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

#include <nil/actor/default_attachable.hpp>

#include <nil/actor/actor.hpp>
#include <nil/actor/message.hpp>
#include <nil/actor/actor_cast.hpp>
#include <nil/actor/system_messages.hpp>

namespace nil {
    namespace actor {

        namespace {

            template<class MsgType>
            message make(abstract_actor *self, const error &reason) {
                return make_message(MsgType {self->address(), reason});
            }

        }    // namespace

        void default_attachable::actor_exited(const error &rsn, execution_unit *host) {
            ACTOR_ASSERT(observed_ != observer_);
            auto factory = type_ == monitor ? &make<down_msg> : &make<exit_msg>;
            auto observer = actor_cast<strong_actor_ptr>(observer_);
            auto observed = actor_cast<strong_actor_ptr>(observed_);
            if (observer)
                observer->enqueue(std::move(observed), make_message_id(priority_),
                                  factory(actor_cast<abstract_actor *>(observed_), rsn), host);
        }

        bool default_attachable::matches(const token &what) {
            if (what.subtype != attachable::token::observer)
                return false;
            auto &ot = *reinterpret_cast<const observe_token *>(what.ptr);
            return ot.observer == observer_ && ot.type == type_;
        }

        default_attachable::default_attachable(actor_addr observed, actor_addr observer, observe_type type,
                                               message_priority priority) :
            observed_(std::move(observed)),
            observer_(std::move(observer)), type_(type), priority_(priority) {
            // nop
        }

    }    // namespace actor
}    // namespace nil
