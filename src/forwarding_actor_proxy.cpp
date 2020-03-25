//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
//
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#include <utility>

#include <nil/actor/forwarding_actor_proxy.hpp>

#include <nil/actor/send.hpp>
#include <nil/actor/locks.hpp>
#include <nil/actor/logger.hpp>
#include <nil/actor/mailbox_element.hpp>

namespace nil {
    namespace actor {

        forwarding_actor_proxy::forwarding_actor_proxy(actor_config &cfg, actor dest) :
            actor_proxy(cfg), broker_(std::move(dest)) {
            anon_send(broker_, monitor_atom::value, ctrl());
        }

        forwarding_actor_proxy::~forwarding_actor_proxy() {
            anon_send(broker_, make_message(delete_atom::value, node(), id()));
        }

        void forwarding_actor_proxy::forward_msg(strong_actor_ptr sender, message_id mid, message msg,
                                                 const forwarding_stack *fwd) {
            ACTOR_LOG_TRACE(ACTOR_ARG(id()) << ACTOR_ARG(sender) << ACTOR_ARG(mid) << ACTOR_ARG(msg));
            if (msg.match_elements<exit_msg>())
                unlink_from(msg.get_as<exit_msg>(0).source);
            forwarding_stack tmp;
            shared_lock<detail::shared_spinlock> guard(broker_mtx_);
            if (broker_)
                broker_->enqueue(nullptr, make_message_id(),
                                 make_message(forward_atom::value, std::move(sender), fwd != nullptr ? *fwd : tmp,
                                              strong_actor_ptr {ctrl()}, mid, std::move(msg)),
                                 nullptr);
        }

        void forwarding_actor_proxy::enqueue(mailbox_element_ptr what, execution_unit *) {
            ACTOR_PUSH_AID(0);
            ACTOR_ASSERT(what);
            forward_msg(std::move(what->sender), what->mid, what->move_content_to_message(), &what->stages);
        }

        bool forwarding_actor_proxy::add_backlink(abstract_actor *x) {
            if (monitorable_actor::add_backlink(x)) {
                forward_msg(ctrl(), make_message_id(), make_message(link_atom::value, x->ctrl()));
                return true;
            }
            return false;
        }

        bool forwarding_actor_proxy::remove_backlink(abstract_actor *x) {
            if (monitorable_actor::remove_backlink(x)) {
                forward_msg(ctrl(), make_message_id(), make_message(unlink_atom::value, x->ctrl()));
                return true;
            }
            return false;
        }

        void forwarding_actor_proxy::kill_proxy(execution_unit *ctx, error rsn) {
            actor tmp;
            {    // lifetime scope of guard
                std::unique_lock<detail::shared_spinlock> guard(broker_mtx_);
                broker_.swap(tmp);    // manually break cycle
            }
            cleanup(std::move(rsn), ctx);
        }

    }    // namespace actor
}    // namespace nil
