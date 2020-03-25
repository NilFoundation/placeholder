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

#include <nil/actor/config.hpp>

#include <map>
#include <mutex>
#include <atomic>
#include <stdexcept>

#include <nil/actor/atom.hpp>
#include <nil/actor/config.hpp>
#include <nil/actor/logger.hpp>
#include <nil/actor/message.hpp>
#include <nil/actor/actor_addr.hpp>
#include <nil/actor/actor_cast.hpp>
#include <nil/actor/spawner.hpp>
#include <nil/actor/abstract_actor.hpp>
#include <nil/actor/actor_registry.hpp>
#include <nil/actor/execution_unit.hpp>
#include <nil/actor/mailbox_element.hpp>
#include <nil/actor/system_messages.hpp>
#include <nil/actor/default_attachable.hpp>
#include <nil/actor/actor_control_block.hpp>

#include <nil/actor/detail/disposer.hpp>
#include <nil/actor/detail/enum_to_string.hpp>
#include <nil/actor/detail/shared_spinlock.hpp>

namespace nil {
    namespace actor {

        // exit_state_ is guaranteed to be set to 0, i.e., exit_reason::not_exited,
        // by std::atomic<> constructor

        actor_control_block *abstract_actor::ctrl() const {
            return actor_control_block::from(this);
        }

        abstract_actor::~abstract_actor() {
            // nop
        }

        void abstract_actor::on_destroy() {
            // nop
        }

        void abstract_actor::enqueue(strong_actor_ptr sender, message_id mid, message msg, execution_unit *host) {
            enqueue(make_mailbox_element(sender, mid, {}, std::move(msg)), host);
        }

        abstract_actor::abstract_actor(actor_config &cfg) : abstract_channel(cfg.flags) {
            // nop
        }

        actor_addr abstract_actor::address() const {
            return actor_addr {actor_control_block::from(this)};
        }

        std::set<std::string> abstract_actor::message_types() const {
            // defaults to untyped
            return std::set<std::string> {};
        }

        actor_id abstract_actor::id() const noexcept {
            return actor_control_block::from(this)->id();
        }

        node_id abstract_actor::node() const noexcept {
            return actor_control_block::from(this)->node();
        }

        spawner &abstract_actor::home_system() const noexcept {
            return *(actor_control_block::from(this)->home_system);
        }

        mailbox_element *abstract_actor::peek_at_next_mailbox_element() {
            return nullptr;
        }

        void abstract_actor::register_at_system() {
            if (getf(is_registered_flag))
                return;
            setf(is_registered_flag);
            home_system().registry().inc_running();
        }

        void abstract_actor::unregister_from_system() {
            if (!getf(is_registered_flag))
                return;
            unsetf(is_registered_flag);
            home_system().registry().dec_running();
        }

    }    // namespace actor
}    // namespace nil
