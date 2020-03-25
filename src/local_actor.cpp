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

#include <nil/actor/local_actor.hpp>

#include <string>
#include <condition_variable>

#include <nil/actor/sec.hpp>
#include <nil/actor/atom.hpp>
#include <nil/actor/logger.hpp>
#include <nil/actor/scheduler.hpp>
#include <nil/actor/resumable.hpp>
#include <nil/actor/actor_cast.hpp>
#include <nil/actor/exit_reason.hpp>
#include <nil/actor/spawner.hpp>
#include <nil/actor/actor_ostream.hpp>
#include <nil/actor/serialization/binary_serializer.hpp>
#include <nil/actor/default_attachable.hpp>
#include <nil/actor/serialization/binary_deserializer.hpp>

namespace nil {
    namespace actor {

        local_actor::local_actor(actor_config &cfg) :
            monitorable_actor(cfg), context_(cfg.host), current_element_(nullptr),
            initial_behavior_fac_(std::move(cfg.init_fun)) {
            // nop
        }

        local_actor::~local_actor() {
            // nop
        }

        void local_actor::on_destroy() {
            ACTOR_PUSH_AID_FROM_PTR(this);
            if (!getf(is_cleaned_up_flag)) {
                on_exit();
                cleanup(exit_reason::unreachable, nullptr);
                monitorable_actor::on_destroy();
            }
        }

        void local_actor::request_response_timeout(const duration &d, message_id mid) {
            ACTOR_LOG_TRACE(ACTOR_ARG(d) << ACTOR_ARG(mid));
            if (!d.valid())
                return;
            auto t = clock().now();
            t += d;
            clock().set_request_timeout(t, this, mid.response_id());
        }

        void local_actor::monitor(abstract_actor *ptr, message_priority priority) {
            if (ptr != nullptr)
                ptr->attach(default_attachable::make_monitor(ptr->address(), address(), priority));
        }

        void local_actor::demonitor(const actor_addr &whom) {
            ACTOR_LOG_TRACE(ACTOR_ARG(whom));
            auto ptr = actor_cast<strong_actor_ptr>(whom);
            if (ptr) {
                default_attachable::observe_token tk {address(), default_attachable::monitor};
                ptr->get()->detach(tk);
            }
        }

        void local_actor::on_exit() {
            // nop
        }

        message_id local_actor::new_request_id(message_priority mp) {
            auto result = ++last_request_id_;
            return mp == message_priority::normal ? result : result.with_high_priority();
        }

        void local_actor::send_exit(const actor_addr &whom, error reason) {
            send_exit(actor_cast<strong_actor_ptr>(whom), std::move(reason));
        }

        void local_actor::send_exit(const strong_actor_ptr &dest, error reason) {
            if (!dest)
                return;
            dest->get()->eq_impl(make_message_id(), nullptr, context(), exit_msg {address(), std::move(reason)});
        }

        const char *local_actor::name() const {
            return "actor";
        }

        error local_actor::save_state(serializer &, const unsigned int) {
            ACTOR_RAISE_ERROR("local_actor::serialize called");
        }

        error local_actor::load_state(deserializer &, const unsigned int) {
            ACTOR_RAISE_ERROR("local_actor::deserialize called");
        }

        void local_actor::initialize() {
            ACTOR_LOG_TRACE(ACTOR_ARG2("id", id()) << ACTOR_ARG2("name", name()));
        }

        bool local_actor::cleanup(error &&fail_state, execution_unit *host) {
            ACTOR_LOG_TRACE(ACTOR_ARG(fail_state));
            // tell registry we're done
            unregister_from_system();
            ACTOR_LOG_TERMINATE_EVENT(this, fail_state);
            monitorable_actor::cleanup(std::move(fail_state), host);
            clock().cancel_timeouts(this);
            return true;
        }

    }    // namespace actor
}    // namespace nil
