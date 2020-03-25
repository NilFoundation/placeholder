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

#include <nil/actor/stream_manager.hpp>

#include <nil/actor/actor_addr.hpp>
#include <nil/actor/actor_cast.hpp>
#include <nil/actor/actor_control_block.hpp>
#include <nil/actor/spawner.hpp>
#include <nil/actor/spawner_config.hpp>
#include <nil/actor/error.hpp>
#include <nil/actor/expected.hpp>
#include <nil/actor/inbound_path.hpp>
#include <nil/actor/logger.hpp>
#include <nil/actor/message.hpp>
#include <nil/actor/outbound_path.hpp>
#include <nil/actor/response_promise.hpp>
#include <nil/actor/scheduled_actor.hpp>
#include <nil/actor/sec.hpp>
#include <nil/actor/type_nr.hpp>

namespace nil {
    namespace actor {

        stream_manager::stream_manager(scheduled_actor *selfptr, stream_priority prio) :
            self_(selfptr), pending_handshakes_(0), priority_(prio), flags_(0) {
            // nop
        }

        stream_manager::~stream_manager() {
            // nop
        }

        void stream_manager::handle(inbound_path *, downstream_msg::batch &) {
            ACTOR_LOG_WARNING("unimplemented base handler for batches called");
        }

        void stream_manager::handle(inbound_path *in, downstream_msg::close &) {
            // Reset the actor handle to make sure no further messages travel upstream.
            in->hdl = nullptr;
        }

        void stream_manager::handle(inbound_path *in, downstream_msg::forced_close &x) {
            ACTOR_ASSERT(in != nullptr);
            ACTOR_LOG_TRACE(ACTOR_ARG2("slots", in->slots) << ACTOR_ARG(x));
            // Reset the actor handle to make sure no further messages travel upstream.
            in->hdl = nullptr;
            // A continuous stream exists independent of sources. Hence, we ignore
            // upstream errors in this case.
            if (!continuous()) {
                stop(std::move(x.reason));
            } else {
                ACTOR_LOG_INFO("received (and ignored) forced_close from a source");
            }
        }

        bool stream_manager::handle(stream_slots slots, upstream_msg::ack_open &x) {
            ACTOR_LOG_TRACE(ACTOR_ARG(slots) << ACTOR_ARG(x));
            ACTOR_ASSERT(x.desired_batch_size > 0);
            auto ptr = out().path(slots.receiver);
            if (ptr == nullptr)
                return false;
            if (!ptr->pending()) {
                ACTOR_LOG_ERROR("received repeated ack_open");
                return false;
            }
            if (ptr->hdl != x.rebind_from) {
                ACTOR_LOG_ERROR("received ack_open with invalid rebind_from");
                return false;
            }
            if (x.rebind_from != x.rebind_to) {
                ptr->hdl = x.rebind_to;
            }
            ptr->slots.receiver = slots.sender;
            ptr->open_credit = x.initial_demand;
            ACTOR_ASSERT(ptr->open_credit >= 0);
            ptr->set_desired_batch_size(x.desired_batch_size);
            --pending_handshakes_;
            push();
            return true;
        }

        void stream_manager::handle(stream_slots slots, upstream_msg::ack_batch &x) {
            ACTOR_LOG_TRACE(ACTOR_ARG(slots) << ACTOR_ARG(x));
            ACTOR_ASSERT(x.desired_batch_size > 0);
            auto path = out().path(slots.receiver);
            if (path != nullptr) {
                path->open_credit += x.new_capacity;
                path->max_capacity = x.max_capacity;
                ACTOR_ASSERT(path->open_credit >= 0);
                ACTOR_ASSERT(path->max_capacity >= 0);
                path->set_desired_batch_size(x.desired_batch_size);
                path->next_ack_id = x.acknowledged_id + 1;
                // Gravefully remove path after receiving its final ACK.
                if (path->closing && out().clean(slots.receiver))
                    out().remove_path(slots.receiver, none, false);
                push();
            }
        }

        void stream_manager::handle(stream_slots slots, upstream_msg::drop &) {
            out().close(slots.receiver);
        }

        void stream_manager::handle(stream_slots slots, upstream_msg::forced_drop &x) {
            if (out().remove_path(slots.receiver, x.reason, true))
                stop(std::move(x.reason));
        }

        void stream_manager::stop(error reason) {
            if (reason)
                out().abort(reason);
            else
                out().close();
            finalize(reason);
            self_->erase_inbound_paths_later(this, std::move(reason));
        }

        void stream_manager::shutdown() {
            ACTOR_LOG_TRACE("");
            // Mark as shutting down and reset other flags.
            if (shutting_down())
                return;
            flags_ = is_shutting_down_flag;
            ACTOR_LOG_DEBUG("emit shutdown messages on" << inbound_paths_.size() << "inbound paths;"
                                                      << ACTOR_ARG2("out.clean", out().clean())
                                                      << ACTOR_ARG2("out.paths", out().num_paths()));
            for (auto ipath : inbound_paths_)
                ipath->emit_regular_shutdown(self_);
        }

        void stream_manager::advance() {
            ACTOR_LOG_TRACE("");
            // Try to emit more credit.
            if (!inbound_paths_.empty()) {
                auto now = self_->clock().now();
                auto &cfg = self_->system().config();
                auto bc = cfg.stream_desired_batch_complexity;
                auto interval = cfg.stream_credit_round_interval;
                auto &qs = self_->get_downstream_queue().queues();
                // Iterate all queues for inbound traffic.
                for (auto &kvp : qs) {
                    auto inptr = kvp.second.policy().handler.get();
                    // Ignore inbound paths of other managers.
                    if (inptr->mgr.get() == this) {
                        auto bs = static_cast<int32_t>(kvp.second.total_task_size());
                        inptr->emit_ack_batch(self_, bs, out().max_capacity(), now, interval, bc);
                    }
                }
            }
            // Try to generate more batches.
            push();
        }

        void stream_manager::push() {
            ACTOR_LOG_TRACE("");
            do {
                out().emit_batches();
            } while (generate_messages());
        }

        bool stream_manager::congested() const noexcept {
            return false;
        }

        void stream_manager::deliver_handshake(response_promise &rp, stream_slot slot, message handshake) {
            ACTOR_LOG_TRACE(ACTOR_ARG(rp) << ACTOR_ARG(slot) << ACTOR_ARG(handshake));
            ACTOR_ASSERT(rp.pending());
            ACTOR_ASSERT(slot != invalid_stream_slot);
            ++pending_handshakes_;
            auto next = rp.next();
            rp.deliver(open_stream_msg {slot, std::move(handshake), self_->ctrl(), next, priority_});
        }

        bool stream_manager::generate_messages() {
            return false;
        }

        const downstream_manager &stream_manager::out() const {
            // We restore the const when returning from this member function.
            return const_cast<stream_manager *>(this)->out();
        }

        void stream_manager::cycle_timeout(size_t) {
            // TODO: make pure virtual
        }

        void stream_manager::register_input_path(inbound_path *ptr) {
            ACTOR_ASSERT(ptr != nullptr);
            ACTOR_LOG_TRACE(ACTOR_ARG2("path", *ptr));
            inbound_paths_.emplace_back(ptr);
        }

        void stream_manager::deregister_input_path(inbound_path *ptr) noexcept {
            ACTOR_ASSERT(ptr != nullptr);
            ACTOR_LOG_TRACE(ACTOR_ARG2("path", *ptr));
            ACTOR_ASSERT(inbound_paths_.size() > 0);
            using std::swap;
            if (ptr != inbound_paths_.back()) {
                auto i = std::find(inbound_paths_.begin(), inbound_paths_.end(), ptr);
                ACTOR_ASSERT(i != inbound_paths_.end());
                swap(*i, inbound_paths_.back());
            }
            inbound_paths_.pop_back();
            ACTOR_LOG_DEBUG(inbound_paths_.size() << "paths remaining");
        }

        void stream_manager::remove_input_path(stream_slot slot, error reason, bool silent) {
            if (silent)
                self_->erase_inbound_path_later(slot);
            else
                self_->erase_inbound_path_later(slot, std::move(reason));
        }

        inbound_path *stream_manager::get_inbound_path(stream_slot x) const noexcept {
            auto pred = [=](inbound_path *ptr) { return ptr->slots.receiver == x; };
            auto e = inbound_paths_.end();
            auto i = std::find_if(inbound_paths_.begin(), e, pred);
            return i != e ? *i : nullptr;
        }

        bool stream_manager::inbound_paths_idle() const noexcept {
            auto f = [](inbound_path *x) { return x->up_to_date() && x->assigned_credit > 0; };
            return std::all_of(inbound_paths_.begin(), inbound_paths_.end(), f);
        }

        int32_t stream_manager::acquire_credit(inbound_path *, int32_t desired) {
            return desired;
        }

        stream_slot stream_manager::add_unchecked_outbound_path_impl(response_promise &rp, message handshake) {
            ACTOR_LOG_TRACE(ACTOR_ARG(rp) << ACTOR_ARG(handshake));
            ACTOR_ASSERT(out().terminal() == false);
            if (!rp.pending()) {
                ACTOR_LOG_WARNING("add_outbound_path called with next == nullptr");
                rp.deliver(sec::no_downstream_stages_defined);
                return invalid_stream_slot;
            }
            auto slot = self_->assign_next_pending_slot_to(this);
            auto path = out().add_path(slot, rp.next());
            ACTOR_IGNORE_UNUSED(path);
            ACTOR_ASSERT(path != nullptr);
            // Build pipeline by forwarding handshake along the path.
            deliver_handshake(rp, slot, std::move(handshake));
            generate_messages();
            return slot;
        }

        stream_slot stream_manager::add_unchecked_outbound_path_impl(strong_actor_ptr next, message handshake) {
            ACTOR_LOG_TRACE(ACTOR_ARG(next) << ACTOR_ARG(handshake));
            response_promise rp {self_->ctrl(), self_->ctrl(), {next}, make_message_id()};
            return add_unchecked_outbound_path_impl(rp, std::move(handshake));
        }

        stream_slot stream_manager::add_unchecked_outbound_path_impl(message handshake) {
            ACTOR_LOG_TRACE(ACTOR_ARG(handshake));
            auto rp = self_->make_response_promise();
            return add_unchecked_outbound_path_impl(rp, std::move(handshake));
        }

        stream_slot stream_manager::add_unchecked_inbound_path_impl(rtti_pair rtti) {
            ACTOR_LOG_TRACE("");
            auto x = self_->current_mailbox_element();
            if (x == nullptr || !x->content().match_elements<open_stream_msg>()) {
                ACTOR_LOG_ERROR(
                    "add_unchecked_inbound_path called, but current message "
                    "is not an open_stream_msg");
                return invalid_stream_slot;
            }
            auto &osm = x->content().get_mutable_as<open_stream_msg>(0);
            if (out().terminal() && !self_->current_forwarding_stack().empty()) {
                // Sinks must always terminate the stream.
                ACTOR_LOG_WARNING(
                    "add_unchecked_inbound_path called in a sink, but the "
                    "handshake has further stages");
                stream_slots path_id {osm.slot, 0};
                auto code = sec::cannot_add_downstream;
                inbound_path::emit_irregular_shutdown(self_, path_id, std::move(osm.prev_stage), code);
                auto rp = self_->make_response_promise();
                rp.deliver(code);
                return invalid_stream_slot;
            }
            auto slot = assign_next_slot();
            stream_slots path_id {osm.slot, slot};
            auto ptr = self_->make_inbound_path(this, path_id, std::move(osm.prev_stage), rtti);
            ACTOR_ASSERT(ptr != nullptr);
            ptr->emit_ack_open(self_, actor_cast<actor_addr>(osm.original_stage));
            return slot;
        }

        stream_slot stream_manager::assign_next_slot() {
            return self_->assign_next_slot_to(this);
        }

        stream_slot stream_manager::assign_next_pending_slot() {
            return self_->assign_next_pending_slot_to(this);
        }

        void stream_manager::finalize(const error &) {
            // nop
        }

        void stream_manager::output_closed(error) {
            // nop
        }

        void stream_manager::downstream_demand(outbound_path *, long) {
            ACTOR_LOG_ERROR("stream_manager::downstream_demand called");
        }

        void stream_manager::input_closed(error) {
            // nop
        }

    }    // namespace actor
}    // namespace nil
