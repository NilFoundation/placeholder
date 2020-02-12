//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#include <nil/actor/actor_registry.hpp>

#include <mutex>
#include <limits>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>

#include <nil/actor/sec.hpp>
#include <nil/actor/locks.hpp>
#include <nil/actor/logger.hpp>
#include <nil/actor/attachable.hpp>
#include <nil/actor/exit_reason.hpp>
#include <nil/actor/spawner.hpp>
#include <nil/actor/scoped_actor.hpp>
#include <nil/actor/stateful_actor.hpp>
#include <nil/actor/event_based_actor.hpp>
#include <nil/actor/uniform_type_info_map.hpp>

#include <nil/actor/detail/shared_spinlock.hpp>

namespace nil {
    namespace actor {

        namespace {

            using exclusive_guard = unique_lock<detail::shared_spinlock>;
            using shared_guard = shared_lock<detail::shared_spinlock>;

        }    // namespace

        actor_registry::~actor_registry() {
            // nop
        }

        actor_registry::actor_registry(spawner &sys) : running_(0), system_(sys) {
            // nop
        }

        strong_actor_ptr actor_registry::get_impl(actor_id key) const {
            shared_guard guard(instances_mtx_);
            auto i = entries_.find(key);
            if (i != entries_.end())
                return i->second;
            ACTOR_LOG_DEBUG("key invalid, assume actor no longer exists:" << ACTOR_ARG(key));
            return nullptr;
        }

        void actor_registry::put_impl(actor_id key, strong_actor_ptr val) {
            ACTOR_LOG_TRACE(ACTOR_ARG(key));
            if (!val)
                return;
            {    // lifetime scope of guard
                exclusive_guard guard(instances_mtx_);
                if (!entries_.emplace(key, val).second)
                    return;
            }
            // attach functor without lock
            ACTOR_LOG_DEBUG("added actor:" << ACTOR_ARG(key));
            actor_registry *reg = this;
            val->get()->attach_functor([key, reg]() { reg->erase(key); });
        }

        void actor_registry::erase(actor_id key) {
            // Stores a reference to the actor we're going to remove. This guarantees
            // that we aren't releasing the last reference to an actor while erasing it.
            // Releasing the final ref can trigger the actor to call its cleanup function
            // that in turn calls this function and we can end up in a deadlock.
            strong_actor_ptr ref;
            {    // Lifetime scope of guard.
                exclusive_guard guard {instances_mtx_};
                auto i = entries_.find(key);
                if (i != entries_.end()) {
                    ref.swap(i->second);
                    entries_.erase(i);
                }
            }
        }

        void actor_registry::inc_running() {
#if ACTOR_LOG_LEVEL >= ACTOR_LOG_LEVEL_DEBUG
            auto value = ++running_;
            ACTOR_LOG_DEBUG(ACTOR_ARG(value));
#else
            ++running_;
#endif
        }

        size_t actor_registry::running() const {
            return running_.load();
        }

        void actor_registry::dec_running() {
            size_t new_val = --running_;
            if (new_val <= 1) {
                std::unique_lock<std::mutex> guard(running_mtx_);
                running_cv_.notify_all();
            }
            ACTOR_LOG_DEBUG(ACTOR_ARG(new_val));
        }

        void actor_registry::await_running_count_equal(size_t expected) const {
            ACTOR_ASSERT(expected == 0 || expected == 1);
            ACTOR_LOG_TRACE(ACTOR_ARG(expected));
            std::unique_lock<std::mutex> guard {running_mtx_};
            while (running_ != expected) {
                ACTOR_LOG_DEBUG(ACTOR_ARG(running_.load()));
                running_cv_.wait(guard);
            }
        }

        strong_actor_ptr actor_registry::get_impl(atom_value key) const {
            shared_guard guard {named_entries_mtx_};
            auto i = named_entries_.find(key);
            if (i == named_entries_.end())
                return nullptr;
            return i->second;
        }

        void actor_registry::put_impl(atom_value key, strong_actor_ptr value) {
            if (value == nullptr) {
                erase(key);
                return;
            }
            exclusive_guard guard {named_entries_mtx_};
            named_entries_.emplace(key, std::move(value));
        }

        void actor_registry::erase(atom_value key) {
            // Stores a reference to the actor we're going to remove for the same
            // reasoning as in erase(actor_id).
            strong_actor_ptr ref;
            {    // Lifetime scope of guard.
                exclusive_guard guard {named_entries_mtx_};
                auto i = named_entries_.find(key);
                if (i != named_entries_.end()) {
                    ref.swap(i->second);
                    named_entries_.erase(i);
                }
            }
        }

        auto actor_registry::named_actors() const -> name_map {
            shared_guard guard {named_entries_mtx_};
            return named_entries_;
        }

        void actor_registry::start() {
            // nop
        }

        void actor_registry::stop() {
            // nop
        }

    }    // namespace actor
}    // namespace nil
