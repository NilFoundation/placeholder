//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#include <nil/actor/actor.hpp>

#include <cassert>
#include <utility>

#include <nil/actor/actor_addr.hpp>
#include <nil/actor/actor_proxy.hpp>
#include <nil/actor/decorator/sequencer.hpp>
#include <nil/actor/deserializer.hpp>
#include <nil/actor/event_based_actor.hpp>
#include <nil/actor/local_actor.hpp>
#include <nil/actor/make_actor.hpp>
#include <nil/actor/scoped_actor.hpp>
#include <nil/actor/serializer.hpp>

namespace nil {
    namespace actor {

        actor::actor(std::nullptr_t) : ptr_(nullptr) {
            // nop
        }

        actor::actor(const scoped_actor &x) : ptr_(actor_cast<strong_actor_ptr>(x)) {
            // nop
        }

        actor::actor(actor_control_block *ptr) : ptr_(ptr) {
            // nop
        }

        actor::actor(actor_control_block *ptr, bool add_ref) : ptr_(ptr, add_ref) {
            // nop
        }

        actor &actor::operator=(std::nullptr_t) {
            ptr_.reset();
            return *this;
        }

        actor &actor::operator=(const scoped_actor &x) {
            ptr_ = actor_cast<strong_actor_ptr>(x);
            return *this;
        }

        intptr_t actor::compare(const actor &x) const noexcept {
            return actor_addr::compare(ptr_.get(), x.ptr_.get());
        }

        intptr_t actor::compare(const actor_addr &x) const noexcept {
            return actor_addr::compare(ptr_.get(), actor_cast<actor_control_block *>(x));
        }

        intptr_t actor::compare(const strong_actor_ptr &x) const noexcept {
            return actor_addr::compare(ptr_.get(), x.get());
        }

        void actor::swap(actor &other) noexcept {
            ptr_.swap(other.ptr_);
        }

        actor_addr actor::address() const noexcept {
            return actor_cast<actor_addr>(ptr_);
        }

        actor operator*(actor f, actor g) {
            auto &sys = f->home_system();
            return make_actor<decorator::sequencer, actor>(
                sys.next_actor_id(), sys.node(), &sys, actor_cast<strong_actor_ptr>(std::move(f)),
                actor_cast<strong_actor_ptr>(std::move(g)), std::set<std::string> {});
        }

        bool operator==(const actor &lhs, abstract_actor *rhs) {
            return lhs ? actor_cast<abstract_actor *>(lhs) == rhs : rhs == nullptr;
        }

        bool operator==(abstract_actor *lhs, const actor &rhs) {
            return rhs == lhs;
        }

        bool operator!=(const actor &lhs, abstract_actor *rhs) {
            return !(lhs == rhs);
        }

        bool operator!=(abstract_actor *lhs, const actor &rhs) {
            return !(lhs == rhs);
        }

    }    // namespace actor
}    // namespace nil
