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

#pragma once

#include <nil/actor/none.hpp>
#include <nil/actor/actor_cast.hpp>
#include <nil/actor/spawner.hpp>
#include <nil/actor/actor_storage.hpp>
#include <nil/actor/intrusive_ptr.hpp>
#include <nil/actor/blocking_actor.hpp>
#include <nil/actor/scoped_execution_unit.hpp>

namespace nil {
    namespace actor {

        /// A scoped handle to a blocking actor.
        class scoped_actor {
        public:
            // allow conversion via actor_cast
            template<class, class, int>
            friend class actor_cast_access;

            using signatures = none_t;

            scoped_actor(spawner &sys, bool hide = false);

            scoped_actor(const scoped_actor &) = delete;
            scoped_actor &operator=(const scoped_actor &) = delete;

            scoped_actor(scoped_actor &&) = delete;
            scoped_actor &operator=(scoped_actor &&) = delete;

            ~scoped_actor();

            inline explicit operator bool() const {
                return static_cast<bool>(self_);
            }

            inline spawner &home_system() const {
                return *self_->home_system;
            }

            inline blocking_actor *operator->() const {
                return ptr();
            }

            inline blocking_actor &operator*() const {
                return *ptr();
            }

            inline actor_addr address() const {
                return ptr()->address();
            }

            blocking_actor *ptr() const;

        private:
            inline actor_control_block *get() const {
                return self_.get();
            }

            actor_id prev_;    // used for logging/debugging purposes only
            scoped_execution_unit context_;
            strong_actor_ptr self_;
        };

        template<>
        struct has_weak_ptr_semantics<scoped_actor> {
            constexpr static const bool value = false;
        };

        std::string to_string(const scoped_actor &x);

    }    // namespace actor
}    // namespace nil
