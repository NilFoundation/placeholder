//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <functional>
#include <string>
#include <utility>

#include <nil/actor/abstract_group.hpp>
#include <nil/actor/detail/comparable.hpp>

#include <nil/actor/detail/type_traits.hpp>
#include <nil/actor/fwd.hpp>
#include <nil/actor/group_module.hpp>
#include <nil/actor/intrusive_ptr.hpp>
#include <nil/actor/none.hpp>

namespace nil {
    namespace actor {

        struct invalid_group_t {
            constexpr invalid_group_t() = default;
        };

        /// Identifies an invalid {@link group}.
        /// @relates group
        constexpr invalid_group_t invalid_group = invalid_group_t {};

        class BOOST_SYMBOL_VISIBLE group : detail::comparable<group>, detail::comparable<group, invalid_group_t> {
        public:
            using signatures = none_t;

            group() = default;

            group(group &&) = default;

            group(const group &) = default;

            group(const invalid_group_t &);

            group &operator=(group &&) = default;

            group &operator=(const group &) = default;

            group &operator=(const invalid_group_t &);

            group(abstract_group *);

            group(intrusive_ptr<abstract_group> gptr);

            explicit operator bool() const noexcept {
                return static_cast<bool>(ptr_);
            }

            bool operator!() const noexcept {
                return !ptr_;
            }

            static intptr_t compare(const abstract_group *lhs, const abstract_group *rhs);

            intptr_t compare(const group &other) const noexcept;

            intptr_t compare(const invalid_group_t &) const noexcept {
                return ptr_ ? 1 : 0;
            }

            friend BOOST_SYMBOL_VISIBLE error inspect(serializer &, group &);

            friend BOOST_SYMBOL_VISIBLE error_code<sec> inspect(binary_serializer &, group &);

            friend BOOST_SYMBOL_VISIBLE error inspect(deserializer &, group &);

            friend BOOST_SYMBOL_VISIBLE error_code<sec> inspect(binary_deserializer &, group &);

            abstract_group *get() const noexcept {
                return ptr_.get();
            }

            /// @cond PRIVATE

            spawner &system() const {
                return ptr_->system();
            }

            template<class... Ts>
            void eq_impl(message_id mid, strong_actor_ptr sender, execution_unit *ctx, Ts &&... xs) const {
                ACTOR_ASSERT(!mid.is_request());
                if (ptr_)
                    ptr_->enqueue(std::move(sender), mid, make_message(std::forward<Ts>(xs)...), ctx);
            }

            bool subscribe(strong_actor_ptr who) const {
                if (!ptr_)
                    return false;
                return ptr_->subscribe(std::move(who));
            }

            void unsubscribe(const actor_control_block *who) const {
                if (ptr_)
                    ptr_->unsubscribe(who);
            }

            const group *operator->() const noexcept {
                return this;
            }

            /// @endcond

        private:
            abstract_group *release() noexcept {
                return ptr_.release();
            }

            group(abstract_group *, bool);

            abstract_group_ptr ptr_;
        };

        /// @relates group
        BOOST_SYMBOL_VISIBLE std::string to_string(const group &x);

    }    // namespace actor
}    // namespace nil

namespace std {
    template<>
    struct hash<nil::actor::group> {
        size_t operator()(const nil::actor::group &x) const {
            // groups are singleton objects, the address is thus the best possible hash
            return !x ? 0 : reinterpret_cast<size_t>(x.get());
        }
    };
}    // namespace std
