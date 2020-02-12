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

#pragma once

#include <list>
#include <vector>
#include <memory>
#include <utility>
#include <type_traits>

#include <nil/actor/fwd.hpp>
#include <nil/actor/none.hpp>
#include <nil/actor/intrusive_ptr.hpp>

#include <nil/actor/behavior.hpp>
#include <nil/actor/duration.hpp>
#include <nil/actor/match_case.hpp>
#include <nil/actor/may_have_timeout.hpp>
#include <nil/actor/message.hpp>
#include <nil/actor/ref_counted.hpp>
#include <nil/actor/timeout_definition.hpp>

#include <nil/actor/detail/behavior_impl.hpp>

namespace nil {
    namespace actor {

        /// A partial function implementation used to process a `message`.
        class message_handler {
        public:
            friend class behavior;

            message_handler() = default;
            message_handler(message_handler &&) = default;
            message_handler(const message_handler &) = default;
            message_handler &operator=(message_handler &&) = default;
            message_handler &operator=(const message_handler &) = default;

            /// A pointer to the underlying implementation.
            using impl_ptr = intrusive_ptr<detail::behavior_impl>;

            /// Returns a pointer to the implementation.
            inline const impl_ptr &as_behavior_impl() const {
                return impl_;
            }

            /// Creates a message handler from @p ptr.
            message_handler(impl_ptr ptr);

            /// Checks whether the message handler is not empty.
            inline operator bool() const {
                return static_cast<bool>(impl_);
            }

            /// Create a message handler a list of match expressions,
            /// functors, or other message handlers.
            template<class T, class... Ts>
            message_handler(const T &v, Ts &&... xs) {
                assign(v, std::forward<Ts>(xs)...);
            }

            /// Assigns new message handlers.
            template<class... Ts>
            void assign(Ts... xs) {
                static_assert(sizeof...(Ts) > 0, "assign without arguments called");
                static_assert(!detail::disjunction<may_have_timeout<typename std::decay<Ts>::type>::value...>::value,
                              "Timeouts are only allowed in behaviors");
                impl_ = detail::make_behavior(xs...);
            }

            /// Equal to `*this = other`.
            void assign(message_handler what);

            /// Runs this handler and returns its (optional) result.
            inline optional<message> operator()(message &arg) {
                return (impl_) ? impl_->invoke(arg) : none;
            }

            /// Runs this handler and returns its (optional) result.
            inline optional<message> operator()(type_erased_tuple &xs) {
                return impl_ ? impl_->invoke(xs) : none;
            }

            /// Runs this handler with callback.
            inline match_case::result operator()(detail::invoke_result_visitor &f, type_erased_tuple &xs) {
                return impl_ ? impl_->invoke(f, xs) : match_case::no_match;
            }

            /// Runs this handler with callback.
            inline match_case::result operator()(detail::invoke_result_visitor &f, message &xs) {
                return impl_ ? impl_->invoke(f, xs) : match_case::no_match;
            }

            /// Returns a new handler that concatenates this handler
            /// with a new handler from `xs...`.
            template<class... Ts>
            typename std::conditional<
                detail::disjunction<may_have_timeout<typename std::decay<Ts>::type>::value...>::value,
                behavior,
                message_handler>::type
                or_else(Ts &&... xs) const {
                // using a behavior is safe here, because we "cast"
                // it back to a message_handler when appropriate
                behavior tmp {std::forward<Ts>(xs)...};
                if (!tmp) {
                    return *this;
                }
                if (impl_)
                    return impl_->or_else(tmp.as_behavior_impl());
                return tmp.as_behavior_impl();
            }

            /// @cond PRIVATE

            inline message_handler &unbox() {
                return *this;
            }

            /// @endcond

        private:
            impl_ptr impl_;
        };

    }    // namespace actor
}    // namespace nil
