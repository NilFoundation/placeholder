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

#include <cstddef>
#include <memory>

#include <nil/actor/actor_control_block.hpp>

#include <nil/actor/intrusive/singly_linked.hpp>
#include <nil/actor/message.hpp>
#include <nil/actor/message_id.hpp>
#include <nil/actor/meta/omittable_if_empty.hpp>
#include <nil/actor/meta/type_name.hpp>
#include <nil/actor/tracing_data.hpp>

namespace nil {
    namespace actor {

        class BOOST_SYMBOL_VISIBLE mailbox_element : public intrusive::singly_linked<mailbox_element> {
        public:
            using forwarding_stack = std::vector<strong_actor_ptr>;

            /// Source of this message and receiver of the final response.
            strong_actor_ptr sender;

            /// Denotes whether this an asynchronous message or a request.
            message_id mid;

            /// `stages.back()` is the next actor in the forwarding chain,
            /// if this is empty then the original sender receives the response.
            forwarding_stack stages;

#ifdef ACTOR_ENABLE_ACTOR_PROFILER
            /// Optional tracing information. This field is unused by default, but an
            /// @ref actor_profiler can make use of it to inject application-specific
            /// instrumentation.
            tracing_data_ptr tracing_id;
#endif    // ACTOR_ENABLE_ACTOR_PROFILER

            /// Stores the payload.
            message payload;

            mailbox_element() = default;

            mailbox_element(strong_actor_ptr sender, message_id mid, forwarding_stack stages, message payload);

            bool is_high_priority() const {
                return mid.category() == message_id::urgent_message_category;
            }

            mailbox_element(mailbox_element &&) = delete;
            mailbox_element(const mailbox_element &) = delete;
            mailbox_element &operator=(mailbox_element &&) = delete;
            mailbox_element &operator=(const mailbox_element &) = delete;

            // -- backward compatibility -------------------------------------------------

            message &content() noexcept {
                return payload;
            }

            const message &content() const noexcept {
                return payload;
            }
        };

        /// @relates mailbox_element
        template<class Inspector>
        typename Inspector::result_type inspect(Inspector &f, mailbox_element &x) {
            return f(meta::type_name("mailbox_element"), x.sender, x.mid, meta::omittable_if_empty(), x.stages,
#ifdef ACTOR_ENABLE_ACTOR_PROFILER
                     x.tracing_id,
#endif    // ACTOR_ENABLE_ACTOR_PROFILER
                     x.payload);
        }

        /// @relates mailbox_element
        using mailbox_element_ptr = std::unique_ptr<mailbox_element>;

        /// @relates mailbox_element
        BOOST_SYMBOL_VISIBLE mailbox_element_ptr make_mailbox_element(strong_actor_ptr sender, message_id id,
                                                                      mailbox_element::forwarding_stack stages,
                                                                      message content);

        /// @relates mailbox_element
        template<class T, class... Ts>
        std::enable_if_t<!std::is_same<typename std::decay<T>::type, message>::value || (sizeof...(Ts) > 0),
                         mailbox_element_ptr>
            make_mailbox_element(strong_actor_ptr sender, message_id id, mailbox_element::forwarding_stack stages,
                                 T &&x, Ts &&... xs) {
            return make_mailbox_element(std::move(sender), id, std::move(stages),
                                        make_message(std::forward<T>(x), std::forward<Ts>(xs)...));
        }

    }    // namespace actor
}    // namespace nil
