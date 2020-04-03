//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#include <nil/actor/mailbox_element.hpp>

#include <memory>

namespace nil {
    namespace actor {

        namespace {

            /// Corrects the message ID for down- and upstream messages to make sure the
            /// category for a `mailbox_element` matches its content.
            template<class...>
            struct mailbox_category_corrector {
                static constexpr message_id apply(message_id x) noexcept {
                    return x;
                }
            };

            template<>
            struct mailbox_category_corrector<downstream_msg> {
                static constexpr message_id apply(message_id x) noexcept {
                    return x.with_category(message_id::downstream_message_category);
                }
            };

            template<>
            struct mailbox_category_corrector<upstream_msg> {
                static constexpr message_id apply(message_id x) noexcept {
                    return x.with_category(message_id::upstream_message_category);
                }
            };

            message_id dynamic_category_correction(const message &msg, message_id mid) {
                if (msg.match_elements<downstream_msg>())
                    return mailbox_category_corrector<downstream_msg>::apply(mid);
                if (msg.match_elements<upstream_msg>())
                    return mailbox_category_corrector<upstream_msg>::apply(mid);
                return mid;
            }

        }    // namespace

        mailbox_element::mailbox_element(strong_actor_ptr sender, message_id mid, forwarding_stack stages,
                                         message payload) :
            sender(std::move(sender)),
            mid(dynamic_category_correction(payload, mid)), stages(std::move(stages)), payload(std::move(payload)) {
            // nop
        }

        mailbox_element_ptr make_mailbox_element(strong_actor_ptr sender, message_id id,
                                                 mailbox_element::forwarding_stack stages, message payload) {
            return std::make_unique<mailbox_element>(std::move(sender), id, std::move(stages), std::move(payload));
        }

    }    // namespace actor
}    // namespace nil
