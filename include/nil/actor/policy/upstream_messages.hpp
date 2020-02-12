//---------------------------------------------------------------------------//
// Copyright (c) 2011-2017 Dominik Charousset
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <nil/actor/fwd.hpp>
#include <nil/actor/mailbox_element.hpp>
#include <nil/actor/unit.hpp>

namespace nil {
    namespace actor {
        namespace policy {

            /// Configures a DRR queue for holding upstream messages.
            class upstream_messages {
            public:
                // -- member types -----------------------------------------------------------

                using mapped_type = mailbox_element;

                using task_size_type = size_t;

                using deficit_type = size_t;

                using unique_pointer = mailbox_element_ptr;

                // -- constructors, destructors, and assignment operators --------------------

                upstream_messages() = default;

                upstream_messages(const upstream_messages &) = default;

                upstream_messages &operator=(const upstream_messages &) = default;

                constexpr upstream_messages(unit_t) {
                    // nop
                }

                // -- interface required by drr_queue ----------------------------------------

                static inline task_size_type task_size(const mailbox_element &) noexcept {
                    return 1;
                }
            };

        }    // namespace policy
    }        // namespace actor
}    // namespace nil
