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
#include <nil/actor/message_priority.hpp>
#include <nil/actor/unit.hpp>

#include <nil/actor/policy/downstream_messages.hpp>
#include <nil/actor/policy/normal_messages.hpp>
#include <nil/actor/policy/upstream_messages.hpp>
#include <nil/actor/policy/urgent_messages.hpp>

namespace nil {
    namespace actor {
        namespace policy {

            /// Configures a cached WDRR fixed multiplexed queue for dispatching to four
            /// nested queue (one for each message category type).
            class categorized {
            public:
                // -- member types -----------------------------------------------------------

                using mapped_type = mailbox_element;

                using task_size_type = size_t;

                using deficit_type = size_t;

                using unique_pointer = mailbox_element_ptr;

                // -- constructors, destructors, and assignment operators --------------------

                categorized() = default;

                categorized(const categorized &) = default;

                categorized &operator=(const categorized &) = default;

                constexpr categorized(unit_t) {
                    // nop
                }

                // -- interface required by wdrr_fixed_multiplexed_queue ---------------------

                template<template<class> class Queue>
                static deficit_type quantum(const Queue<urgent_messages> &, deficit_type x) noexcept {
                    // Allow actors to consume twice as many urgent as normal messages per
                    // credit round.
                    return x + x;
                }

                template<class Queue>
                static deficit_type quantum(const Queue &, deficit_type x) noexcept {
                    return x;
                }

                static size_t id_of(const mailbox_element &x) noexcept {
                    return static_cast<size_t>(x.mid.category());
                }
            };

        }    // namespace policy
    }        // namespace actor
}    // namespace nil
