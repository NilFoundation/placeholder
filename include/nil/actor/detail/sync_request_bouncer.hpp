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

#include <cstdint>

#include <nil/actor/error.hpp>
#include <nil/actor/fwd.hpp>

#include <nil/actor/intrusive/task_result.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            /// Drains a mailbox and sends an error message to each unhandled request.
            struct sync_request_bouncer {
                error rsn;
                explicit sync_request_bouncer(error r);
                void operator()(const strong_actor_ptr &sender, const message_id &mid) const;
                void operator()(const mailbox_element &e) const;

                /// Unwrap WDRR queues. Nesting WDRR queues results in a Key/Queue prefix for
                /// each layer of nesting.
                template<class Key, class Queue, class... Ts>
                intrusive::task_result operator()(const Key &, const Queue &, const Ts &... xs) const {
                    (*this)(xs...);
                    return intrusive::task_result::resume;
                }
            };

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
