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

#include <cstdint>

#include <boost/config.hpp>

#include <nil/actor/error.hpp>
#include <nil/actor/fwd.hpp>
#include <nil/actor/intrusive/task_result.hpp>

namespace nil::actor::detail {

    /// Drains a mailbox and sends an error message to each unhandled request.
    struct BOOST_SYMBOL_VISIBLE sync_request_bouncer {
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
}    // namespace nil::actor::detail