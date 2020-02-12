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

#include <functional>

#include <nil/actor/fwd.hpp>

namespace nil {
    namespace actor {

        /// @relates local_actor
        /// Default handler function that leaves messages in the mailbox.
        /// Can also be used inside custom message handlers to signalize
        /// skipping to the runtime.
        class skip_t {
        public:
            using fun = std::function<result<message>(scheduled_actor *self, message_view &)>;

            constexpr skip_t() {
                // nop
            }

            constexpr skip_t operator()() const {
                return *this;
            }

            operator fun() const;

        private:
            static result<message> skip_fun_impl(scheduled_actor *, message_view &);
        };

        /// Tells the runtime system to skip a message when used as message
        /// handler, i.e., causes the runtime to leave the message in
        /// the mailbox of an actor.
        constexpr skip_t skip = skip_t {};

    }    // namespace actor
}    // namespace nil
