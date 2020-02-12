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

#include <nil/actor/mailbox_element.hpp>

namespace nil {
    namespace actor {

        /// Convenience tag type for producing empty forwarding stacks.
        struct no_stages_t {
            constexpr no_stages_t() {
                // nop
            }

            inline operator mailbox_element::forwarding_stack() const {
                return {};
            }
        };

        /// Convenience tag for producing empty forwarding stacks.
        constexpr no_stages_t no_stages = no_stages_t {};

    }    // namespace actor
}    // namespace nil
