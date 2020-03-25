//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#pragma once

#include <cstdint>
#include <type_traits>

namespace nil {
    namespace actor {

        /// Denotes the urgency of asynchronous messages.
        enum class message_priority {
            high = 0,
            normal = 1,
        };

        /// @relates message_priority
        using high_message_priority_constant = std::integral_constant<message_priority, message_priority::high>;

        /// @relates message_priority
        using normal_message_priority_constant = std::integral_constant<message_priority, message_priority::normal>;

    }    // namespace actor
}    // namespace nil
