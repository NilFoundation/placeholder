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

#include <string>

#include <boost/config.hpp>

namespace nil {
    namespace actor {

        /// Stores the result of a message invocation.
        enum class invoke_message_result {
            /// Indicates that the actor consumed the message.
            consumed,

            /// Indicates that the actor left the message in the mailbox.
            skipped,

            /// Indicates that the actor discarded the message based on meta data. For
            /// example, timeout messages for already received requests usually get
            /// dropped without calling any user-defined code.
            dropped,
        };

        BOOST_SYMBOL_VISIBLE std::string to_string(invoke_message_result);

    }    // namespace actor
}    // namespace nil
