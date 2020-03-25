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

#include <nil/actor/fwd.hpp>

namespace nil {
    namespace actor {

        /// Represents an object pointing to a `type_erased_tuple` that
        /// is convertible to a `message`
        class message_view {
        public:
            virtual ~message_view();

            virtual type_erased_tuple &content() = 0;

            virtual const type_erased_tuple &content() const = 0;

            virtual message move_content_to_message() = 0;

            virtual message copy_content_to_message() const = 0;
        };

    }    // namespace actor
}    // namespace nil
