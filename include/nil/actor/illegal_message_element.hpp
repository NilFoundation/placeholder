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

#include <type_traits>

namespace nil {
    namespace actor {

        /// Marker class identifying classes in ACTOR that are not allowed
        /// to be used as message element.
        struct illegal_message_element {
            // no members (marker class)
        };

        template<class T>
        struct is_illegal_message_element : std::is_base_of<illegal_message_element, T> {};

    }    // namespace actor
}    // namespace nil
