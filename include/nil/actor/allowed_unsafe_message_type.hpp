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

// This file is referenced in the manual, do not modify without updating refs!
// ConfiguringActorApplications: 50-54

#pragma once

#include <type_traits>

namespace nil {
    namespace actor {

        /// Template specializations can whitelist individual
        /// types for unsafe message passing operations.
        template<class T>
        struct allowed_unsafe_message_type : std::false_type {};

        template<class T>
        struct is_allowed_unsafe_message_type : allowed_unsafe_message_type<T> {};

        template<class T>
        struct is_allowed_unsafe_message_type<T &> : allowed_unsafe_message_type<T> {};

        template<class T>
        struct is_allowed_unsafe_message_type<T &&> : allowed_unsafe_message_type<T> {};

        template<class T>
        struct is_allowed_unsafe_message_type<const T &> : allowed_unsafe_message_type<T> {};

        template<class T>
        constexpr bool is_allowed_unsafe_message_type_v = allowed_unsafe_message_type<T>::value;

    }    // namespace actor
}    // namespace nil

#define ACTOR_ALLOW_UNSAFE_MESSAGE_TYPE(type_name)                               \
    namespace nil {                                                            \
        namespace actor {                                                        \
            template<>                                                         \
            struct allowed_unsafe_message_type<type_name> : std::true_type {}; \
        }                                                                      \
    }
