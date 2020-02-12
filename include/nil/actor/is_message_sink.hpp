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

#include <type_traits>

#include <nil/actor/fwd.hpp>

namespace nil {
    namespace actor {

        template<class T>
        struct is_message_sink : std::false_type {};

        template<>
        struct is_message_sink<actor> : std::true_type {};

        template<>
        struct is_message_sink<group> : std::true_type {};

        template<class... Ts>
        struct is_message_sink<typed_actor<Ts...>> : std::true_type {};

    }    // namespace actor
}    // namespace nil
