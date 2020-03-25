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

        class statically_typed_actor_base {
            // used as marker only
        };

        class dynamically_typed_actor_base {
            // used as marker only
        };

        template<class T>
        struct actor_marker {
            using type = statically_typed_actor_base;
        };

        template<>
        struct actor_marker<behavior> {
            using type = dynamically_typed_actor_base;
        };

        template<class T>
        using is_statically_typed = std::is_base_of<statically_typed_actor_base, T>;

        template<class T>
        using is_dynamically_typed = std::is_base_of<dynamically_typed_actor_base, T>;

    }    // namespace actor
}    // namespace nil
