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

#include <nil/actor/meta/annotation.hpp>

namespace nil {
    namespace actor {
        namespace meta {

            struct omittable_t : annotation {
                constexpr omittable_t() {
                    // nop
                }
            };

            /// Allows an inspector to omit the following data field
            /// unconditionally when producing human-friendly output.
            constexpr omittable_t omittable() {
                return {};
            }

        }    // namespace meta
    }        // namespace actor
}    // namespace nil
