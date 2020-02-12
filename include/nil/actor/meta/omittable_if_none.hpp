//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt or
// http://opensource.org/licenses/BSD-3-Clause
//---------------------------------------------------------------------------//

#pragma once

#include <nil/actor/meta/annotation.hpp>

namespace nil {
    namespace actor {
        namespace meta {

            struct omittable_if_none_t : annotation {
                constexpr omittable_if_none_t() {
                    // nop
                }
            };

            /// Allows an inspector to omit the following data field if it is empty.
            constexpr omittable_if_none_t omittable_if_none() {
                return {};
            }

        }    // namespace meta
    }        // namespace actor
}    // namespace nil
