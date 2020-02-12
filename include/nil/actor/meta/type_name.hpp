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

            struct type_name_t : annotation {
                constexpr type_name_t(const char *cstr) : value(cstr) {
                    // nop
                }

                const char *value;
            };

            /// Returns a type name annotation.
            type_name_t constexpr type_name(const char *cstr) {
                return {cstr};
            }
        }    // namespace meta
    }        // namespace actor
}    // namespace nil
