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

#include <tuple>
#include <string>
#include <functional>

#include <nil/actor/meta/type_name.hpp>

namespace nil {
    namespace actor {

        /// Marker for representing placeholders at runtime.
        struct index_mapping {
            int value;

            explicit index_mapping(int x) : value(x) {
                // nop
            }

            template<class T, class E = typename std::enable_if<std::is_placeholder<T>::value != 0>::type>
            index_mapping(T) : value(std::is_placeholder<T>::value) {
                // nop
            }
        };

        inline bool operator==(const index_mapping &x, const index_mapping &y) {
            return x.value == y.value;
        }

        template<class Inspector>
        typename Inspector::result_type inspect(Inspector &f, index_mapping &x) {
            return f(meta::type_name("index_mapping"), x.value);
        }

    }    // namespace actor
}    // namespace nil
