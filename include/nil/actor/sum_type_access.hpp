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

#include <type_traits>

namespace nil {
    namespace actor {

        /// Specializing this trait allows users to enable `holds_alternative`, `get`,
        /// `get_if`, and `visit` for any user-defined sum type.
        /// @relates SumType
        template<class T>
        struct sum_type_access {
            static constexpr bool specialized = false;
        };

        /// Evaluates to `true` if `T` specializes `sum_type_access`.
        /// @relates SumType
        template<class T>
        struct has_sum_type_access {
            static constexpr bool value = sum_type_access<T>::specialized;
        };

    }    // namespace actor
}    // namespace nil
