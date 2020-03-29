//---------------------------------------------------------------------------//
// Copyright (c) 2011-2020 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <cstddef>

namespace nil {
    namespace actor {
        namespace detail {

            /// Calculates the size for `T` including padding for aligning to `max_align_t`.
            template<class T>
            constexpr size_t padded_size_v = ((sizeof(T) / alignof(max_align_t)) +
                                              static_cast<size_t>(sizeof(T) % alignof(max_align_t) != 0)) *
                                             alignof(max_align_t);

        }    // namespace detail
    }        // namespace actor
}    // namespace nil