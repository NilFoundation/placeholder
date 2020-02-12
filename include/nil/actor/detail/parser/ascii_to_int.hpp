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

namespace nil {
    namespace actor {
        namespace detail {
            namespace parser {

                template<int Base, class T>
                struct ascii_to_int {
                    // @pre `c` is a valid ASCII digit, i.e., matches [0-9].
                    constexpr T operator()(char c) const {
                        // Result is guaranteed to have a value between 0 and 10 and can be safely
                        // cast to any integer type.
                        return static_cast<T>(c - '0');
                    }
                };

                template<class T>
                struct ascii_to_int<16, T> {
                    // @pre `c` is a valid ASCII hex digit, i.e., matches [0-9A-Fa-f].
                    constexpr T operator()(char c) const {
                        // Numbers start at position 48 in the ASCII table.
                        // Uppercase characters start at position 65 in the ASCII table.
                        // Lowercase characters start at position 97 in the ASCII table.
                        // Result is guaranteed to have a value between 0 and 16 and can be safely
                        // cast to any integer type.
                        return static_cast<T>(c <= '9' ? c - '0' : (c <= 'F' ? 10 + (c - 'A') : 10 + (c - 'a')));
                    }
                };

            }    // namespace parser
        }        // namespace detail
    }            // namespace actor
}    // namespace nil
