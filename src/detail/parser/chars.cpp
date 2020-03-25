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

#include <nil/actor/detail/parser/chars.hpp>

namespace nil {
    namespace actor {
        namespace detail {
            namespace parser {

                const char alphanumeric_chars[63] =
                    "0123456789"
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "abcdefghijklmnopqrstuvwxyz";

                const char alphabetic_chars[53] =
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "abcdefghijklmnopqrstuvwxyz";

                const char hexadecimal_chars[23] = "0123456789ABCDEFabcdef";

                const char decimal_chars[11] = "0123456789";

                const char octal_chars[9] = "01234567";

            }    // namespace parser
        }        // namespace detail
    }            // namespace actor
}    // namespace nil
