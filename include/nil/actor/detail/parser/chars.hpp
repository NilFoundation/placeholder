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

#include <cstring>

namespace nil {
    namespace actor {
        namespace detail {
            namespace parser {

                struct any_char_t {};

                constexpr any_char_t any_char = any_char_t {};

                constexpr bool in_whitelist(any_char_t, char) {
                    return true;
                }

                constexpr bool in_whitelist(char whitelist, char ch) {
                    return whitelist == ch;
                }

                inline bool in_whitelist(const char *whitelist, char ch) {
                    return strchr(whitelist, ch) != nullptr;
                }

                inline bool in_whitelist(bool (*filter)(char), char ch) {
                    return filter(ch);
                }

                extern const char alphanumeric_chars[63];

                extern const char alphabetic_chars[53];

                extern const char hexadecimal_chars[23];

                extern const char decimal_chars[11];

                extern const char octal_chars[9];

            }    // namespace parser
        }        // namespace detail
    }            // namespace actor
}    // namespace nil
