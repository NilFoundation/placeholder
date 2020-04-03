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

#include <cstring>

#include <nil/actor/config.hpp>

namespace nil::actor::detail::parser {

    struct any_char_t {};

    constexpr any_char_t any_char = any_char_t {};

    constexpr bool in_whitelist(any_char_t, char) {
        return true;
    }

    constexpr bool in_whitelist(char whitelist, char ch) {
        return whitelist == ch;
    }

    inline bool in_whitelist(const char *whitelist, char ch) {
        // Note: using strchr breaks if `ch == '\0'`.
        for (char c = *whitelist++; c != '\0'; c = *whitelist++)
            if (c == ch)
                return true;
        return false;
    }

    inline bool in_whitelist(bool (*filter)(char), char ch) {
        return filter(ch);
    }

    BOOST_SYMBOL_VISIBLE extern const char alphanumeric_chars[63];

    BOOST_SYMBOL_VISIBLE extern const char alphabetic_chars[53];

    BOOST_SYMBOL_VISIBLE extern const char hexadecimal_chars[23];

    BOOST_SYMBOL_VISIBLE extern const char decimal_chars[11];

    BOOST_SYMBOL_VISIBLE extern const char octal_chars[9];

}    // namespace nil::actor::detail::parser
