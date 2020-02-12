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

#include <cstddef>
#include <cstdint>
#include <string>

#include <nil/actor/fwd.hpp>

namespace nil {
    namespace actor {

        /// PEC stands for "Parser Error Code". This enum contains error codes used by
        /// various ACTOR parsers.
        enum class pec : uint8_t {
            /// Not-an-error.
            success = 0,
            /// Parser succeeded but found trailing character(s).
            trailing_character = 1,
            /// Parser stopped after reaching the end while still expecting input.
            unexpected_eof,
            /// Parser stopped after reading an unexpected character.
            unexpected_character,
            /// Parsed integer exceeds the number of available bits of a `timespan`.
            timespan_overflow,
            /// Tried constructing a `timespan` with from a floating point number.
            fractional_timespan = 5,
            /// Too many characters for an atom.
            too_many_characters,
            /// Unrecognized character after escaping `\`.
            illegal_escape_sequence,
            /// Misplaced newline, e.g., inside a string.
            unexpected_newline,
            /// Parsed positive integer exceeds the number of available bits.
            integer_overflow,
            /// Parsed negative integer exceeds the number of available bits.
            integer_underflow = 10,
            /// Exponent of parsed double is less than the minimum supported exponent.
            exponent_underflow,
            /// Exponent of parsed double is greater than the maximum supported exponent.
            exponent_overflow,
            /// Parsed type does not match the expected type.
            type_mismatch,
            /// Stopped at an unrecognized option name.
            not_an_option,
            /// Stopped at an unparseable argument.
            illegal_argument = 15,
            /// Stopped because an argument was omitted.
            missing_argument,
            /// Stopped because the key of a category was taken.
            illegal_category,
        };

        /// Returns an error object from given error code.
        error make_error(pec code);

        /// Returns an error object from given error code with additional context
        /// information for where the parser stopped in the input.
        error make_error(pec code, size_t line, size_t column);

        /// Returns an error object from given error code with additional context
        /// information for where the parser stopped in the argument.
        error make_error(pec code, string_view argument);

        /// @relates pec
        const char *to_string(pec x);

    }    // namespace actor
}    // namespace nil
