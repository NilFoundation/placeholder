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

#include <nil/actor/pec.hpp>

#include <nil/actor/config_value.hpp>
#include <nil/actor/error.hpp>
#include <nil/actor/make_message.hpp>
#include <nil/actor/string_view.hpp>

namespace {

    constexpr const char *tbl[] = {
        "success",
        "trailing_character",
        "unexpected_eof",
        "unexpected_character",
        "negative_duration",
        "duration_overflow",
        "too_many_characters",
        "illegal_escape_sequence",
        "unexpected_newline",
        "integer_overflow",
        "integer_underflow",
        "exponent_underflow",
        "exponent_overflow",
        "type_mismatch",
        "not_an_option",
        "illegal_argument",
        "missing_argument",
        "illegal_category",
    };

}    // namespace

namespace nil {
    namespace actor {

        error make_error(pec code) {
            return {static_cast<uint8_t>(code), atom("parser")};
        }

        error make_error(pec code, size_t line, size_t column) {
            config_value::dictionary context;
            context["line"] = line;
            context["column"] = column;
            return {static_cast<uint8_t>(code), atom("parser"), make_message(std::move(context))};
        }

        error make_error(pec code, string_view argument) {
            config_value::dictionary context;
            context["argument"] = std::string {argument.begin(), argument.end()};
            return {static_cast<uint8_t>(code), atom("parser"), make_message(std::move(context))};
        }

        const char *to_string(pec x) {
            return tbl[static_cast<uint8_t>(x)];
        }

    }    // namespace actor
}    // namespace nil
