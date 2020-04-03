//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#include <nil/actor/detail/append_percent_encoded.hpp>

#include <nil/actor/byte.hpp>
#include <nil/actor/config.hpp>
#include <nil/actor/detail/append_hex.hpp>
#include <nil/actor/string_view.hpp>

namespace nil::actor::detail {

    void append_percent_encoded(std::string &str, string_view x, bool is_path) {
        for (auto ch : x)
            switch (ch) {
                case ':':
                case '/':
                    if (is_path) {
                        str += ch;
                        break;
                    }
                    [[fallthrough]];
                case ' ':
                case '?':
                case '#':
                case '[':
                case ']':
                case '@':
                case '!':
                case '$':
                case '&':
                case '\'':
                case '"':
                case '(':
                case ')':
                case '*':
                case '+':
                case ',':
                case ';':
                case '=':
                    str += '%';
                    append_hex(str, ch);
                    break;
                default:
                    str += ch;
            }
    }

}    // namespace nil::actor::detail