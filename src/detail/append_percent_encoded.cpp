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

#include <nil/actor/detail/append_percent_encoded.hpp>

#include <nil/crypto3/codec/algorithm/encode.hpp>
#include <nil/crypto3/codec/hex.hpp>

#include <nil/actor/config.hpp>
#include <nil/actor/string_view.hpp>

using namespace nil::crypto3;

namespace nil {
    namespace actor {
        namespace detail {

            void append_percent_encoded(std::string &str, string_view x, bool is_path) {
                for (auto ch : x)
                    switch (ch) {
                        case '/':
                            if (is_path) {
                                str += ch;
                                break;
                            }
                            ACTOR_ANNOTATE_FALLTHROUGH;
                        case ' ':
                        case ':':
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
                        case '=': {
                            std::string chenc = encode<codec::hex<>>(reinterpret_cast<uint8_t *>(&ch),
                                                                     reinterpret_cast<uint8_t *>(&ch) + 1);
                            str += '%' + chenc;
                        } break;
                        default:
                            str += ch;
                    }
            }

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
