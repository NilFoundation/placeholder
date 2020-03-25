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

#include <cctype>
#include <cstdint>

#include <nil/actor/pec.hpp>

namespace nil {
    namespace actor {
        namespace detail {
            namespace parser {

                template<class Iterator, class Sentinel = Iterator>
                struct state {
                    Iterator i;
                    Sentinel e;
                    pec code;
                    int32_t line;
                    int32_t column;

                    state() noexcept : i(), e(), code(pec::success), line(1), column(1) {
                        // nop
                    }

                    explicit state(Iterator first) noexcept : state() {
                        i = first;
                    }

                    state(Iterator first, Sentinel last) noexcept : state() {
                        i = first;
                        e = last;
                    }

                    /// Returns the null terminator when reaching the end of the string,
                    /// otherwise the next character.
                    char next() noexcept {
                        ++i;
                        ++column;
                        if (i != e) {
                            auto c = *i;
                            if (c == '\n') {
                                ++line;
                                column = 1;
                            }
                            return c;
                        }
                        return '\0';
                    }

                    /// Returns the null terminator if `i == e`, otherwise the current character.
                    char current() const noexcept {
                        return i != e ? *i : '\0';
                    }

                    /// Checks whether `i == e`.
                    bool at_end() const noexcept {
                        return i == e;
                    }

                    /// Skips any whitespaces characters in the input.
                    void skip_whitespaces() noexcept {
                        auto c = current();
                        while (isspace(c))
                            c = next();
                    }

                    /// Tries to read `x` as the next character (skips any whitespaces).
                    bool consume(char x) noexcept {
                        skip_whitespaces();
                        if (current() == x) {
                            next();
                            return true;
                        }
                        return false;
                    }
                };

            }    // namespace parser
        }        // namespace detail
    }            // namespace actor
}    // namespace nil
