//---------------------------------------------------------------------------//
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <bit>
#include <cstddef>
#include <stdexcept>
#include <string_view>

namespace nil::crypto3::multiprecision {
    template<std::size_t Bits>
    class big_uint;

    namespace detail {
        constexpr bool is_valid_hex_digit(char c) {
            return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F');
        }

        constexpr unsigned parse_hex_digit(char c) {
            if ('0' <= c && c <= '9') {
                return c - '0';
            }
            if ('a' <= c && c <= 'f') {
                return (c - 'a') + 10;
            }
            return (c - 'A') + 10;
        }

        constexpr bool has_hex_prefix(std::string_view str) {
            return str.size() >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X');
        }

        template<std::size_t Bits>
        constexpr big_uint<Bits> parse_int_hex(std::string_view str) {
            if (!has_hex_prefix(str)) {
                throw std::invalid_argument("hex number should start with 0x");
            }

            big_uint<Bits> result{0};

            std::size_t bits = 0;
            for (std::size_t i = 2; i < str.size(); ++i) {
                char c = str[i];
                if (!is_valid_hex_digit(c)) {
                    throw std::invalid_argument("non-hex character in hex number");
                }
                result <<= 4;
                if (bits != 0) {
                    bits += 4;
                }
                unsigned digit = parse_hex_digit(c);
                result += digit;
                if (bits == 0 && digit != 0) {
                    bits += std::bit_width(digit);
                }
            }
            if (bits > Bits) {
                throw std::range_error("not enough bits to store number");
            }
            return result;
        }

        template<std::size_t Bits>
        constexpr big_uint<Bits> parse_int_decimal(std::string_view str) {
            big_uint<Bits> result{0};

            for (std::size_t i = 0; i < str.size(); ++i) {
                char c = str[i];
                if (c < '0' || c > '9') {
                    throw std::invalid_argument("non-decimal character in number");
                }
                result *= 10u;
                result += static_cast<unsigned>(c - '0');
            }
            return result;
        }

        template<std::size_t Bits>
        constexpr big_uint<Bits> parse_int(std::string_view str) {
            if (has_hex_prefix(str)) {
                return parse_int_hex<Bits>(str);
            }
            return parse_int_decimal<Bits>(str);
        }
    }  // namespace detail
}  // namespace nil::crypto3::multiprecision
