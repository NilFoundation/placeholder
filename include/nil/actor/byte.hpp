//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#include <cstdint>
#include <type_traits>

#include <nil/actor/detail/type_traits.hpp>

#pragma once

namespace nil {
    namespace actor {

        /// A C++11/14 drop-in replacement for C++17's `std::byte`.
        enum class byte : uint8_t {};

        template<class IntegerType, class = detail::enable_if_tt<std::is_integral<IntegerType>>>
        constexpr IntegerType to_integer(byte x) noexcept {
            return static_cast<IntegerType>(x);
        }

        template<class IntegerType, class E = detail::enable_if_tt<std::is_integral<IntegerType>>>
        constexpr byte &operator<<=(byte &x, IntegerType shift) noexcept {
            return x = static_cast<byte>(to_integer<uint8_t>(x) << shift);
        }

        template<class IntegerType, class E = detail::enable_if_tt<std::is_integral<IntegerType>>>
        constexpr byte operator<<(byte x, IntegerType shift) noexcept {
            return static_cast<byte>(to_integer<uint8_t>(x) << shift);
        }

        template<class IntegerType, class E = detail::enable_if_tt<std::is_integral<IntegerType>>>
        constexpr byte &operator>>=(byte &x, IntegerType shift) noexcept {
            return x = static_cast<byte>(to_integer<uint8_t>(x) >> shift);
        }

        template<class IntegerType, class E = detail::enable_if_tt<std::is_integral<IntegerType>>>
        constexpr byte operator>>(byte x, IntegerType shift) noexcept {
            return static_cast<byte>(static_cast<unsigned char>(x) >> shift);
        }

        inline byte &operator|=(byte &x, byte y) noexcept {
            return x = static_cast<byte>(to_integer<uint8_t>(x) | to_integer<uint8_t>(y));
        }

        constexpr byte operator|(byte x, byte y) noexcept {
            return static_cast<byte>(to_integer<uint8_t>(x) | to_integer<uint8_t>(y));
        }

        inline byte &operator&=(byte &x, byte y) noexcept {
            return x = static_cast<byte>(to_integer<uint8_t>(x) & to_integer<uint8_t>(y));
        }

        constexpr byte operator&(byte x, byte y) noexcept {
            return static_cast<byte>(to_integer<uint8_t>(x) & to_integer<uint8_t>(y));
        }

        inline byte &operator^=(byte &x, byte y) noexcept {
            return x = static_cast<byte>(to_integer<uint8_t>(x) ^ to_integer<uint8_t>(y));
        }

        constexpr byte operator^(byte x, byte y) noexcept {
            return static_cast<byte>(to_integer<uint8_t>(x) ^ to_integer<uint8_t>(y));
        }

        constexpr byte operator~(byte x) noexcept {
            return static_cast<byte>(~to_integer<uint8_t>(x));
        }

    }    // namespace actor
}    // namespace nil
