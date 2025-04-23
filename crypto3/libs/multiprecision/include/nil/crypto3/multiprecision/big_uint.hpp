//---------------------------------------------------------------------------//
// Copyright (c) 2012-2022 John Maddock
// Copyright (c) 2022 Christopher Kormanyos
// Copyright (c) 2024 Martun Karapetyan <martun@nil.foundation>
// Copyright (c) 2024-2025 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <cctype>
#include <charconv>
#include <climits>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>

#include <boost/assert.hpp>
#include <boost/functional/hash.hpp>

#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops/fwd.hpp"  // IWYU pragma: keep (used for friend declarations)
#include "nil/crypto3/multiprecision/detail/big_uint/arithmetic.hpp"
#include "nil/crypto3/multiprecision/detail/big_uint/internal_conversions.hpp"
#include "nil/crypto3/multiprecision/detail/big_uint/limits.hpp"  // IWYU pragma: export
#include "nil/crypto3/multiprecision/detail/big_uint/parsing.hpp"
#include "nil/crypto3/multiprecision/detail/big_uint/storage.hpp"
#include "nil/crypto3/multiprecision/detail/endian.hpp"
#include "nil/crypto3/multiprecision/detail/force_inline.hpp"
#include "nil/crypto3/multiprecision/unsigned_utils.hpp"

namespace nil::crypto3::multiprecision {
    /**
     * @brief Big unsigned integer type
     *
     * @tparam Bits Number of bits
     *
     * @details
     * This is a class that represents a big unsigned integer with a fixed size in bits.
     *
     * @note
     * All arithmetic operations and conversions are safe by default, they throw
     * on overflow. If you want arithmetic modulo 2^Bits you can use wrapping_*
     * functions. There are also unchecked_* operations, these assert on overflow so
     * overflows in them are not checked in release builds.
     */
    template<std::size_t Bits_>
    class big_uint {
      public:
        static constexpr std::size_t Bits = Bits_;

        // Storage

      private:
        using limb_type = detail::limb_type;
        using double_limb_type = detail::double_limb_type;
        using signed_limb_type = detail::signed_limb_type;
        using signed_double_limb_type = detail::signed_double_limb_type;

        using limb_pointer = detail::limb_pointer;
        using const_limb_pointer = detail::const_limb_pointer;
        static constexpr std::size_t limb_bits = detail::limb_bits;
        static constexpr limb_type max_limb_value = detail::max_limb_value;

        static constexpr std::size_t static_limb_count =
            (Bits / limb_bits) + (((Bits % limb_bits) != 0u) ? 1u : 0u);
        static constexpr std::size_t upper_limb_bits =
            (Bits % limb_bits) ? Bits % limb_bits : limb_bits;
        static constexpr limb_type upper_limb_mask =
            (Bits % limb_bits) ? (limb_type(1) << (Bits % limb_bits)) - 1
                               : (~limb_type(0u));

        constexpr std::size_t limb_count() const noexcept {
            static_assert(static_limb_count != 0, "No limbs in storage.");
            return static_limb_count;
        }
        constexpr limb_pointer limbs() noexcept { return m_data.data(); }
        constexpr const_limb_pointer limbs() const noexcept { return m_data.data(); }

        constexpr limb_type normalize() noexcept {
            if constexpr (Bits % limb_bits != 0) {
                limb_type result = (limbs()[static_limb_count - 1] & ~upper_limb_mask) >>
                                   upper_limb_bits;
                limbs()[static_limb_count - 1] &= upper_limb_mask;
                return result;
            } else {
                return 0;
            }
        }

        // Zeros out everything after limb[i]
        NIL_CO3_MP_FORCEINLINE constexpr void zero_after(
            std::size_t start_index) noexcept {
            for (std::size_t i = start_index; i < static_limb_count; ++i) {
                limbs()[i] = 0;
            }
        }

        constexpr std::size_t used_limbs() const noexcept {
            for (int i = static_limb_count - 1; i >= 0; --i) {
                if (limbs()[i] != 0) {
                    return i + 1;
                }
            }
            return 0;
        }

        constexpr std::size_t order() const noexcept {
            for (int i = static_limb_count - 1; i >= 0; --i) {
                if (limbs()[i] != 0) {
                    return i;
                }
            }
            return 0;
        }

        // Assignment

        template<typename T, std::enable_if_t<
                                 std::is_integral_v<T> && std::is_unsigned_v<T>, int> = 0>
        constexpr void do_assign_integral_unchecked(const T& a) noexcept {
            if constexpr (sizeof(T) <= sizeof(limb_type)) {
                this->limbs()[0] = a;
                this->zero_after(1);
            } else {
                static_assert(sizeof(T) % sizeof(limb_type) == 0);
                constexpr std::size_t n =
                    std::min(static_limb_count, sizeof(T) / sizeof(limb_type));
                auto a_copy = a;
                for (std::size_t i = 0; i < n; ++i) {
                    limbs()[i] = a_copy & static_cast<T>(static_cast<limb_type>(-1));
                    a_copy >>= limb_bits;
                }
                zero_after(n);
            }
            this->normalize();
        }

        template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
        constexpr void do_assign_integral(const T& a) {
            do_assign_integral_unchecked(unsigned_or_throw(a));
            if constexpr (sizeof(T) * CHAR_BIT > Bits) {
                if (*this != a) {
                    throw std::range_error("big_uint: overflow");
                }
            }
        }

        template<std::size_t Bits2>
        constexpr void do_assign_unchecked(const big_uint<Bits2>& other) noexcept {
            std::size_t count = (std::min)(other.limb_count(), this->limb_count());
            for (std::size_t i = 0; i < count; ++i) {
                this->limbs()[i] = other.limbs()[i];
            }
            // Zero out everything after (std::min)(other.limb_count(), limb_count()), so
            // if size of other was less, we have 0s at the end.
            this->zero_after((std::min)(other.limb_count(), this->limb_count()));
            this->normalize();
        }

        template<std::size_t Bits2>
        constexpr void do_assign(const big_uint<Bits2>& other) {
            do_assign_unchecked(other);
            if constexpr (Bits2 > Bits) {
                if (*this != other) {
                    throw std::range_error("big_uint: overflow");
                }
            }
        }

      public:
        // Constructor

        constexpr big_uint() noexcept {}

        constexpr big_uint(std::string_view str) { *this = str; }
        constexpr big_uint(const char* str) { *this = str; }
        constexpr big_uint(const std::string& str) { *this = str; }

        template<class T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
        constexpr big_uint(T a) {
            do_assign_integral(a);
        }

        template<std::size_t Bits2, std::enable_if_t<Bits2 <= Bits, int> = 0>
        constexpr big_uint(const big_uint<Bits2>& other) {
            do_assign(other);
        }

        template<std::size_t Bits2, std::enable_if_t<(Bits2 > Bits), int> = 0>
        explicit constexpr big_uint(const big_uint<Bits2>& other) {
            do_assign(other);
        }

        template<std::size_t N>
        constexpr big_uint(const std::array<std::uint8_t, N>& bytes) noexcept {
            *this = bytes;
        }

        // Assignment

        constexpr big_uint& operator=(std::string_view str) {
            *this = detail::parse_int<Bits>(str);
            return *this;
        }
        constexpr big_uint& operator=(const char* str) {
            *this = detail::parse_int<Bits>(str);
            return *this;
        }
        constexpr big_uint& operator=(const std::string& str) {
            *this = detail::parse_int<Bits>(str);
            return *this;
        }

        template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
        constexpr big_uint& operator=(T a) {
            do_assign_integral(a);
            return *this;
        }

        template<std::size_t Bits2, std::enable_if_t<Bits2 <= Bits, int> = 0>
        constexpr big_uint& operator=(const big_uint<Bits2>& other) {
            do_assign(other);
            return *this;
        }

        template<std::size_t N>
        constexpr big_uint& operator=(const std::array<std::uint8_t, N>& bytes) {
            std::size_t bits = 0;
            for (std::size_t i = 0; i < bytes.size(); ++i) {
                *this <<= 8;
                if (bits != 0) {
                    bits += 8;
                }
                unsigned b = bytes[i];
                *this += b;
                if (bits == 0 && b != 0) {
                    bits += std::bit_width(b);
                }
            }
            if (bits > Bits) {
                throw std::range_error("big_uint: not enough bits to store bytes");
            }
            return *this;
        }

        // String conversion

      private:
        constexpr std::string decimal_str() const {
            // TODO(ioxid): optimize
            std::string result;
            auto copy = *this;
            while (!copy.is_zero()) {
                result += static_cast<char>(static_cast<unsigned>(copy % 10u) + '0');
                copy /= 10u;
            }
            std::reverse(result.begin(), result.end());
            if (result.empty()) {
                result += '0';
            }
            return result;
        }

        constexpr std::string hex_str() const {
            std::string result;
            result.reserve(used_limbs() * limb_bits / 4);
            bool found_first = false;
            for (int i = static_limb_count - 1; i >= 0; --i) {
                auto limb = limbs()[i];
                bool should_pad = found_first;
                found_first = found_first || limb != 0;
                if (found_first) {
                    std::size_t len = limb == 0 ? 1 : (std::bit_width(limb) + 3) / 4;
                    std::size_t padded_len = len;
                    if (should_pad) {
                        padded_len = sizeof(limb_type) * 2;
                    }
                    for (std::size_t j = 0; j < padded_len - len; ++j) {
                        result += '0';
                    }
                    std::size_t start_offset = result.size();
                    result.resize(result.size() + len);
                    auto ec = std::to_chars(result.data() + start_offset,
                                            result.data() + result.size(), limb, 16)
                                  .ec;
                    BOOST_ASSERT(ec == std::errc{});
                }
            }
            if (result.empty()) {
                result += '0';
            }
            return result;
        }

      public:
        constexpr std::string str(
            std::ios_base::fmtflags flags = std::ios_base::hex | std::ios_base::showbase |
                                            std::ios_base::uppercase) const {
            if ((flags & std::ios_base::dec) || !(flags & std::ios_base::basefield)) {
                return decimal_str();
            }
            if (!(flags & std::ios_base::hex)) {
                throw std::invalid_argument("big_uint: unsupported format flags");
            }
            auto result = hex_str();
            if (flags & std::ios_base::uppercase) {
                for (std::size_t i = 0; i < result.size(); ++i) {
                    result[i] = static_cast<char>(
                        std::toupper(static_cast<unsigned char>(result[i])));
                }
            }
            if (flags & std::ios_base::showbase) {
                result = "0x" + result;
            }
            return result;
        }

        template<std::size_t Bits2, std::enable_if_t<(Bits2 < Bits), int> = 0>
        constexpr big_uint<Bits2> truncate() const noexcept {
            big_uint<Bits2> result;
            result.do_assign_unchecked(*this);
            return result;
        }

        // Cast to integral types

      private:
        template<typename T,
                 std::enable_if_t<!std::is_same_v<T, bool> && std::is_integral_v<T> &&
                                      std::is_unsigned_v<T>,
                                  int> = 0>
        constexpr T to_unsigned_unchecked() const {
            T result;
            if constexpr (sizeof(T) <= sizeof(limb_type)) {
                result = static_cast<T>(this->limbs()[0]);
            } else {
                static_assert(sizeof(T) % sizeof(limb_type) == 0);
                constexpr std::size_t n =
                    std::min(sizeof(T) / sizeof(limb_type), static_limb_count);
                result = 0;
                for (std::size_t i = 0; i < n; ++i) {
                    result <<= limb_bits;
                    result |= limbs()[n - i - 1];
                }
            }
            return result;
        }

      public:
        template<typename T,
                 std::enable_if_t<!std::is_same_v<T, bool> && std::is_integral_v<T> &&
                                      std::is_unsigned_v<T>,
                                  int> = 0>
        explicit constexpr operator T() const {
            auto result = to_unsigned_unchecked<T>();
            if constexpr (sizeof(T) * CHAR_BIT < Bits) {
                if (*this != result) {
                    throw std::overflow_error("big_uint: overflow");
                }
            }
            return result;
        }

        template<typename T,
                 std::enable_if_t<std::is_integral_v<T> && std::is_signed_v<T>, int> = 0>
        explicit constexpr operator T() const {
            T result = static_cast<T>(to_unsigned_unchecked<std::make_unsigned_t<T>>());
            if constexpr (sizeof(T) * CHAR_BIT <= Bits) {
                if (*this != result) {
                    throw std::overflow_error("big_uint: overflow");
                }
            }
            return result;
        }

        explicit constexpr operator bool() const { return !is_zero(); }

        // Comparison

        template<std::size_t Bits2>
        constexpr std::strong_ordering operator<=>(
            const big_uint<Bits2>& b) const noexcept {
            auto pa = limbs();
            auto pb = b.limbs();
            constexpr std::size_t m =
                std::min(static_limb_count, big_uint<Bits2>::static_limb_count);
            for (auto i = static_cast<std::ptrdiff_t>(limb_count()) - 1;
                 i >= b.limb_count(); --i) {
                if (pa[i]) {
                    return std::strong_ordering::greater;
                }
            }
            for (auto i = static_cast<std::ptrdiff_t>(b.limb_count()) - 1;
                 i >= limb_count(); --i) {
                if (pb[i]) {
                    return std::strong_ordering::less;
                }
            }
            for (auto i = static_cast<std::ptrdiff_t>(m) - 1; i >= 0; --i) {
                if (pa[i] != pb[i]) {
                    return pa[i] <=> pb[i];
                }
            }
            return std::strong_ordering::equal;
        }

        template<typename T,
                 std::enable_if_t<std::is_integral_v<T> && !std::is_same_v<T, bool> &&
                                      std::is_signed_v<T>,
                                  int> = 0>
        constexpr std::strong_ordering operator<=>(const T& b) const noexcept {
            if (b < 0) {
                return std::strong_ordering::greater;
            }
            return *this <=> static_cast<std::make_unsigned_t<T>>(b);
        }

        template<typename T,
                 std::enable_if_t<std::is_integral_v<T> && !std::is_same_v<T, bool> &&
                                      std::is_unsigned_v<T>,
                                  int> = 0>
        constexpr std::strong_ordering operator<=>(const T& b) const noexcept {
            static_assert(sizeof(T) <= sizeof(double_limb_type));
            std::size_t s = used_limbs();
            if constexpr (sizeof(T) <= sizeof(limb_type)) {
                if (s > 1) {
                    return std::strong_ordering::greater;
                }
                auto lmb = this->limbs()[0];
                return lmb <=> b;
            } else {
                if (s > 2) {
                    return std::strong_ordering::greater;
                }
                auto dbl = to_unsigned_unchecked<double_limb_type>();
                return dbl <=> b;
            }
        }

        template<typename T,
                 std::enable_if_t<is_integral_v<T> && !std::is_same_v<T, bool>, int> = 0>
        friend constexpr bool operator==(const big_uint& a, const T& b) noexcept {
            return (a <=> b) == 0;
        }

        friend constexpr bool operator==(const big_uint& a, bool b) noexcept {
            return a == static_cast<limb_type>(b);
        }

        NIL_CO3_MP_FORCEINLINE constexpr bool is_zero() const noexcept {
            for (std::size_t i = 0; i < limb_count(); ++i) {
                if (limbs()[i] != 0) {
                    return false;
                }
            }
            return true;
        }

        // Arithmetic operations

        constexpr void wrapping_neg_inplace() noexcept {
            if (is_zero()) {
                return;
            }
            complement(*this);
            ++*this;
        }

        constexpr auto wrapping_neg() const noexcept {
            auto result = *this;
            result.wrapping_neg_inplace();
            return result;
        }

        constexpr auto& operator++() noexcept {
            if (limbs()[0] < max_limb_value) {
                ++limbs()[0];
                if constexpr (Bits < limb_bits) {
                    normalize();
                }
            } else {
                detail::add<detail::overflow_policy::throw_exception>(
                    *this, *this, static_cast<limb_type>(1u));
            }
            return *this;
        }

        constexpr auto operator++(int) noexcept {
            auto copy = *this;
            ++*this;
            return copy;
        }

        constexpr auto operator+() const noexcept { return *this; }

        constexpr auto& operator--() noexcept {
            if (limbs()[0]) {
                --limbs()[0];
            } else {
                detail::subtract<detail::overflow_policy::throw_exception>(
                    *this, *this, static_cast<limb_type>(1u));
            }
            return *this;
        }
        constexpr auto operator--(int) noexcept {
            auto copy = *this;
            --*this;
            return copy;
        }

        template<typename T, std::enable_if_t<is_integral_v<T>, int> = 0>
        friend constexpr auto operator+(const big_uint& a, const T& b) {
            detail::largest_big_uint_t<big_uint, T> result;
            detail::add<detail::overflow_policy::throw_exception>(result, a, b);
            return result;
        }

        template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
        friend constexpr auto operator+(const T& a, const big_uint& b) {
            return b + a;
        }

        template<typename T, std::enable_if_t<is_integral_v<T>, int> = 0>
        friend constexpr auto& operator+=(big_uint& a, const T& b) {
            detail::add<detail::overflow_policy::throw_exception>(a, a, b);
            return a;
        }

        template<typename T, std::enable_if_t<is_integral_v<T>, int> = 0>
        friend constexpr auto wrapping_add(const big_uint& a, const T& b) noexcept {
            detail::largest_big_uint_t<big_uint, T> result;
            detail::add<detail::overflow_policy::wrap>(result, a, b);
            return result;
        }

        template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
        friend constexpr auto wrapping_add(const T& a, const big_uint& b) noexcept {
            return wrapping_add(b, a);
        }

        template<typename T, std::enable_if_t<is_integral_v<T>, int> = 0>
        friend constexpr auto& wrapping_add_assign(big_uint& a, const T& b) noexcept {
            detail::add<detail::overflow_policy::wrap>(a, a, b);
            return a;
        }

        template<typename T, std::enable_if_t<is_integral_v<T>, int> = 0>
        friend constexpr auto unchecked_add(const big_uint& a, const T& b) noexcept {
            detail::largest_big_uint_t<big_uint, T> result;
            detail::add<detail::overflow_policy::debug_assert>(result, a, b);
            return result;
        }

        template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
        friend constexpr auto unchecked_add(const T& a, const big_uint& b) noexcept {
            return unchecked_add(b, a);
        }

        template<typename T, std::enable_if_t<is_integral_v<T>, int> = 0>
        friend constexpr auto& unchecked_add_assign(big_uint& a, const T& b) noexcept {
            detail::add<detail::overflow_policy::debug_assert>(a, a, b);
            return a;
        }

        template<std::size_t Bits2>
        [[nodiscard]] friend constexpr bool overflowing_add_assign(
            big_uint& a, const big_uint<Bits2>& b) {
            return detail::add_unsigned<detail::overflow_policy::throw_exception>(a, a,
                                                                                  b);
        }

        template<typename T, std::enable_if_t<is_integral_v<T>, int> = 0>
        friend constexpr auto operator-(const big_uint& a, const T& b) {
            detail::largest_big_uint_t<big_uint, T> result;
            detail::subtract<detail::overflow_policy::throw_exception>(result, a, b);
            return result;
        }

        template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
        friend constexpr auto operator-(const T& a, const big_uint& b) {
            auto a_unsigned = unsigned_or_throw(a);
            detail::largest_big_uint_t<big_uint, T> result;
            detail::subtract_unsigned<detail::overflow_policy::throw_exception>(
                result, detail::as_limb_type_or_big_uint(a_unsigned), b);
            return result;
        }

        template<typename T, std::enable_if_t<is_integral_v<T>, int> = 0>
        friend constexpr auto& operator-=(big_uint& a, const T& b) {
            detail::subtract<detail::overflow_policy::throw_exception>(a, a, b);
            return a;
        }

        template<typename T, std::enable_if_t<is_integral_v<T>, int> = 0>
        friend constexpr auto wrapping_sub(const big_uint& a, const T& b) noexcept {
            detail::largest_big_uint_t<big_uint, T> result;
            detail::subtract<detail::overflow_policy::wrap>(result, a, b);
            return result;
        }

        template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
        friend constexpr auto wrapping_sub(const T& a, const big_uint& b) noexcept {
            return wrapping_add(b.wrapping_neg(), a);
        }

        template<typename T, std::enable_if_t<is_integral_v<T>, int> = 0>
        friend constexpr auto& wrapping_sub_assign(big_uint& a, const T& b) noexcept {
            detail::subtract<detail::overflow_policy::wrap>(a, a, b);
            return a;
        }

        template<typename T, std::enable_if_t<is_integral_v<T>, int> = 0>
        friend constexpr auto unchecked_sub(const big_uint& a, const T& b) noexcept {
            detail::largest_big_uint_t<big_uint, T> result;
            detail::subtract<detail::overflow_policy::debug_assert>(result, a, b);
            return result;
        }

        template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
        friend constexpr auto unchecked_sub(const T& a, const big_uint& b) noexcept {
            if constexpr (std::is_signed_v<T>) {
                BOOST_ASSERT_MSG(a >= 0, "big_uint: nonnegative value expected");
            }
            auto a_unsigned = unsigned_abs(a);
            BOOST_ASSERT_MSG(a_unsigned >= b, "big_uint: subtraction overflow");
            return wrapping_add(b.wrapping_neg(), a);
        }

        template<typename T, std::enable_if_t<is_integral_v<T>, int> = 0>
        friend constexpr auto& unchecked_sub_assign(big_uint& a, const T& b) noexcept {
            detail::subtract<detail::overflow_policy::debug_assert>(a, a, b);
            return a;
        }

        template<typename T, std::enable_if_t<is_integral_v<T>, int> = 0>
        friend constexpr auto operator*(const big_uint& a, const T& b) {
            decltype(auto) b_unsigned = unsigned_or_throw(b);
            detail::largest_big_uint_t<big_uint, T> result;
            detail::multiply<detail::overflow_policy::throw_exception>(result, a,
                                                                       b_unsigned);
            return result;
        }

        template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
        friend constexpr auto operator*(const T& a, const big_uint& b) {
            return b * a;
        }

        template<typename T, std::enable_if_t<is_integral_v<T>, int> = 0>
        friend constexpr auto& operator*=(big_uint& a, const T& b) {
            decltype(auto) b_unsigned = unsigned_or_throw(b);
            detail::multiply<detail::overflow_policy::throw_exception>(a, a, b_unsigned);
            return a;
        }

        template<typename T, std::enable_if_t<is_integral_v<T>, int> = 0>
        friend constexpr auto wrapping_mul(const big_uint& a, const T& b) {
            decltype(auto) b_unsigned = unsigned_abs(b);
            detail::largest_big_uint_t<big_uint, T> result;
            detail::multiply<detail::overflow_policy::wrap>(result, a, b_unsigned);
            if constexpr (std::is_signed_v<T>) {
                if (b < 0) {
                    result.wrapping_neg_inplace();
                }
            }
            return result;
        }

        template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
        friend constexpr auto wrapping_mul(const T& a, const big_uint& b) {
            return wrapping_mul(b, a);
        }

        template<typename T, std::enable_if_t<is_integral_v<T>, int> = 0>
        friend constexpr auto& wrapping_mul_assign(big_uint& a, const T& b) {
            decltype(auto) b_unsigned = unsigned_abs(b);
            detail::multiply<detail::overflow_policy::wrap>(a, a, b_unsigned);
            if constexpr (std::is_signed_v<T>) {
                if (b < 0) {
                    a.wrapping_neg_inplace();
                }
            }
            return a;
        }

        template<typename T, std::enable_if_t<is_integral_v<T>, int> = 0>
        friend constexpr auto unchecked_mul(const big_uint& a, const T& b) {
            if constexpr (std::is_signed_v<T>) {
                BOOST_ASSERT_MSG(b >= 0, "big_uint: nonnegative value expected");
            }
            decltype(auto) b_unsigned = unsigned_abs(b);
            detail::largest_big_uint_t<big_uint, T> result;
            detail::multiply<detail::overflow_policy::debug_assert>(result, a,
                                                                    b_unsigned);
            return result;
        }

        template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
        friend constexpr auto unchecked_mul(const T& a, const big_uint& b) {
            return unchecked_mul(b, a);
        }

        template<typename T, std::enable_if_t<is_integral_v<T>, int> = 0>
        friend constexpr auto& unchecked_mul_assign(big_uint& a, const T& b) {
            if constexpr (std::is_signed_v<T>) {
                BOOST_ASSERT_MSG(b >= 0, "big_uint: nonnegative value expected");
            }
            decltype(auto) b_unsigned = unsigned_abs(b);
            detail::multiply<detail::overflow_policy::debug_assert>(a, a, b_unsigned);
            return a;
        }

        // TODO(ioxid): maybe add wrapping versions of division and modulus, which accept
        // negative arguments

        template<
            typename T1, typename T2,
            std::enable_if_t<(std::is_same_v<T1, big_uint> && is_integral_v<T2>) ||
                                 (std::is_integral_v<T1> && std::is_same_v<T2, big_uint>),
                             int> = 0>
        friend constexpr auto operator/(const T1& a, const T2& b) {
            decltype(auto) a_unsigned = unsigned_or_throw(a);
            decltype(auto) b_unsigned = unsigned_or_throw(b);
            using big_uint_a = std::decay_t<decltype(detail::as_big_uint(a_unsigned))>;
            big_uint_a result;
            big_uint_a modulus;
            detail::divide(&result, detail::as_big_uint(a_unsigned),
                           detail::as_big_uint(b_unsigned), modulus);
            try {
                return static_cast<detail::largest_big_uint_t<T1, T2>>(result);
            } catch (const std::range_error&) {
                throw std::overflow_error("big_uint: division overflow");
            }
        }

        template<typename T, std::enable_if_t<is_integral_v<T>, int> = 0>
        friend constexpr auto& operator/=(big_uint& a, const T& b) {
            decltype(auto) b_unsigned = unsigned_or_throw(b);
            big_uint result;
            big_uint modulus;
            detail::divide(&result, a, detail::as_big_uint(b_unsigned), modulus);
            try {
                a = result;
            } catch (const std::range_error&) {
                throw std::overflow_error("big_uint: division overflow");
            }
            return a;
        }

        template<
            typename T1, typename T2,
            std::enable_if_t<(std::is_same_v<T1, big_uint> && is_integral_v<T2>) ||
                                 (std::is_integral_v<T1> && std::is_same_v<T2, big_uint>),
                             int> = 0>
        friend constexpr auto operator%(const T1& a, const T2& b) {
            decltype(auto) a_unsigned = unsigned_or_throw(a);
            decltype(auto) b_unsigned = unsigned_or_throw(b);
            using big_uint_a = std::decay_t<decltype(detail::as_big_uint(a_unsigned))>;
            big_uint_a modulus;
            detail::divide(static_cast<big_uint_a*>(nullptr),
                           detail::as_big_uint(a_unsigned),
                           detail::as_big_uint(b_unsigned), modulus);
            return static_cast<detail::largest_big_uint_t<T1, T2>>(modulus);
        }

        template<typename T, std::enable_if_t<is_integral_v<T>, int> = 0>
        friend constexpr auto& operator%=(big_uint& a, const T& b) {
            decltype(auto) b_unsigned = unsigned_or_throw(b);
            big_uint modulus;
            detail::divide(static_cast<big_uint*>(nullptr), a,
                           detail::as_big_uint(b_unsigned), modulus);
            a = modulus;
            return a;
        }

#define NIL_CO3_MP_BIG_UINT_BITWISE_OPERATOR_IMPL(OP, OP_ASSIGN_, METHOD_)      \
    template<typename T, std::enable_if_t<is_integral_v<T>, int> = 0>           \
    friend constexpr auto operator OP(const big_uint& a, const T& b) {         \
        detail::largest_big_uint_t<big_uint, T> result = a;                     \
        result.METHOD_(detail::as_limb_type_or_big_uint(unsigned_or_throw(b))); \
        return result;                                                          \
    }                                                                           \
                                                                                \
    template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>      \
    friend constexpr auto operator OP(const T& a, const big_uint& b) {         \
        return b OP a;                                                         \
    }                                                                           \
                                                                                \
    template<typename T, std::enable_if_t<is_integral_v<T>, int> = 0>           \
    friend constexpr auto& operator OP_ASSIGN_(big_uint & a, const T & b) {     \
        a.METHOD_(detail::as_limb_type_or_big_uint(unsigned_or_throw(b)));      \
        return a;                                                               \
    }

        NIL_CO3_MP_BIG_UINT_BITWISE_OPERATOR_IMPL(&, &=, bitwise_and)
        NIL_CO3_MP_BIG_UINT_BITWISE_OPERATOR_IMPL(|, |=, bitwise_or)
        NIL_CO3_MP_BIG_UINT_BITWISE_OPERATOR_IMPL(^, ^=, bitwise_xor)

#undef NIL_CO3_MP_BIG_UINT_BITWISE_OPERATOR_IMPL

        // Bitwise operations

      private:
        template<std::size_t Bits2, typename Op>
        constexpr void bitwise_op(const big_uint<Bits2>& o,
                                  Op op) noexcept(std::is_same_v<Op, std::bit_and<>>) {
            //
            // Both arguments are unsigned types, very simple case handled as a special
            // case.
            //
            // First figure out how big the result needs to be and set up some data:
            //
            constexpr std::size_t rs = static_limb_count;
            constexpr std::size_t os = std::decay_t<decltype(o)>::static_limb_count;
            constexpr std::size_t m = std::min(rs, os);

            limb_pointer pr = limbs();
            const_limb_pointer po = o.limbs();

            std::size_t i = 0;
            for (; i < m; ++i) {
                pr[i] = op(pr[i], po[i]);
            }
            for (; i < rs; ++i) {
                pr[i] = op(pr[i], static_cast<limb_type>(0u));
            }

            if constexpr (Bits2 > Bits && !std::is_same_v<Op, std::bit_and<>>) {
                for (; i < os; ++i) {
                    if (po[i] != 0) {
                        throw std::overflow_error("big_uint: bitwise_op overflow");
                    }
                }
                if (normalize()) {
                    throw std::overflow_error("big_uint: bitwise_op overflow");
                }
            }
        }

        template<std::size_t Bits2>
        NIL_CO3_MP_FORCEINLINE constexpr void bitwise_and(
            const big_uint<Bits2>& other) noexcept {
            bitwise_op(other, std::bit_and());
        }

        template<std::size_t Bits2>
        NIL_CO3_MP_FORCEINLINE constexpr void bitwise_or(const big_uint<Bits2>& other) {
            bitwise_op(other, std::bit_or());
        }

        template<std::size_t Bits2>
        NIL_CO3_MP_FORCEINLINE constexpr void bitwise_xor(const big_uint<Bits2>& other) {
            bitwise_op(other, std::bit_xor());
        }

        //
        // Again for operands which are single limbs:
        //

        NIL_CO3_MP_FORCEINLINE constexpr void bitwise_and(limb_type l) noexcept {
            limbs()[0] &= l;
            zero_after(1);
        }

        NIL_CO3_MP_FORCEINLINE constexpr void bitwise_or(limb_type l) {
            limbs()[0] |= l;
            if constexpr (static_limb_count == 1) {
                if (normalize()) {
                    throw std::overflow_error("big_uint: or overflow");
                }
            }
        }

        NIL_CO3_MP_FORCEINLINE constexpr void bitwise_xor(limb_type l) {
            limbs()[0] ^= l;
            if constexpr (static_limb_count == 1) {
                if (normalize()) {
                    throw std::overflow_error("big_uint: xor overflow");
                }
            }
        }

        NIL_CO3_MP_FORCEINLINE constexpr void complement(
            const big_uint<Bits>& other) noexcept {
            std::size_t os = other.limb_count();
            for (std::size_t i = 0; i < os; ++i) {
                limbs()[i] = ~other.limbs()[i];
            }
            normalize();
        }

        // Left shift will throw away upper Bits.
        // This function must be called only when s % 8 == 0, i.e. we shift bytes.
        void left_shift_byte(double_limb_type s) noexcept {
            limb_pointer pr = limbs();

            std::size_t bytes = static_cast<std::size_t>(s / CHAR_BIT);
            if (s >= Bits) {
                // Set result to 0.
                zero_after(0);
            } else {
                unsigned char* pc = reinterpret_cast<unsigned char*>(pr);
                std::memmove(pc + bytes, pc, limb_count() * sizeof(limb_type) - bytes);
                std::memset(pc, 0, bytes);
            }
        }

        // Left shift will throw away upper Bits.
        // This function must be called only when s % limb_bits == 0, i.e. we shift limbs,
        // which are normally 64 bit.

        constexpr void left_shift_limb(double_limb_type s) noexcept {
            limb_type offset = static_cast<limb_type>(s / limb_bits);
            BOOST_ASSERT(static_cast<limb_type>(s % limb_bits) == 0);

            limb_pointer pr = limbs();

            if (s >= Bits) {
                // Set result to 0.
                zero_after(0);
            } else {
                std::size_t i = offset;
                std::size_t rs = limb_count() + offset;
                for (; i < limb_count(); ++i) {
                    pr[rs - 1 - i] = pr[limb_count() - 1 - i];
                }
                for (; i < rs; ++i) {
                    pr[rs - 1 - i] = 0;
                }
            }
        }

        // Left shift will throw away upper Bits.

        constexpr void left_shift_generic(double_limb_type s) noexcept {
            if (s >= Bits) {
                // Set result to 0.
                zero_after(0);
            } else {
                limb_type offset = static_cast<limb_type>(s / limb_bits);
                limb_type shift = static_cast<limb_type>(s % limb_bits);

                limb_pointer pr = limbs();
                std::size_t i = 0;
                std::size_t rs = limb_count();
                // This code only works when shift is non-zero, otherwise we invoke
                // undefined behaviour!
                BOOST_ASSERT(shift);
                for (; rs - i >= 2 + offset; ++i) {
                    pr[rs - 1 - i] = pr[rs - 1 - i - offset] << shift;
                    pr[rs - 1 - i] |= pr[rs - 2 - i - offset] >> (limb_bits - shift);
                }
                if (rs - i >= 1 + offset) {
                    pr[rs - 1 - i] = pr[rs - 1 - i - offset] << shift;
                    ++i;
                }
                for (; i < rs; ++i) {
                    pr[rs - 1 - i] = 0;
                }
            }
        }

        void right_shift_byte(double_limb_type s) noexcept {
            limb_type offset = static_cast<limb_type>(s / limb_bits);
            BOOST_ASSERT((s % CHAR_BIT) == 0);
            std::size_t ors = limb_count();
            std::size_t rs = ors;
            if (offset >= rs) {
                zero_after(0);
                return;
            }
            rs -= offset;
            limb_pointer pr = limbs();
            unsigned char* pc = reinterpret_cast<unsigned char*>(pr);
            limb_type shift = static_cast<limb_type>(s / CHAR_BIT);
            std::memmove(pc, pc + shift, ors * sizeof(pr[0]) - shift);
            shift = (sizeof(limb_type) - shift % sizeof(limb_type)) * CHAR_BIT;
            if (shift < limb_bits) {
                pr[ors - offset - 1] &= (static_cast<limb_type>(1u) << shift) - 1;
                if (!pr[ors - offset - 1] && (rs > 1)) {
                    --rs;
                }
            }
            // Set zeros after 'rs', alternative to resizing to size 'rs'.
            zero_after(rs);
        }

        constexpr void right_shift_limb(double_limb_type s) noexcept {
            limb_type offset = static_cast<limb_type>(s / limb_bits);
            BOOST_ASSERT((s % limb_bits) == 0);
            std::size_t ors = limb_count();
            std::size_t rs = ors;
            if (offset >= rs) {
                zero_after(0);
                return;
            }
            rs -= offset;
            limb_pointer pr = limbs();
            std::size_t i = 0;
            for (; i < rs; ++i) {
                pr[i] = pr[i + offset];
            }
            // Set zeros after 'rs', alternative to resizing to size 'rs'.
            zero_after(rs);
        }

        constexpr void right_shift_generic(double_limb_type s) noexcept {
            limb_type offset = static_cast<limb_type>(s / limb_bits);
            limb_type shift = static_cast<limb_type>(s % limb_bits);
            std::size_t ors = limb_count();
            std::size_t rs = ors;

            if (offset >= rs) {
                *this = static_cast<limb_type>(0u);
                return;
            }
            rs -= offset;
            limb_pointer pr = limbs();
            if ((pr[ors - 1] >> shift) == 0) {
                if (--rs == 0) {
                    *this = static_cast<limb_type>(0u);
                    return;
                }
            }
            std::size_t i = 0;

            // This code only works for non-zero shift, otherwise we invoke undefined
            // behaviour!
            BOOST_ASSERT(shift);
            for (; i + offset + 1 < ors; ++i) {
                pr[i] = pr[i + offset] >> shift;
                pr[i] |= pr[i + offset + 1] << (limb_bits - shift);
            }
            pr[i] = pr[i + offset] >> shift;

            // We cannot resize any more, so we need to set all the limbs to zero.
            zero_after(rs);
        }

      public:
        constexpr auto operator~() const noexcept {
            big_uint result;
            result.complement(*this);
            return result;
        }

        // Shifting left throws away upper Bits.
        template<typename T>
        constexpr big_uint& operator<<=(T s_original) {
            static_assert(std::is_integral_v<T>);
            if (!s_original) {
                return *this;
            }
            auto s = unsigned_or_throw(s_original);

#if NIL_CO3_MP_ENDIAN_LITTLE_BYTE && defined(NIL_CO3_MP_USE_LIMB_SHIFT)
            constexpr limb_type limb_shift_mask = limb_bits - 1;
            constexpr limb_type byte_shift_mask = CHAR_BIT - 1;

            if ((s & limb_shift_mask) == 0) {
                left_shift_limb(s);
            } else if (((s & byte_shift_mask) == 0) && !std::is_constant_evaluated()) {
                left_shift_byte(s);
            }
#elif NIL_CO3_MP_ENDIAN_LITTLE_BYTE
            constexpr limb_type limb_shift_mask = limb_bits - 1;
            constexpr limb_type byte_shift_mask = CHAR_BIT - 1;

            if (std::is_constant_evaluated() && ((s & limb_shift_mask) == 0)) {
                left_shift_limb(s);
            } else if (((s & byte_shift_mask) == 0) && !std::is_constant_evaluated()) {
                left_shift_byte(s);
            }
#else
            constexpr limb_type limb_shift_mask = limb_bits - 1;

            if ((s & limb_shift_mask) == 0) {
                left_shift_limb(s);
            }
#endif
            else {
                left_shift_generic(s);
            }
            normalize();
            return *this;
        }

        template<typename T>
        constexpr big_uint operator<<(T s) const {
            big_uint result = *this;
            result <<= s;
            return result;
        }

        template<typename T>
        constexpr big_uint& operator>>=(T s_original) {
            static_assert(std::is_integral_v<T>);
            if (!s_original) {
                return *this;
            }
            auto s = unsigned_or_throw(s_original);

#if NIL_CO3_MP_ENDIAN_LITTLE_BYTE && defined(NIL_CO3_MP_USE_LIMB_SHIFT)
            constexpr limb_type limb_shift_mask = limb_bits - 1;
            constexpr limb_type byte_shift_mask = CHAR_BIT - 1;

            if ((s & limb_shift_mask) == 0) {
                right_shift_limb(s);
            } else if (((s & byte_shift_mask) == 0) && !std::is_constant_evaluated()) {
                right_shift_byte(s);
            }
#elif NIL_CO3_MP_ENDIAN_LITTLE_BYTE
            constexpr limb_type byte_shift_mask = CHAR_BIT - 1;

            constexpr limb_type limb_shift_mask = limb_bits - 1;
            if (std::is_constant_evaluated() && ((s & limb_shift_mask) == 0)) {
                right_shift_limb(s);
            } else if (((s & byte_shift_mask) == 0) && !std::is_constant_evaluated()) {
                right_shift_byte(s);
            }
#else
            constexpr limb_type limb_shift_mask = limb_bits - 1;

            if ((s & limb_shift_mask) == 0) {
                right_shift_limb(s);
            }
#endif
            else {
                right_shift_generic(s);
            }
            return *this;
        }

        template<typename T>
        constexpr big_uint operator>>(T s) const {
            big_uint result = *this;
            result >>= s;
            return result;
        }

        constexpr std::size_t lsb() const {
            //
            // Find the index of the least significant limb that is non-zero:
            //
            std::size_t index = 0;
            while ((index < limb_count()) && !limbs()[index]) {
                ++index;
            }

            if (index == limb_count()) {
                throw std::invalid_argument("zero has no lsb");
            }

            //
            // Find the index of the least significant bit within that limb:
            //
            std::size_t result = std::countr_zero(limbs()[index]);

            return result + index * limb_bits;
        }

        constexpr std::size_t msb() const {
            //
            // Find the index of the most significant bit that is non-zero:
            //
            for (std::size_t i = limb_count() - 1; i > 0; --i) {
                if (limbs()[i] != 0) {
                    return i * limb_bits + std::bit_width(limbs()[i]) - 1;
                }
            }
            if (limbs()[0] == 0) {
                throw std::invalid_argument("zero has no msb");
            }
            return std::bit_width(limbs()[0]) - 1;
        }

        constexpr bool bit_test(std::size_t index) const {
            if (index >= Bits) {
                // NB: we assume there are infinite leading zeros
                return false;
            }
            std::size_t offset = index / limb_bits;
            std::size_t shift = index % limb_bits;
            limb_type mask = limb_type(1u) << shift;
            return static_cast<bool>(limbs()[offset] & mask);
        }

        constexpr big_uint& bit_set(std::size_t index) {
            if (index >= Bits) {
                throw std::invalid_argument("fixed precision overflow");
            }
            std::size_t offset = index / limb_bits;
            std::size_t shift = index % limb_bits;
            limb_type mask = limb_type(1u) << shift;
            limbs()[offset] |= mask;
            return *this;
        }

        constexpr big_uint& bit_unset(std::size_t index) {
            if (index >= Bits) {
                throw std::invalid_argument("fixed precision overflow");
            }
            std::size_t offset = index / limb_bits;
            std::size_t shift = index % limb_bits;
            limb_type mask = limb_type(1u) << shift;
            limbs()[offset] &= ~mask;
            return *this;
        }

        constexpr big_uint& bit_flip(std::size_t index) {
            if (index >= Bits) {
                throw std::invalid_argument("fixed precision overflow");
            }
            std::size_t offset = index / limb_bits;
            std::size_t shift = index % limb_bits;
            limb_type mask = limb_type(1u) << shift;
            limbs()[offset] ^= mask;
            return *this;
        }

        // Import / export

      private:
        template<typename Unsigned>
        void assign_bits(Unsigned bits, std::size_t bit_location,
                         std::size_t chunk_bits) {
            std::size_t limb = bit_location / limb_bits;
            std::size_t shift = bit_location % limb_bits;

            limb_type mask = chunk_bits >= limb_bits
                                 ? ~static_cast<limb_type>(0u)
                                 : (static_cast<limb_type>(1u) << chunk_bits) - 1;

            limb_type value = static_cast<limb_type>(bits & mask) << shift;
            if (value) {
                if (limb >= limb_count()) {
                    throw std::overflow_error("import_bits: overflow");
                }
                limbs()[limb] |= value;
            }

            /* If some extra bits need to be assigned to the next limb */
            if (chunk_bits > limb_bits - shift) {
                shift = limb_bits - shift;
                chunk_bits -= shift;
                bit_location += shift;
                auto extra_bits = bits >> shift;
                if (extra_bits) {
                    assign_bits(extra_bits, bit_location, chunk_bits);
                }
            }
        }

        std::uintmax_t extract_bits(std::size_t location, std::size_t count) const {
            std::size_t limb = location / limb_bits;
            std::size_t shift = location % limb_bits;
            std::uintmax_t result = 0;
            std::uintmax_t mask = count == std::numeric_limits<std::uintmax_t>::digits
                                      ? ~static_cast<std::uintmax_t>(0)
                                      : (static_cast<std::uintmax_t>(1u) << count) - 1;
            if (count > (limb_bits - shift)) {
                result =
                    extract_bits(location + limb_bits - shift, count - limb_bits + shift);
                result <<= limb_bits - shift;
            }
            if (limb < limb_count()) {
                result |= (limbs()[limb] >> shift) & mask;
            }
            return result;
        }

        template<typename Iterator>
        void import_bits_generic(Iterator i, Iterator j, std::size_t chunk_size = 0,
                                 bool msv_first = true) {
            zero_after(0);

            using value_type = typename std::iterator_traits<Iterator>::value_type;
            using difference_type =
                typename std::iterator_traits<Iterator>::difference_type;
            using size_type = typename std::make_unsigned<difference_type>::type;

            if (!chunk_size) {
                chunk_size = std::numeric_limits<value_type>::digits;
            }

            size_type limbs = std::distance(i, j);
            size_type bits = limbs * chunk_size;

            difference_type bit_location = msv_first ? bits - chunk_size : 0;
            difference_type bit_location_change =
                msv_first ? -static_cast<difference_type>(chunk_size) : chunk_size;

            while (i != j) {
                assign_bits(*i, static_cast<std::size_t>(bit_location), chunk_size);
                ++i;
                bit_location += bit_location_change;
            }

            if (normalize()) {
                throw std::overflow_error("import_bits: overflow");
            }
        }

        template<typename T>
        void import_bits_fast(T* i, T* j) {
            std::size_t copy_len =
                (std::min)((j - i) * sizeof(T), limb_count() * sizeof(limb_type));

            if (std::any_of(reinterpret_cast<const unsigned char*>(i) + copy_len,
                            reinterpret_cast<const unsigned char*>(j),
                            [](char c) { return c != 0; })) {
                throw std::overflow_error("import_bits: overflow");
            }

            std::memcpy(reinterpret_cast<unsigned char*>(limbs()), i, copy_len);
            std::memset(reinterpret_cast<unsigned char*>(limbs()) + copy_len, 0,
                        limb_count() * sizeof(limb_type) - copy_len);

            if (normalize()) {
                throw std::overflow_error("import_bits: overflow");
            }
        }

      public:
        template<typename Iterator,
                 std::enable_if_t<!std::is_pointer_v<Iterator>, int> = 0>
        void import_bits(Iterator i, Iterator j, std::size_t chunk_size = 0,
                         bool msv_first = true) {
            return import_bits_generic(i, j, chunk_size, msv_first);
        }

        template<typename T>
        void import_bits(T* i, T* j, std::size_t chunk_size = 0, bool msv_first = true) {
#if NIL_CO3_MP_ENDIAN_LITTLE_BYTE
            if (((chunk_size % CHAR_BIT) == 0) && !msv_first &&
                (sizeof(*i) * CHAR_BIT == chunk_size)) {
                return import_bits_fast(i, j);
            }
#endif
            return import_bits_generic(i, j, chunk_size, msv_first);
        }

        template<typename OutputIterator>
        OutputIterator export_bits(OutputIterator out, std::size_t chunk_size,
                                   bool msv_first = true) const {
            if (!*this) {
                *out = 0;
                ++out;
                return out;
            }
            std::size_t bitcount = msb() + 1;

            std::ptrdiff_t bit_location =
                msv_first ? static_cast<std::ptrdiff_t>(bitcount) -
                                static_cast<std::ptrdiff_t>(chunk_size)
                          : 0;
            const std::ptrdiff_t bit_step =
                msv_first ? (-static_cast<std::ptrdiff_t>(chunk_size))
                          : static_cast<std::ptrdiff_t>(chunk_size);
            while (bit_location % bit_step) {
                ++bit_location;
            }
            do {
                *out = extract_bits(bit_location, chunk_size);
                ++out;
                bit_location += bit_step;
            } while ((bit_location >= 0) &&
                     (bit_location < static_cast<std::ptrdiff_t>(bitcount)));

            return out;
        }

        // Hash

        friend constexpr std::size_t hash_value(const big_uint& a) noexcept {
            std::size_t result = 0;
            for (std::size_t i = 0; i < a.limb_count(); ++i) {
                boost::hash_combine(result, a.limbs()[i]);
            }
            return result;
        }

        // IO

        friend constexpr std::ostream& operator<<(std::ostream& os, const big_uint& a) {
            os << a.str(os.flags());
            return os;
        }

        friend constexpr std::istream& operator>>(std::istream& is, big_uint& a) {
            std::string s;
            is >> s;
            a = s;
            return is;
        }

      private:
        // Data

        // m_data[0] contains the lowest bits.
        std::array<limb_type, static_limb_count> m_data{0};

        // Friends

        template<std::size_t Bits1>
        friend class big_uint;

        template<std::size_t Bits1, std::size_t Bits2, std::size_t Bits3>
        friend constexpr bool detail::add_unsigned_intrinsic(
            big_uint<Bits1>& result, const big_uint<Bits2>& a,
            const big_uint<Bits3>& b) noexcept;
        template<detail::overflow_policy OverflowPolicy, std::size_t Bits1,
                 std::size_t Bits2, std::size_t Bits3>
        friend constexpr bool detail::add_unsigned(big_uint<Bits1>& result,
                                                   const big_uint<Bits2>& a,
                                                   const big_uint<Bits3>& b);
        template<detail::overflow_policy OverflowPolicy, std::size_t Bits1,
                 std::size_t Bits2>
        friend constexpr bool detail::add_unsigned(big_uint<Bits1>& result,
                                                   const big_uint<Bits2>& a,
                                                   const limb_type& o);
        template<detail::overflow_policy OverflowPolicy, std::size_t Bits1,
                 std::size_t Bits2, std::size_t Bits3>
        friend constexpr void detail::subtract_unsigned_intrinsic(
            big_uint<Bits1>& result, const big_uint<Bits2>& a, const big_uint<Bits3>& b);
        template<detail::overflow_policy OverflowPolicy, bool GuaranteedGreater,
                 std::size_t Bits1, std::size_t Bits2, std::size_t Bits3>
        friend constexpr void detail::subtract_unsigned(big_uint<Bits1>& result,
                                                        const big_uint<Bits2>& a,
                                                        const big_uint<Bits3>& b);
        template<detail::overflow_policy OverflowPolicy, std::size_t Bits1,
                 std::size_t Bits2>
        friend constexpr void detail::subtract_unsigned(big_uint<Bits1>& result,
                                                        const big_uint<Bits2>& a,
                                                        const limb_type& b);
        template<detail::overflow_policy OverflowPolicy, std::size_t Bits1,
                 std::size_t Bits2>
        friend constexpr void detail::subtract_unsigned(big_uint<Bits1>& result,
                                                        const limb_type& a,
                                                        const big_uint<Bits2>& b);
        template<std::size_t Bits1, std::size_t Bits2>
        friend constexpr void detail::divide(big_uint<Bits1>* div,
                                             const big_uint<Bits1>& x,
                                             const big_uint<Bits2>& y,
                                             big_uint<Bits1>& rem);
        template<detail::overflow_policy OverflowPolicy, std::size_t Bits1,
                 std::size_t Bits2, typename T>
        friend constexpr void detail::multiply(big_uint<Bits1>& result,
                                               const big_uint<Bits2>& a, const T& b);

        template<std::size_t Bits1>
        friend struct detail::modular_policy;

        template<std::size_t Bits1>
        friend class detail::montgomery_modular_ops;
    };

    // For generic code

    template<std::size_t Bits>
    constexpr std::size_t lsb(const big_uint<Bits>& a) {
        return a.lsb();
    }

    template<std::size_t Bits>
    constexpr std::size_t msb(const big_uint<Bits>& a) {
        return a.msb();
    }

    template<std::size_t Bits>
    constexpr bool bit_test(const big_uint<Bits>& a, std::size_t index) {
        return a.bit_test(index);
    }

    template<std::size_t Bits>
    constexpr big_uint<Bits>& bit_set(big_uint<Bits>& a, std::size_t index) {
        return a.bit_set(index);
    }

    template<std::size_t Bits>
    constexpr big_uint<Bits>& bit_unset(big_uint<Bits>& a, std::size_t index) {
        return a.bit_unset(index);
    }

    template<std::size_t Bits>
    constexpr big_uint<Bits>& bit_flip(big_uint<Bits>& a, std::size_t index) {
        return a.bit_flip(index);
    }

    template<std::size_t Bits>
    constexpr bool is_zero(const big_uint<Bits>& a) {
        return a.is_zero();
    }

    // To efficiently compute quotient and remainder at the same time

    template<std::size_t Bits1, std::size_t Bits2>
    constexpr void divide_qr(const big_uint<Bits1>& a, const big_uint<Bits2>& b,
                             big_uint<Bits1>& q, big_uint<Bits1>& r) {
        detail::divide(&q, a, b, r);
    }

    using uint128_t = big_uint<128>;
    using uint256_t = big_uint<256>;
    using uint512_t = big_uint<512>;
    using uint1024_t = big_uint<1024>;
}  // namespace nil::crypto3::multiprecision

template<std::size_t Bits>
struct std::hash<nil::crypto3::multiprecision::big_uint<Bits>> {
    std::size_t operator()(
        const nil::crypto3::multiprecision::big_uint<Bits>& a) const noexcept {
        return boost::hash<nil::crypto3::multiprecision::big_uint<Bits>>{}(a);
    }
};
