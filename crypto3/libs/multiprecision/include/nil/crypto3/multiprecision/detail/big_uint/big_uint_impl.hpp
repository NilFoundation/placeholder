#pragma once

// IWYU pragma: private; include "nil/crypto3/multiprecision/big_uint.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cctype>
#include <charconv>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>

#include <boost/functional/hash.hpp>

#include "nil/crypto3/multiprecision/detail/assert.hpp"
#include "nil/crypto3/multiprecision/detail/big_uint/arithmetic.hpp"
#include "nil/crypto3/multiprecision/detail/big_uint/parsing.hpp"  // IWYU pragma: export
#include "nil/crypto3/multiprecision/detail/big_uint/storage.hpp"
#include "nil/crypto3/multiprecision/detail/big_uint/type_traits.hpp"  // IWYU pragma: export
#include "nil/crypto3/multiprecision/detail/config.hpp"
#include "nil/crypto3/multiprecision/detail/endian.hpp"
#include "nil/crypto3/multiprecision/detail/type_traits.hpp"
#include "nil/crypto3/multiprecision/detail/throw.hpp"

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
     * Addition and subtraction operations are optimized, while multiplication and division are not.
     * Multiplication and division should be used in compile time or in non-performance critical
     * code.
     * If you need fast arithmetic, you probably are looking for big_mod, which implements fast
     * modular arithmetic.
     */
    template<std::size_t Bits_>
    class big_uint {
      public:
        static constexpr std::size_t Bits = Bits_;
        using self_type = big_uint;

        using limb_type = detail::limb_type;
        using double_limb_type = detail::double_limb_type;
        using signed_limb_type = detail::signed_limb_type;
        using signed_double_limb_type = detail::signed_double_limb_type;

        // Storage

        using limb_pointer = detail::limb_pointer;
        using const_limb_pointer = detail::const_limb_pointer;
        static constexpr std::size_t limb_bits = detail::limb_bits;
        static constexpr limb_type max_limb_value = detail::max_limb_value;

        static constexpr std::size_t internal_limb_count =
            (Bits / limb_bits) + (((Bits % limb_bits) != 0u) ? 1u : 0u);
        static constexpr limb_type upper_limb_mask =
            (Bits % limb_bits) ? (limb_type(1) << (Bits % limb_bits)) - 1 : (~limb_type(0u));

        //
        // Helper functions for getting at our internal data, and manipulating storage:
        //
        constexpr std::size_t limbs_count() const noexcept {
            static_assert(internal_limb_count != 0, "No limbs in storage.");
            return internal_limb_count;
        }
        constexpr limb_pointer limbs() noexcept { return m_data.data(); }
        constexpr const_limb_pointer limbs() const noexcept { return m_data.data(); }
        constexpr auto& limbs_array() noexcept { return m_data; }
        constexpr const auto& limbs_array() const noexcept { return m_data; }

      private:
        // Zeros out everything after limb[i], replaces resizing.
        constexpr void zero_after(std::size_t start_index) {
            auto pr = this->limbs();
            for (std::size_t i = start_index; i < this->limbs_count(); ++i) {
                pr[i] = 0;
            }
        }

        constexpr std::size_t used_limbs() const noexcept {
            for (int i = internal_limb_count - 1; i >= 0; --i) {
                if (limbs()[i] != 0) {
                    return i + 1;
                }
            }
            return 0;
        }

        constexpr std::size_t order() const noexcept {
            for (int i = internal_limb_count - 1; i >= 0; --i) {
                if (limbs()[i] != 0) {
                    return i;
                }
            }
            return 0;
        }

        // Assignment

        template<typename T,
                 std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T> || std::is_same_v<T, unsigned __int128>, int> = 0>
        constexpr void do_assign_integral(const T& a) noexcept {
            if constexpr (sizeof(T) <= sizeof(limb_type)) {
                this->limbs()[0] = a;
                this->zero_after(1);
            } else {
                static_assert(sizeof(T) % sizeof(limb_type) == 0);
                constexpr std::size_t n =
                    std::min(internal_limb_count, sizeof(T) / sizeof(limb_type));
                auto a_copy = a;
                for (std::size_t i = 0; i < n; ++i) {
                    limbs()[i] = a_copy & static_cast<T>(static_cast<limb_type>(-1));
                    a_copy >>= limb_bits;
                }
                zero_after(n);
            }
            this->normalize();
            if constexpr (sizeof(T) * CHAR_BIT > Bits) {
                NIL_CO3_MP_ASSERT(big_uint<sizeof(T) * CHAR_BIT>(a).compare(*this) == 0);
            }
        }

        template<std::size_t Bits2>
        constexpr void do_assign(const big_uint<Bits2>& other) noexcept {
            std::size_t count = (std::min)(other.limbs_count(), this->limbs_count());
            for (std::size_t i = 0; i < count; ++i) {
                this->limbs()[i] = other.limbs()[i];
            }
            // Zero out everything after (std::min)(other.limbs_count(), limbs_count()), so if size
            // of other was less, we have 0s at the end.
            this->zero_after((std::min)(other.limbs_count(), this->limbs_count()));
            this->normalize();
        }

      public:
        // TODO(ioxid): this should be private
        constexpr void normalize() noexcept { limbs()[internal_limb_count - 1] &= upper_limb_mask; }

        constexpr bool has_carry() const noexcept { return m_carry; }
        constexpr void set_carry(bool carry) noexcept { m_carry = carry; }

        // Constructor

        constexpr big_uint() noexcept {}

        constexpr big_uint(std::string_view str) { *this = str; }
        constexpr big_uint(const char* str) { *this = str; }
        constexpr big_uint(const std::string &str) { *this = str; }

        template<class T, std::enable_if_t<std::is_integral_v<T> && std::is_signed_v<T>, int> = 0>
        constexpr big_uint(T val) noexcept {
            NIL_CO3_MP_ASSERT_MSG(val >= 0, "big_uint: assignment from negative integer");
            do_assign_integral(static_cast<std::make_unsigned_t<T>>(val));
        }

        template<class T, std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, int> = 0>
        constexpr big_uint(T val) noexcept {
            do_assign_integral(val);
        }

        // TODO(ioxid): make this explicit for the case when Bits2 > Bits
        template<std::size_t Bits2>
        constexpr big_uint(const big_uint<Bits2>& other) noexcept {
            do_assign(other);
            if constexpr (Bits2 > Bits) {
                NIL_CO3_MP_ASSERT(other.compare(*this) == 0);
            }
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
        constexpr big_uint& operator=(const std::string &str) {
            *this = detail::parse_int<Bits>(str);
            return *this;
        }

        template<typename T,
                 std::enable_if_t<std::is_integral_v<T> && std::is_signed_v<T>, int> = 0>
        constexpr big_uint& operator=(T val) noexcept {
            NIL_CO3_MP_ASSERT_MSG(val >= 0, "big_uint: assignment from negative integer");
            do_assign_integral(static_cast<std::make_unsigned_t<T>>(val));
            return *this;
        }

        template<typename T,
                 std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T> || std::is_same_v<T, unsigned __int128>, int> = 0>
        constexpr big_uint& operator=(T val) noexcept {
            do_assign_integral(val);
            return *this;
        }

        template<std::size_t Bits2>
        constexpr big_uint& operator=(const big_uint<Bits2>& other) noexcept {
            do_assign(other);
            if constexpr (Bits2 > Bits) {
                NIL_CO3_MP_ASSERT(other.compare(*this) == 0);
            }
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
                NIL_THROW(std::invalid_argument("not enough bits"));
            }
            return *this;
        }

        // String conversion

        constexpr std::string str(std::ios_base::fmtflags flags = std::ios_base::hex |
                                                                  std::ios_base::showbase |
                                                                  std::ios_base::uppercase) const {
            if (flags & std::ios_base::dec) {
                // TODO(ioxid): this is inefficient
                std::string result;
                auto copy = *this;
                while (!copy.is_zero()) {
                    result += static_cast<char>(static_cast<unsigned int>(copy % 10u) + '0');
                    copy /= 10u;
                }
                std::reverse(result.begin(), result.end());
                if (result.empty()) {
                    result += '0';
                }
                return result;
            }
            if (!(flags & std::ios_base::hex)) {
                NIL_THROW(std::invalid_argument("big_uint: unsupported format flags"));
            }
            std::string result;
            result.reserve(used_limbs() * limb_bits / 4);
            bool found_first = false;
            for (int i = internal_limb_count - 1; i >= 0; --i) {
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
                    NIL_CO3_MP_ASSERT(ec == std::errc{});
                }
            }
            if (flags & std::ios_base::uppercase) {
                for (std::size_t i = 0; i < result.size(); ++i) {
                    result[i] =
                        static_cast<char>(std::toupper(static_cast<unsigned char>(result[i])));
                }
            }
            if (result.size() == 0) {
                result += '0';
            }
            if (flags & std::ios_base::showbase) {
                result = "0x" + result;
            }
            return result;
        }

        template<std::size_t Bits2, std::enable_if_t<(Bits2 < Bits), int> = 0>
        constexpr big_uint<Bits2> truncate() const noexcept {
            big_uint<Bits2> result;
            result.do_assign(*this);
            return result;
        }

        // Cast to integral types

        template<typename T, std::enable_if_t<!std::is_same_v<T, bool> && std::is_integral_v<T> &&
                                                  std::is_unsigned_v<T>,
                                              int> = 0>
        explicit constexpr operator T() const {
            if constexpr (sizeof(T) <= sizeof(limb_type)) {
                return static_cast<T>(this->limbs()[0]);
            } else {
                constexpr std::size_t n =
                    std::min(sizeof(T) / sizeof(limb_type), internal_limb_count);
                T result = 0;
                for (std::size_t i = 0; i < n; ++i) {
                    result <<= limb_bits;
                    result |= limbs()[n - i - 1];
                }
                return result;
            }
        }

        template<typename T,
                 std::enable_if_t<std::is_integral_v<T> && std::is_signed_v<T>, int> = 0>
        explicit constexpr operator T() const {
            return static_cast<T>(static_cast<std::make_unsigned_t<T>>(*this));
        }

        explicit constexpr operator bool() const { return !is_zero(); }

        // Comparison

        template<std::size_t Bits2>
        constexpr int compare(const big_uint<Bits2>& b) const noexcept {
            std::size_t as = used_limbs();
            std::size_t bs = b.used_limbs();
            if (as != bs) {
                return as > bs ? 1 : -1;
            }
            auto pa = limbs();
            auto pb = b.limbs();
            for (auto i = static_cast<std::ptrdiff_t>(as) - 1; i >= 0; --i) {
                if (pa[i] != pb[i]) {
                    return pa[i] > pb[i] ? 1 : -1;
                }
            }
            return 0;
        }

        template<typename T,
                 std::enable_if_t<std::is_integral_v<T> && std::is_signed_v<T>, int> = 0>
        constexpr int compare(const T& b) const noexcept {
            if (b < 0) {
                return 1;
            }
            return compare(static_cast<std::make_unsigned_t<T>>(b));
        }

        template<typename T,
                 std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, int> = 0>
        constexpr int compare(const T& b) const noexcept {
            static_assert(sizeof(T) <= sizeof(double_limb_type));
            std::size_t s = used_limbs();
            if constexpr (sizeof(T) <= sizeof(limb_type)) {
                if (s > 1) {
                    return 1;
                }
                auto lmb = this->limbs()[0];
                return lmb == b ? 0 : lmb > b ? 1 : -1;
            } else {
                if (s > 2) {
                    return 1;
                }
                auto dbl = static_cast<double_limb_type>(*this);
                return dbl == b ? 0 : dbl > b ? 1 : -1;
            }
        }

        // Comparison

#define NIL_CO3_MP_BIG_UINT_IMPL_COMPARISON_OPERATOR(OP_)                        \
    template<typename T, std::enable_if_t<detail::is_integral_v<T>, int> = 0>    \
    constexpr bool operator OP_(const T& o) const noexcept {                     \
        return compare(o) OP_ 0;                                                 \
    }                                                                            \
                                                                                 \
    template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>       \
    friend constexpr bool operator OP_(const T& a, const big_uint& b) noexcept { \
        return (-(b.compare(a)))OP_ 0;                                           \
    }

        NIL_CO3_MP_BIG_UINT_IMPL_COMPARISON_OPERATOR(<)
        NIL_CO3_MP_BIG_UINT_IMPL_COMPARISON_OPERATOR(<=)
        NIL_CO3_MP_BIG_UINT_IMPL_COMPARISON_OPERATOR(>)
        NIL_CO3_MP_BIG_UINT_IMPL_COMPARISON_OPERATOR(>=)
        NIL_CO3_MP_BIG_UINT_IMPL_COMPARISON_OPERATOR(==)
        NIL_CO3_MP_BIG_UINT_IMPL_COMPARISON_OPERATOR(!=)

#undef NIL_CO3_MP_BIG_UINT_IMPL_COMPARISON_OPERATOR

        // Arithmetic operations

        constexpr void negate() noexcept {
            if (is_zero()) {
                return;
            }
            complement(*this);
            ++*this;
        }

        constexpr auto& operator++() noexcept {
            if (limbs()[0] < max_limb_value) {
                ++limbs()[0];
                if constexpr (Bits < limb_bits) {
                    normalize();
                }
            } else {
                detail::add(*this, *this, static_cast<limb_type>(1u));
            }
            return *this;
        }

        constexpr auto operator++(int) noexcept {
            auto copy = *this;
            ++*this;
            return copy;
        }

        NIL_CO3_MP_FORCEINLINE constexpr void decrement() noexcept {}

        constexpr auto operator+() const noexcept { return *this; }

        constexpr auto& operator--() noexcept {
            if (limbs()[0]) {
                --limbs()[0];
            } else {
                detail::subtract(*this, *this, static_cast<limb_type>(1u));
            }
            return *this;
        }
        constexpr auto operator--(int) noexcept {
            auto copy = *this;
            --*this;
            return copy;
        }

        constexpr big_uint operator-() const noexcept {
            big_uint result = *this;
            result.negate();
            return result;
        }

        // Arithmetic operations

        template<typename T, std::enable_if_t<detail::is_integral_v<T>, int> = 0>
        constexpr auto operator+(const T& b) const noexcept {
            detail::largest_big_uint_t<big_uint, T> result;
            detail::add(result, *this, b);
            return result;
        }

        template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
        friend constexpr auto operator+(const T& a, const big_uint& b) noexcept {
            return b + a;
        }

        template<typename T, std::enable_if_t<detail::is_integral_v<T>, int> = 0>
        constexpr auto& operator+=(const T& b) noexcept {
            detail::add(*this, *this, b);
            return *this;
        }

        template<typename T, std::enable_if_t<detail::is_integral_v<T>, int> = 0>
        constexpr auto operator-(const T& b) const noexcept {
            detail::largest_big_uint_t<big_uint, T> result;
            detail::subtract(result, *this, b);
            return result;
        }

        template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
        friend constexpr auto operator-(const T& a, const big_uint& b) noexcept {
            return (-b) + a;
        }

        template<typename T, std::enable_if_t<detail::is_integral_v<T>, int> = 0>
        constexpr auto& operator-=(const T& b) noexcept {
            detail::subtract(*this, *this, b);
            return *this;
        }

        template<typename T, std::enable_if_t<detail::is_integral_v<T>, int> = 0>
        constexpr auto operator*(const T& b) const noexcept {
            decltype(auto) b_unsigned = detail::unsigned_or_throw(b);
            detail::largest_big_uint_t<big_uint, T> result;
            detail::multiply(result, *this, detail::as_big_uint(b_unsigned));
            return result;
        }

        template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
        friend constexpr auto operator*(const T& a, const big_uint& b) noexcept {
            return b * a;
        }

        template<typename T, std::enable_if_t<detail::is_integral_v<T>, int> = 0>
        constexpr auto& operator*=(const T& b) noexcept {
            decltype(auto) b_unsigned = detail::unsigned_or_throw(b);
            big_uint result;
            detail::multiply(result, *this, detail::as_big_uint(b_unsigned));
            *this = result;
            return *this;
        }

        template<typename T1, typename T2,
                 std::enable_if_t<(std::is_same_v<T1, big_uint> && detail::is_integral_v<T2>) ||
                                      (std::is_integral_v<T1> && std::is_same_v<T2, big_uint>),
                                  int> = 0>
        friend constexpr auto operator/(const T1& a, const T2& b) noexcept {
            decltype(auto) a_unsigned = detail::unsigned_or_throw(a);
            decltype(auto) b_unsigned = detail::unsigned_or_throw(b);
            using big_uint_a = std::decay_t<decltype(detail::as_big_uint(a_unsigned))>;
            big_uint_a result;
            big_uint_a modulus;
            detail::divide(&result, detail::as_big_uint(a_unsigned),
                           detail::as_big_uint(b_unsigned), modulus);
            return static_cast<detail::largest_big_uint_t<T1, T2>>(result);
        }

        template<typename T, std::enable_if_t<detail::is_integral_v<T>, int> = 0>
        constexpr auto& operator/=(const T& b) noexcept {
            decltype(auto) b_unsigned = detail::unsigned_or_throw(b);
            big_uint result;
            big_uint modulus;
            detail::divide(&result, *this, detail::as_big_uint(b_unsigned), modulus);
            *this = result;
            return *this;
        }

        template<typename T1, typename T2,
                 std::enable_if_t<(std::is_same_v<T1, big_uint> && detail::is_integral_v<T2>) ||
                                      (std::is_integral_v<T1> && std::is_same_v<T2, big_uint>),
                                  int> = 0>
        friend constexpr auto operator%(const T1& a, const T2& b) {
            decltype(auto) a_unsigned = detail::unsigned_or_throw(a);
            decltype(auto) b_unsigned = detail::unsigned_or_throw(b);
            using big_uint_a = std::decay_t<decltype(detail::as_big_uint(a_unsigned))>;
            big_uint_a modulus;
            detail::divide(static_cast<big_uint_a*>(nullptr), detail::as_big_uint(a_unsigned),
                           detail::as_big_uint(b_unsigned), modulus);
            return static_cast<detail::largest_big_uint_t<T1, T2>>(modulus);
        }

        template<typename T, std::enable_if_t<detail::is_integral_v<T>, int> = 0>
        constexpr auto& operator%=(const T& b) {
            decltype(auto) b_unsigned = detail::unsigned_or_throw(b);
            big_uint modulus;
            detail::divide(static_cast<big_uint*>(nullptr), *this, detail::as_big_uint(b_unsigned),
                           modulus);
            *this = modulus;
            return *this;
        }

#define NIL_CO3_MP_BIG_UINT_BITWISE_OPERATOR_IMPL(OP_, OP_ASSIGN_, METHOD_)             \
    template<typename T, std::enable_if_t<detail::is_integral_v<T>, int> = 0>           \
    constexpr auto operator OP_(const T& b) const noexcept {                            \
        detail::largest_big_uint_t<big_uint, T> result = *this;                         \
        result.METHOD_(detail::as_limb_type_or_big_uint(detail::unsigned_or_throw(b))); \
        return result;                                                                  \
    }                                                                                   \
                                                                                        \
    template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>              \
    friend constexpr auto operator OP_(const T& a, const big_uint& b) noexcept {        \
        return b OP_ a;                                                                 \
    }                                                                                   \
                                                                                        \
    template<typename T, std::enable_if_t<detail::is_integral_v<T>, int> = 0>           \
    constexpr auto& operator OP_ASSIGN_(const T & b) noexcept {                         \
        METHOD_(detail::as_limb_type_or_big_uint(detail::unsigned_or_throw(b)));        \
        return *this;                                                                   \
    }

        NIL_CO3_MP_BIG_UINT_BITWISE_OPERATOR_IMPL(&, &=, bitwise_and)
        NIL_CO3_MP_BIG_UINT_BITWISE_OPERATOR_IMPL(|, |=, bitwise_or)
        NIL_CO3_MP_BIG_UINT_BITWISE_OPERATOR_IMPL(^, ^=, bitwise_xor)

#undef NIL_CO3_MP_BIG_UINT_BITWISE_OPERATOR_IMPL

        // Bitwise operations

      private:
        template<std::size_t Bits2, typename Op>
        constexpr void bitwise_op(const big_uint<Bits2>& o, Op op) noexcept {
            //
            // Both arguments are unsigned types, very simple case handled as a special case.
            //
            // First figure out how big the result needs to be and set up some data:
            //
            std::size_t rs = limbs_count();
            std::size_t os = o.limbs_count();
            auto [m, x] = std::minmax(rs, os);
            limb_pointer pr = limbs();
            const_limb_pointer po = o.limbs();
            for (std::size_t i = rs; i < x; ++i) {
                pr[i] = 0;
            }

            for (std::size_t i = 0; i < os; ++i) {
                pr[i] = op(pr[i], po[i]);
            }
            for (std::size_t i = os; i < x; ++i) {
                pr[i] = op(pr[i], static_cast<limb_type>(0u));
            }
            normalize();
        }

        template<std::size_t Bits2>
        NIL_CO3_MP_FORCEINLINE constexpr void bitwise_and(const big_uint<Bits2>& o) noexcept {
            bitwise_op(o, std::bit_and());
        }

        template<std::size_t Bits2>
        NIL_CO3_MP_FORCEINLINE constexpr void bitwise_or(const big_uint<Bits2>& o) noexcept {
            bitwise_op(o, std::bit_or());
        }

        template<std::size_t Bits2>
        NIL_CO3_MP_FORCEINLINE constexpr void bitwise_xor(const big_uint<Bits2>& o) noexcept {
            bitwise_op(o, std::bit_xor());
        }

        //
        // Again for operands which are single limbs:
        //

        NIL_CO3_MP_FORCEINLINE constexpr void bitwise_and(limb_type l) noexcept {
            limbs()[0] &= l;
            zero_after(1);
        }

        NIL_CO3_MP_FORCEINLINE constexpr void bitwise_or(limb_type l) noexcept { limbs()[0] |= l; }

        NIL_CO3_MP_FORCEINLINE constexpr void bitwise_xor(limb_type l) noexcept { limbs()[0] ^= l; }

        NIL_CO3_MP_FORCEINLINE constexpr void complement(const big_uint<Bits>& o) noexcept {
            std::size_t os = o.limbs_count();
            for (std::size_t i = 0; i < os; ++i) {
                limbs()[i] = ~o.limbs()[i];
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
                std::memmove(pc + bytes, pc, limbs_count() * sizeof(limb_type) - bytes);
                std::memset(pc, 0, bytes);
            }
        }

        // Left shift will throw away upper Bits.
        // This function must be called only when s % limb_bits == 0, i.e. we shift limbs, which
        // are normally 64 bit.

        constexpr void left_shift_limb(double_limb_type s) noexcept {
            limb_type offset = static_cast<limb_type>(s / limb_bits);
            NIL_CO3_MP_ASSERT(static_cast<limb_type>(s % limb_bits) == 0);

            limb_pointer pr = limbs();

            if (s >= Bits) {
                // Set result to 0.
                zero_after(0);
            } else {
                std::size_t i = offset;
                std::size_t rs = limbs_count() + offset;
                for (; i < limbs_count(); ++i) {
                    pr[rs - 1 - i] = pr[limbs_count() - 1 - i];
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
                std::size_t rs = limbs_count();
                // This code only works when shift is non-zero, otherwise we invoke undefined
                // behaviour!
                NIL_CO3_MP_ASSERT(shift);
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
            NIL_CO3_MP_ASSERT((s % CHAR_BIT) == 0);
            std::size_t ors = limbs_count();
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
            NIL_CO3_MP_ASSERT((s % limb_bits) == 0);
            std::size_t ors = limbs_count();
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
            std::size_t ors = limbs_count();
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

            // This code only works for non-zero shift, otherwise we invoke undefined behaviour!
            NIL_CO3_MP_ASSERT(shift);
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
        constexpr big_uint& operator<<=(double_limb_type s) noexcept {
            if (!s) {
                return *this;
            }

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

        constexpr big_uint operator<<(double_limb_type s) const noexcept {
            big_uint result = *this;
            result <<= s;
            return result;
        }

        constexpr big_uint& operator>>=(double_limb_type s) noexcept {
            if (!s) {
                return *this;
            }

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

        constexpr big_uint operator>>(double_limb_type s) const noexcept {
            big_uint result = *this;
            result >>= s;
            return result;
        }

        // IO

        friend std::ostream& operator<<(std::ostream& os, const big_uint& value) {
            os << value.str(os.flags());
            return os;
        }

        // Misc ops

        NIL_CO3_MP_FORCEINLINE constexpr bool is_zero() const noexcept {
            for (std::size_t i = 0; i < limbs_count(); ++i) {
                if (limbs()[i] != 0) {
                    return false;
                }
            }
            return true;
        }

        constexpr std::size_t lsb() const {
            //
            // Find the index of the least significant limb that is non-zero:
            //
            std::size_t index = 0;
            while ((index < limbs_count()) && !limbs()[index]) {
                ++index;
            }

            if (index == limbs_count()) {
                NIL_THROW(std::invalid_argument("zero has no lsb"));
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
            for (std::size_t i = limbs_count() - 1; i > 0; --i) {
                if (limbs()[i] != 0) {
                    return i * limb_bits + std::bit_width(limbs()[i]) - 1;
                }
            }
            if (limbs()[0] == 0) {
                NIL_THROW(std::invalid_argument("zero has no msb"));
            }
            return std::bit_width(limbs()[0]) - 1;
        }

        constexpr bool bit_test(std::size_t index) const {
            if (index >= Bits) {
                return false;
                // TODO(ioxid): this throws in multiexp tests
                // NIL_THROW(std::invalid_argument("fixed precision overflow"));
            }
            std::size_t offset = index / limb_bits;
            std::size_t shift = index % limb_bits;
            limb_type mask = limb_type(1u) << shift;
            return static_cast<bool>(limbs()[offset] & mask);
        }

        constexpr void bit_set(std::size_t index) {
            if (index >= Bits) {
                NIL_THROW(std::invalid_argument("fixed precision overflow"));
            }
            std::size_t offset = index / limb_bits;
            std::size_t shift = index % limb_bits;
            limb_type mask = limb_type(1u) << shift;
            limbs()[offset] |= mask;
        }

        constexpr void bit_unset(std::size_t index) {
            if (index >= Bits) {
                NIL_THROW(std::invalid_argument("fixed precision overflow"));
            }
            std::size_t offset = index / limb_bits;
            std::size_t shift = index % limb_bits;
            limb_type mask = limb_type(1u) << shift;
            limbs()[offset] &= ~mask;
        }

        constexpr void bit_flip(big_uint<Bits>& val, std::size_t index) {
            if (index >= Bits) {
                NIL_THROW(std::invalid_argument("fixed precision overflow"));
            }
            std::size_t offset = index / limb_bits;
            std::size_t shift = index % limb_bits;
            limb_type mask = limb_type(1u) << shift;
            val.limbs()[offset] ^= mask;
        }

      private:
        // Data

        // m_data[0] contains the lowest bits.
        std::array<limb_type, internal_limb_count> m_data{0};

        // This is a temporary value which is set when carry has happend during addition.
        // If this value is true, reduction by modulus must happen next.
        bool m_carry = false;

        // Friends

        template<std::size_t>
        friend class big_uint;

        template<std::size_t Bits1, std::size_t Bits2, std::size_t Bits3>
        friend constexpr void detail::add_constexpr_unsigned(big_uint<Bits1>& result,
                                                             const big_uint<Bits2>& a,
                                                             const big_uint<Bits3>& b) noexcept;
        template<std::size_t Bits1, std::size_t Bits2, std::size_t Bits3>
        friend constexpr void detail::subtract_constexpr_unsigned(
            big_uint<Bits1>& result, const big_uint<Bits2>& a, const big_uint<Bits3>& b) noexcept;
        template<std::size_t Bits1, std::size_t Bits2, std::size_t Bits3>
        friend constexpr void detail::add_unsigned(big_uint<Bits1>& result,
                                                   const big_uint<Bits2>& a,
                                                   const big_uint<Bits3>& b) noexcept;
        template<std::size_t Bits1, std::size_t Bits2, std::size_t Bits3>
        friend constexpr void detail::subtract_unsigned(big_uint<Bits1>& result,
                                                        const big_uint<Bits2>& a,
                                                        const big_uint<Bits3>& b) noexcept;
        template<std::size_t Bits1, std::size_t Bits2>
        friend constexpr void detail::add_unsigned(big_uint<Bits1>& result,
                                                   const big_uint<Bits2>& a,
                                                   const limb_type& o) noexcept;
        template<std::size_t Bits1, std::size_t Bits2>
        friend constexpr void detail::subtract_unsigned(big_uint<Bits1>& result,
                                                        const big_uint<Bits2>& a,
                                                        const limb_type& b) noexcept;
        template<std::size_t Bits1, std::size_t Bits2>
        friend constexpr void detail::divide(big_uint<Bits1>* div, const big_uint<Bits1>& x,
                                             const big_uint<Bits2>& y, big_uint<Bits1>& rem);
        template<std::size_t Bits1, std::size_t Bits2, typename T>
        friend constexpr void detail::multiply(big_uint<Bits1>& result, const big_uint<Bits2>& a,
                                               const T& b) noexcept;
    };

    // Hash

    template<std::size_t Bits>
    constexpr std::size_t hash_value(const big_uint<Bits>& val) noexcept {
        std::size_t result = 0;
        for (std::size_t i = 0; i < val.limbs_count(); ++i) {
            boost::hash_combine(result, val.limbs()[i]);
        }
        return result;
    }

    // Misc ops

    template<std::size_t Bits>
    constexpr std::size_t msb(const big_uint<Bits>& a) {
        return a.msb();
    }

    template<std::size_t Bits>
    constexpr std::size_t lsb(const big_uint<Bits>& a) {
        return a.lsb();
    }

    template<std::size_t Bits>
    constexpr bool bit_test(const big_uint<Bits>& a, std::size_t index) {
        return a.bit_test(index);
    }

    template<std::size_t Bits>
    constexpr bool is_zero(const big_uint<Bits>& a) {
        return a.is_zero();
    }

    template<std::size_t Bits1, std::size_t Bits2>
    constexpr void divide_qr(const big_uint<Bits1>& a, const big_uint<Bits2>& b, big_uint<Bits1>& q,
                             big_uint<Bits1>& r) {
        detail::divide(&q, a, b, r);
    }
}  // namespace nil::crypto3::multiprecision

template<std::size_t Bits>
struct std::hash<nil::crypto3::multiprecision::big_uint<Bits>> {
    std::size_t operator()(const nil::crypto3::multiprecision::big_uint<Bits>& a) const noexcept {
        return boost::hash<nil::crypto3::multiprecision::big_uint<Bits>>{}(a);
    }
};
