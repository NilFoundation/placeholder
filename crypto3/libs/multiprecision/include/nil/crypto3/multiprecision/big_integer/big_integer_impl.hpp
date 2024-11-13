#pragma once

// IWYU pragma: private; include "nil/crypto3/multiprecision/big_integer/big_integer.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <boost/functional/hash.hpp>
#include <cctype>
#include <charconv>
#include <climits>
#include <cstddef>
#include <cstring>
#include <exception>
#include <functional>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>

#include "nil/crypto3/multiprecision/big_integer/detail/assert.hpp"
#include "nil/crypto3/multiprecision/big_integer/detail/config.hpp"
#include "nil/crypto3/multiprecision/big_integer/detail/endian.hpp"
#include "nil/crypto3/multiprecision/big_integer/detail/intel_intrinsics.hpp"
#include "nil/crypto3/multiprecision/big_integer/storage.hpp"

namespace nil::crypto3::multiprecision {
    template<std::size_t Bits>
    class big_integer;

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

        template<std::size_t Bits>
        constexpr big_integer<Bits> parse_int_hex(std::string_view str) {
            if (str.size() < 2 || str[0] != '0' || str[1] != 'x') {
                throw std::invalid_argument("hex literal should start with 0x");
            }

            big_integer<Bits> result{0};

            std::size_t bits = 0;
            for (std::size_t i = 2; i < str.size(); ++i) {
                char c = str[i];
                if (!is_valid_hex_digit(c)) {
                    throw std::invalid_argument("non-hex character in literal");
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
                throw std::invalid_argument("not enough bits to store literal");
            }
            return result;
        }

        template<std::size_t Bits>
        constexpr big_integer<Bits> parse_int_decimal(std::string_view str) {
            big_integer<Bits> result{0};

            for (std::size_t i = 0; i < str.size(); ++i) {
                char c = str[i];
                if (c < '0' || c > '9') {
                    throw std::invalid_argument("non decimal character in literal");
                }
                result *= 10;
                result += c - '0';
            }
            return result;
        }

        template<std::size_t Bits>
        constexpr big_integer<Bits> parse_int(std::string_view str) {
            if (str.size() >= 2 && str[0] == '0' && str[1] == 'x') {
                return parse_int_hex<Bits>(str);
            }
            return parse_int_decimal<Bits>(str);
        }
    }  // namespace detail

    template<std::size_t Bits_>
    class big_integer {
      public:
        constexpr static std::size_t Bits = Bits_;
        using self_type = big_integer;

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
        inline constexpr std::size_t size() const noexcept {
            static_assert(internal_limb_count != 0, "No limbs in storage.");
            return internal_limb_count;
        }
        inline constexpr limb_pointer limbs() noexcept { return m_data.data(); }
        inline constexpr const_limb_pointer limbs() const noexcept { return m_data.data(); }
        inline constexpr auto& limbs_array() noexcept { return m_data; }
        inline constexpr const auto& limbs_array() const noexcept { return m_data; }
        inline constexpr bool sign() const noexcept { return false; }

        // Zeros out everything after limb[i], replaces resizing.
        inline constexpr void zero_after(std::size_t start_index) {
            auto pr = this->limbs();
            for (std::size_t i = start_index; i < this->size(); ++i) {
                pr[i] = 0;
            }
        }
        inline constexpr bool has_carry() const noexcept { return m_carry; }
        inline constexpr void set_carry(bool carry) noexcept { m_carry = carry; }

        inline constexpr void normalize() noexcept {
            limbs()[internal_limb_count - 1] &= upper_limb_mask;
        }

        // Constructor

        inline constexpr big_integer() noexcept {}

        inline constexpr big_integer(const char* str) { *this = str; }

        template<class T,
                 std::enable_if_t<std::is_integral_v<T> /*&& std::is_unsigned_v<T>*/, int> = 0>
        inline constexpr big_integer(T val) noexcept {
            if (val < 0) {
                std::cerr << "big_integer: assignment from negative integer" << std::endl;
                std::terminate();
            }
            do_assign_integral(static_cast<std::make_unsigned_t<T>>(val));
        }

        // This should be implicit even for Bits2 < Bits because it's used in boost random
        template<std::size_t Bits2>
        inline constexpr big_integer(const big_integer<Bits2>& other) noexcept {
            do_assign(other);
            if constexpr (Bits2 > Bits) {
                NIL_CO3_MP_ASSERT(other.compare(*this) == 0);
            }
        }

        // Assignment

        inline constexpr big_integer& operator=(const char* str) {
            *this = detail::parse_int<Bits>(str);
            return *this;
        }

        template<std::size_t Bits2>
        inline constexpr big_integer& operator=(const big_integer<Bits2>& other) noexcept {
            do_assign(other);
            if constexpr (Bits2 > Bits) {
                NIL_CO3_MP_ASSERT(other.compare(*this) == 0);
            }
            return *this;
        }

        template<typename T,
                 std::enable_if_t<std::is_integral_v<T> /*&& std::is_unsigned_v<T>*/, int> = 0>
        inline constexpr big_integer& operator=(T val) noexcept {
            NIL_CO3_MP_ASSERT_MSG(val >= 0, "big_integer: assignment from negative integer");
            do_assign_integral(static_cast<std::make_unsigned_t<T>>(val));
            return *this;
        }

        inline std::string str() const {
            std::string result;
            result.reserve(order() * limb_bits / 4 + 2);
            result += "0x";
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
            for (std::size_t i = 2; i < result.size(); ++i) {
                result[i] = static_cast<char>(std::toupper(static_cast<unsigned char>(result[i])));
            }
            if (result.size() == 2) {
                result += '0';
            }
            return result;
        }

        template<std::size_t Bits2, std::enable_if_t<(Bits2 < Bits), int> = 0>
        inline constexpr big_integer<Bits2> truncate() const noexcept {
            big_integer<Bits2> result;
            result.do_assign(*this);
            return result;
        }

        // Cast to integral types

        template<typename T,
                 std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, int> = 0>
        explicit inline constexpr operator T() const {
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

        // Comparisions

        inline constexpr int compare(const big_integer& b) const noexcept {
            auto pa = limbs();
            auto pb = b.limbs();
            for (int i = size() - 1; i >= 0; --i) {
                if (pa[i] != pb[i]) {
                    return pa[i] > pb[i] ? 1 : -1;
                }
            }
            return 0;
        }

        // Arithmetic operations

        // Addition/subtraction

      private:
        static inline constexpr void add_constexpr(big_integer& result, const big_integer& a,
                                                   const big_integer& b) noexcept {
            //
            // This is the generic, C++ only version of addition.
            // It's also used for all constexpr branches, hence the name.
            // Nothing fancy, just let uintmax_t take the strain:
            //
            double_limb_type carry = 0;
            std::size_t s = a.size();
            if (s == 1) {
                double_limb_type r = static_cast<double_limb_type>(*a.limbs()) +
                                     static_cast<double_limb_type>(*b.limbs());
                double_limb_type mask = big_integer::upper_limb_mask;
                if (r & ~mask) {
                    result = r & mask;
                    result.set_carry(true);
                } else {
                    result = r;
                }
                return;
            }

            const_limb_pointer pa = a.limbs();
            const_limb_pointer pb = b.limbs();
            limb_pointer pr = result.limbs();

            // First where a and b overlap:
            for (std::size_t i = 0; i < s; ++i) {
                carry += static_cast<double_limb_type>(*pa) + static_cast<double_limb_type>(*pb);
                *pr = static_cast<limb_type>(carry);
                carry >>= big_integer::limb_bits;
                ++pr, ++pa, ++pb;
            }
            if constexpr (Bits % big_integer::limb_bits == 0) {
                result.set_carry(carry);
            } else {
                limb_type mask = big_integer::upper_limb_mask;
                // If we have set any bit above "Bits", then we have a carry.
                if (result.limbs()[s - 1] & ~mask) {
                    result.limbs()[s - 1] &= mask;
                    result.set_carry(true);
                }
            }
        }

        //
        // Core subtraction routine:
        // It is the caller's responsibility to make sure that a >= b.
        //
        static inline constexpr void subtract_constexpr(big_integer& result, const big_integer& a,
                                                        const big_integer& b) noexcept {
            NIL_CO3_MP_ASSERT(a >= b);

            //
            // This is the generic, C++ only version of subtraction.
            // It's also used for all constexpr branches, hence the name.
            // Nothing fancy, just let uintmax_t take the strain:
            //
            std::size_t s = a.size();
            if (s == 1) {
                result = *a.limbs() - *b.limbs();
                return;
            }
            const_limb_pointer pa = a.limbs();
            const_limb_pointer pb = b.limbs();
            limb_pointer pr = result.limbs();

            double_limb_type borrow = 0;
            // First where a and b overlap:
            for (std::size_t i = 0; i < s; ++i) {
                borrow = static_cast<double_limb_type>(pa[i]) -
                         static_cast<double_limb_type>(pb[i]) - borrow;
                pr[i] = static_cast<limb_type>(borrow);
                borrow = (borrow >> big_integer::limb_bits) & 1u;
            }
            // if a > b, then borrow must be 0 at the end.
            NIL_CO3_MP_ASSERT(0 == borrow);
        }

      public:
#ifdef NIL_CO3_MP_HAS_IMMINTRIN_H
        //
        // This is the key addition routine:
        //
        //
        // This optimization is limited to: GCC, LLVM, ICC (Intel), MSVC for x86_64 and i386.
        // If your architecture and compiler supports ADC intrinsic, please file a bug.
        //
        // As of May, 2020 major compilers don't recognize carry chain though adc
        // intrinsics are used to hint compilers to use ADC and still compilers don't
        // unroll the loop efficiently (except LLVM) so manual unrolling is done.
        //
        // Also note that these intrinsics were only introduced by Intel as part of the
        // ADX processor extensions, even though the addc instruction has been available
        // for basically all x86 processors.  That means gcc-9, clang-9, msvc-14.2 and up
        // are required to support these intrinsics.
        //
        static inline constexpr void add(big_integer& result, const big_integer& a,
                                         const big_integer& b) noexcept {
            if (std::is_constant_evaluated()) {
                add_constexpr(result, a, b);
            } else {
                // Nothing fancy, just let uintmax_t take the strain:
                std::size_t as = a.used_limbs();
                std::size_t bs = b.used_limbs();
                auto [m, x] = std::minmax(as, bs);

                if (x == 1) {
                    double_limb_type v = static_cast<double_limb_type>(*a.limbs()) +
                                         static_cast<double_limb_type>(*b.limbs());
                    if (result.size() == 1) {
                        double_limb_type mask = big_integer::upper_limb_mask;
                        if (v & ~mask) {
                            v &= mask;
                            result.set_carry(true);
                        }
                    }
                    result = v;
                    return;
                }
                const_limb_pointer pa = a.limbs();
                const_limb_pointer pb = b.limbs();
                limb_pointer pr = result.limbs();

                if (as < bs) {
                    std::swap(pa, pb);
                }

                std::size_t i = 0;
                unsigned char carry = 0;
                for (; i + 4 <= m; i += 4) {
                    carry = detail::addcarry_limb(carry, pa[i + 0], pb[i + 0], pr + i);
                    carry = detail::addcarry_limb(carry, pa[i + 1], pb[i + 1], pr + i + 1);
                    carry = detail::addcarry_limb(carry, pa[i + 2], pb[i + 2], pr + i + 2);
                    carry = detail::addcarry_limb(carry, pa[i + 3], pb[i + 3], pr + i + 3);
                }
                for (; i < m; ++i) {
                    carry = detail::addcarry_limb(carry, pa[i], pb[i], pr + i);
                }
                for (; i < x && carry; ++i) {
                    // We know carry is 1, so we just need to increment pa[i] (ie add a literal 1)
                    // and capture the carry:
                    carry = detail::addcarry_limb(0, pa[i], 1, pr + i);
                }
                if (i == x && carry) {
                    if (internal_limb_count > x) {
                        result.limbs()[x] = static_cast<limb_type>(1u);
                    }
                } else if (x != i) {
                    // Copy remaining digits only if we need to:
                    std::copy(pa + i, pa + x, pr + i);
                }

                if constexpr (Bits % big_integer::limb_bits == 0) {
                    result.set_carry(carry);
                } else {
                    limb_type mask = big_integer::upper_limb_mask;
                    // If we have set any bit above "Bits", then we have a carry.
                    if (result.limbs()[result.size() - 1] & ~mask) {
                        result.limbs()[result.size() - 1] &= mask;
                        result.set_carry(true);
                    }
                }
            }
        }

        // It is the caller's responsibility to make sure that a > b.
        static inline constexpr void subtract(big_integer& result, const big_integer& a,
                                              const big_integer& b) noexcept {
            NIL_CO3_MP_ASSERT(a.compare(b) >= 0);

            if (std::is_constant_evaluated()) {
                subtract_constexpr(result, a, b);
            } else {
                // Nothing fancy, just let uintmax_t take the strain:
                std::size_t m = b.used_limbs();
                std::size_t x = a.used_limbs();

                //
                // special cases for small limb counts:
                //
                if (x == 1) {
                    result = *a.limbs() - *b.limbs();
                    return;
                }
                // Now that a, b, and result are stable, get pointers to their limbs:
                const_limb_pointer pa = a.limbs();
                const_limb_pointer pb = b.limbs();
                limb_pointer pr = result.limbs();

                std::size_t i = 0;
                unsigned char borrow = 0;
                // First where a and b overlap:
                for (; i + 4 <= m; i += 4) {
                    borrow = detail::subborrow_limb(borrow, pa[i], pb[i], pr + i);
                    borrow = detail::subborrow_limb(borrow, pa[i + 1], pb[i + 1], pr + i + 1);
                    borrow = detail::subborrow_limb(borrow, pa[i + 2], pb[i + 2], pr + i + 2);
                    borrow = detail::subborrow_limb(borrow, pa[i + 3], pb[i + 3], pr + i + 3);
                }
                for (; i < m; ++i) {
                    borrow = detail::subborrow_limb(borrow, pa[i], pb[i], pr + i);
                }
                while (borrow && (i < x)) {
                    borrow = detail::subborrow_limb(borrow, pa[i], 0, pr + i);
                    ++i;
                }
                // Any remaining digits are the same as those in pa:
                if ((x != i) && (pa != pr)) {
                    std::copy(pa + i, pa + x, pr + i);
                }
                NIL_CO3_MP_ASSERT(0 == borrow);
            }  // constexpr.
        }

#else

        static inline constexpr void add(big_integer& result, const big_integer& a,
                                         const big_integer& b) noexcept {
            add_constexpr(result, a, b);
        }

        static inline constexpr void subtract(big_integer& result, const big_integer& a,
                                              const big_integer& b) noexcept {
            subtract_constexpr(result, a, b);
        }

#endif

        static inline constexpr void add(big_integer& result, const big_integer& a,
                                         const limb_type& o) noexcept {
            // Addition using modular arithmetic.
            // Nothing fancy, just let uintmax_t take the strain:

            double_limb_type carry = o;
            limb_pointer pr = result.limbs();
            const_limb_pointer pa = a.limbs();
            unsigned i = 0;
            // Addition with carry until we either run out of digits or carry is zero:
            for (; carry && (i < result.size()); ++i) {
                carry += static_cast<double_limb_type>(pa[i]);
                pr[i] = static_cast<limb_type>(carry);
                carry >>= big_integer::limb_bits;
            }
            // Just copy any remaining digits:
            if (&a != &result) {
                std::copy(pa + i, pa + a.size(), pr + i);
            }
            if constexpr (Bits % big_integer::limb_bits == 0) {
                result.set_carry(carry);
            } else {
                limb_type mask = big_integer::upper_limb_mask;
                // If we have set any bit above "Bits", then we have a carry.
                if (pr[result.size() - 1] & ~mask) {
                    pr[result.size() - 1] &= mask;
                    result.set_carry(true);
                }
            }
        }

        //
        // And again to subtract a single limb: caller is responsible to check that a > b and
        // the result is non-negative.
        //
        static inline constexpr void subtract(big_integer& result, const big_integer& a,
                                              const limb_type& b) noexcept {
            NIL_CO3_MP_ASSERT(a >= b);

            // Subtract one limb.
            // Nothing fancy, just let uintmax_t take the strain:
            constexpr double_limb_type borrow =
                static_cast<double_limb_type>(big_integer::max_limb_value) + 1;
            limb_pointer pr = result.limbs();
            const_limb_pointer pa = a.limbs();
            if (*pa >= b) {
                *pr = *pa - b;
                if (&result != &a) {
                    std::copy(pa + 1, pa + a.size(), pr + 1);
                }
            } else if (result.size() == 1) {
                *pr = b - *pa;
            } else {
                *pr = static_cast<limb_type>((borrow + *pa) - b);
                unsigned i = 1;
                while (!pa[i]) {
                    pr[i] = big_integer::max_limb_value;
                    ++i;
                }
                pr[i] = pa[i] - 1;
                if (&result != &a) {
                    ++i;
                    std::copy(pa + i, pa + a.size(), pr + i);
                }
            }
        }

        NIL_CO3_MP_FORCEINLINE constexpr void increment() noexcept {
            if (limbs()[0] < big_integer::max_limb_value) {
                ++limbs()[0];
            } else {
                add(*this, *this, static_cast<limb_type>(1u));
            }
        }

        NIL_CO3_MP_FORCEINLINE constexpr void decrement() noexcept {
            if (limbs()[0]) {
                --limbs()[0];
            } else {
                subtract(*this, *this, static_cast<limb_type>(1u));
            }
        }

        // Bitwise

        template<typename Op>
        static constexpr void bitwise_op(big_integer& result, const big_integer& o,
                                         Op op) noexcept {
            //
            // Both arguments are unsigned types, very simple case handled as a special case.
            //
            // First figure out how big the result needs to be and set up some data:
            //
            unsigned rs = result.size();
            unsigned os = o.size();
            auto [m, x] = std::minmax(rs, os);
            limb_pointer pr = result.limbs();
            const_limb_pointer po = o.limbs();
            for (unsigned i = rs; i < x; ++i) {
                pr[i] = 0;
            }

            for (unsigned i = 0; i < os; ++i) {
                pr[i] = op(pr[i], po[i]);
            }
            for (unsigned i = os; i < x; ++i) {
                pr[i] = op(pr[i], limb_type(0));
            }
            result.normalize();
        }

        NIL_CO3_MP_FORCEINLINE static constexpr void bitwise_and(big_integer& result,
                                                                 const big_integer& o) noexcept {
            bitwise_op(result, o, std::bit_and());
        }

        NIL_CO3_MP_FORCEINLINE static constexpr void bitwise_or(big_integer& result,
                                                                const big_integer& o) noexcept {
            bitwise_op(result, o, std::bit_or());
        }

        NIL_CO3_MP_FORCEINLINE static constexpr void bitwise_xor(big_integer& result,
                                                                 const big_integer& o) noexcept {
            bitwise_op(result, o, std::bit_xor());
        }
        //
        // Again for operands which are single limbs:
        //
        NIL_CO3_MP_FORCEINLINE static constexpr void bitwise_and(big_integer& result,
                                                                 limb_type l) noexcept {
            result.limbs()[0] &= l;
            result.zero_after(1);
        }

        NIL_CO3_MP_FORCEINLINE static constexpr void bitwise_or(big_integer& result,
                                                                limb_type l) noexcept {
            result.limbs()[0] |= l;
        }

        NIL_CO3_MP_FORCEINLINE static constexpr void bitwise_xor(big_integer& result,
                                                                 limb_type l) noexcept {
            result.limbs()[0] ^= l;
        }

        NIL_CO3_MP_FORCEINLINE static constexpr void complement(big_integer& result,
                                                                const big_integer& o) noexcept {
            unsigned os = o.size();
            for (unsigned i = 0; i < os; ++i) {
                result.limbs()[i] = ~o.limbs()[i];
            }
            result.normalize();
        }

        // Left shift will throw away upper Bits.
        // This function must be called only when s % 8 == 0, i.e. we shift bytes.
        static inline void left_shift_byte(big_integer& result, double_limb_type s) {
            limb_pointer pr = result.limbs();

            std::size_t bytes = static_cast<std::size_t>(s / CHAR_BIT);
            if (s >= Bits) {
                // Set result to 0.
                result.zero_after(0);
            } else {
                unsigned char* pc = reinterpret_cast<unsigned char*>(pr);
                std::memmove(pc + bytes, pc, result.size() * sizeof(limb_type) - bytes);
                std::memset(pc, 0, bytes);
            }
        }

        // Left shift will throw away upper Bits.
        // This function must be called only when s % limb_bits == 0, i.e. we shift limbs, which
        // are normally 64 bit.
        static inline constexpr void left_shift_limb(big_integer& result, double_limb_type s) {
            limb_type offset = static_cast<limb_type>(s / limb_bits);
            NIL_CO3_MP_ASSERT(static_cast<limb_type>(s % limb_bits) == 0);

            limb_pointer pr = result.limbs();

            if (s >= Bits) {
                // Set result to 0.
                result.zero_after(0);
            } else {
                unsigned i = offset;
                std::size_t rs = result.size() + offset;
                for (; i < result.size(); ++i) {
                    pr[rs - 1 - i] = pr[result.size() - 1 - i];
                }
                for (; i < rs; ++i) {
                    pr[rs - 1 - i] = 0;
                }
            }
        }

        // Left shift will throw away upper Bits.
        static inline constexpr void left_shift_generic(big_integer& result, double_limb_type s) {
            if (s >= Bits) {
                // Set result to 0.
                result.zero_after(0);
            } else {
                limb_type offset = static_cast<limb_type>(s / limb_bits);
                limb_type shift = static_cast<limb_type>(s % limb_bits);

                limb_pointer pr = result.limbs();
                std::size_t i = 0;
                std::size_t rs = result.size();
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

        // Shifting left throws away upper Bits.
        static inline constexpr void left_shift(big_integer& result, double_limb_type s) noexcept {
            if (!s) {
                return;
            }

#if NIL_CO3_MP_ENDIAN_LITTLE_BYTE && defined(NIL_CO3_MP_USE_LIMB_SHIFT)
            constexpr limb_type limb_shift_mask = big_integer::limb_bits - 1;
            constexpr limb_type byte_shift_mask = CHAR_BIT - 1;

            if ((s & limb_shift_mask) == 0) {
                left_shift_limb(result, s);
            } else if (((s & byte_shift_mask) == 0) && !std::is_constant_evaluated()) {
                left_shift_byte(result, s);
            }
#elif NIL_CO3_MP_ENDIAN_LITTLE_BYTE
            constexpr limb_type limb_shift_mask = big_integer::limb_bits - 1;
            constexpr limb_type byte_shift_mask = CHAR_BIT - 1;

            if (std::is_constant_evaluated() && ((s & limb_shift_mask) == 0)) {
                left_shift_limb(result, s);
            } else if (((s & byte_shift_mask) == 0) && !std::is_constant_evaluated()) {
                left_shift_byte(result, s);
            }
#else
            constexpr limb_type limb_shift_mask = big_integer::limb_bits - 1;

            if ((s & limb_shift_mask) == 0) {
                left_shift_limb(result, s);
            }
#endif
            else {
                left_shift_generic(result, s);
            }
            result.normalize();
        }

        static inline void right_shift_byte(big_integer& result, double_limb_type s) {
            limb_type offset = static_cast<limb_type>(s / limb_bits);
            NIL_CO3_MP_ASSERT((s % CHAR_BIT) == 0);
            unsigned ors = result.size();
            unsigned rs = ors;
            if (offset >= rs) {
                result.zero_after(0);
                return;
            }
            rs -= offset;
            limb_pointer pr = result.limbs();
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
            result.zero_after(rs);
        }

        static inline constexpr void right_shift_limb(big_integer& result, double_limb_type s) {
            limb_type offset = static_cast<limb_type>(s / limb_bits);
            NIL_CO3_MP_ASSERT((s % limb_bits) == 0);
            unsigned ors = result.size();
            unsigned rs = ors;
            if (offset >= rs) {
                result.zero_after(0);
                return;
            }
            rs -= offset;
            limb_pointer pr = result.limbs();
            unsigned i = 0;
            for (; i < rs; ++i) {
                pr[i] = pr[i + offset];
            }
            // Set zeros after 'rs', alternative to resizing to size 'rs'.
            result.zero_after(rs);
        }

        static inline constexpr void right_shift_generic(big_integer& result, double_limb_type s) {
            limb_type offset = static_cast<limb_type>(s / limb_bits);
            limb_type shift = static_cast<limb_type>(s % limb_bits);
            unsigned ors = result.size();
            unsigned rs = ors;

            if (offset >= rs) {
                result = limb_type(0);
                return;
            }
            rs -= offset;
            limb_pointer pr = result.limbs();
            if ((pr[ors - 1] >> shift) == 0) {
                if (--rs == 0) {
                    result = limb_type(0);
                    return;
                }
            }
            unsigned i = 0;

            // This code only works for non-zero shift, otherwise we invoke undefined behaviour!
            NIL_CO3_MP_ASSERT(shift);
            for (; i + offset + 1 < ors; ++i) {
                pr[i] = pr[i + offset] >> shift;
                pr[i] |= pr[i + offset + 1] << (limb_bits - shift);
            }
            pr[i] = pr[i + offset] >> shift;

            // We cannot resize any more, so we need to set all the limbs to zero.
            result.zero_after(rs);
        }

        static inline constexpr void right_shift(big_integer& result, double_limb_type s) noexcept {
            if (!s) {
                return;
            }

#if NIL_CO3_MP_ENDIAN_LITTLE_BYTE && defined(NIL_CO3_MP_USE_LIMB_SHIFT)
            constexpr limb_type limb_shift_mask = big_integer::limb_bits - 1;
            constexpr limb_type byte_shift_mask = CHAR_BIT - 1;

            if ((s & limb_shift_mask) == 0) {
                right_shift_limb(result, s);
            } else if (((s & byte_shift_mask) == 0) && !std::is_constant_evaluated()) {
                right_shift_byte(result, s);
            }
#elif NIL_CO3_MP_ENDIAN_LITTLE_BYTE
            constexpr limb_type byte_shift_mask = CHAR_BIT - 1;

            constexpr limb_type limb_shift_mask = big_integer::limb_bits - 1;
            if (std::is_constant_evaluated() && ((s & limb_shift_mask) == 0)) {
                right_shift_limb(result, s);
            } else if (((s & byte_shift_mask) == 0) && !std::is_constant_evaluated()) {
                right_shift_byte(result, s);
            }
#else
            constexpr limb_type limb_shift_mask = big_integer::limb_bits - 1;

            if ((s & limb_shift_mask) == 0) {
                right_shift_limb(result, s);
            }
#endif
            else {
                right_shift_generic(result, s);
            }
        }

        inline constexpr std::size_t used_limbs() const noexcept {
            for (int i = internal_limb_count - 1; i >= 0; --i) {
                if (limbs()[i] != 0) {
                    return i + 1;
                }
            }
            return 0;
        }

        inline constexpr std::size_t order() const noexcept {
            for (int i = internal_limb_count - 1; i >= 0; --i) {
                if (limbs()[i] != 0) {
                    return i;
                }
            }
            return 0;
        }

        // Modulus/divide

        // This should be called only for creation of Montgomery and Barett
        // params, not during "normal" execution, so we do not care about the execution speed.

        template<std::size_t Bits2>
        static inline constexpr void divide(big_integer* div, const big_integer& x,
                                            const big_integer<Bits2>& y, big_integer& rem) {
            /*
            Very simple long division.
            Start by setting the remainder equal to x, and the
            result equal to 0.  Then in each loop we calculate our
            "best guess" for how many times y divides into rem,
            add our guess to the result, and subtract guess*y
            from the remainder rem.  One wrinkle is that the remainder
            may go negative, in which case we subtract the current guess
            from the result rather than adding.  The value of the guess
            is determined by dividing the most-significant-limb of the
            current remainder by the most-significant-limb of y.

            Note that there are more efficient algorithms than this
            available, in particular see Knuth Vol 2.  However for small
            numbers of limbs this generally outperforms the alternatives
            and avoids the normalisation step which would require extra storage.
            */

            if (is_zero(y)) {
                throw std::overflow_error("integer division by zero");
            }

            const_limb_pointer px = x.limbs();
            const_limb_pointer py = y.limbs();

            if (is_zero(x)) {
                // x is zero, so is the result:
                rem = x;
                if (div) {
                    *div = x;
                }
                return;
            }

            rem = x;
            std::size_t rem_order = rem.order();
            std::size_t y_order = y.order();
            if (div) {
                *div = 0u;
            }
            //
            // Check if the remainder is already less than the divisor, if so
            // we already have the result.  Note we try and avoid a full compare
            // if we can:
            //
            if (rem < y) {
                return;
            }

            big_integer t;
            bool rem_neg = false;

            //
            // See if we can short-circuit long division, and use basic arithmetic instead:
            //
            if (rem_order == 0) {
                if (div) {
                    *div = px[0] / py[0];
                }
                rem = px[0] % py[0];
                return;
            }
            if (rem_order == 1) {
                double_limb_type a = (static_cast<double_limb_type>(px[1]) << limb_bits) | px[0];
                double_limb_type b =
                    y_order ? (static_cast<double_limb_type>(py[1]) << limb_bits) | py[0] : py[0];
                if (div) {
                    *div = a / b;
                }
                rem = a % b;
                return;
            }
            const_limb_pointer prem = rem.limbs();
            // This is initialised just to keep the compiler from emitting useless warnings later
            // on:
            limb_pointer pdiv = limb_pointer();
            if (div) {
                pdiv = div->limbs();
                for (std::size_t i = 1; i < 1 + rem_order - y_order; ++i) {
                    pdiv[i] = 0;
                }
            }
            bool first_pass = true;

            do {
                //
                // Calculate our best guess for how many times y divides into rem:
                //
                limb_type guess = 1;
                if (rem_order > 0 && prem[rem_order] <= py[y_order]) {
                    double_limb_type a =
                        (static_cast<double_limb_type>(prem[rem_order]) << limb_bits) |
                        prem[rem_order - 1];
                    double_limb_type b = py[y_order];
                    double_limb_type v = a / b;
                    if (v <= max_limb_value) {
                        guess = static_cast<limb_type>(v);
                        --rem_order;
                    }
                } else if (rem_order == 0) {
                    guess = prem[0] / py[y_order];
                } else {
                    double_limb_type a =
                        (static_cast<double_limb_type>(prem[rem_order]) << limb_bits) |
                        prem[rem_order - 1];
                    double_limb_type b =
                        (y_order > 0) ? (static_cast<double_limb_type>(py[y_order]) << limb_bits) |
                                            py[y_order - 1]
                                      : (static_cast<double_limb_type>(py[y_order]) << limb_bits);
                    NIL_CO3_MP_ASSERT(b);
                    double_limb_type v = a / b;
                    guess = static_cast<limb_type>(v);
                }
                NIL_CO3_MP_ASSERT(guess);  // If the guess ever gets to zero we go on forever....
                //
                // Update result:
                //
                std::size_t shift = rem_order - y_order;
                if (div) {
                    if (rem_neg) {
                        if (pdiv[shift] > guess) {
                            pdiv[shift] -= guess;
                        } else {
                            t = 0u;
                            t.limbs()[shift] = guess;
                            *div -= t;
                        }
                    } else if (max_limb_value - pdiv[shift] > guess) {
                        pdiv[shift] += guess;
                    } else {
                        t = 0u;
                        t.limbs()[shift] = guess;
                        *div += t;
                    }
                }
                //
                // Calculate guess * y, we use a fused mutiply-shift O(N) for this
                // rather than a full O(N^2) multiply:
                //
                double_limb_type carry = 0;
                // t.resize(y.size() + shift + 1, y.size() + shift);
                // bool truncated_t = (t.size() != y.size() + shift + 1);
                const bool truncated_t = y_order + shift + 2 > internal_limb_count;
                t = 0u;
                limb_pointer pt = t.limbs();
                for (std::size_t i = 0; i < y_order + 1; ++i) {
                    carry +=
                        static_cast<double_limb_type>(py[i]) * static_cast<double_limb_type>(guess);
                    pt[i + shift] = static_cast<limb_type>(carry);
                    carry >>= limb_bits;
                }
                if (carry && !truncated_t) {
                    pt[y_order + shift + 1] = static_cast<limb_type>(carry);
                } else if (!truncated_t) {
                    // t.resize(t.size() - 1, t.size() - 1);
                }
                //
                // Update rem in a way that won't actually produce a negative result
                // in case the argument types are unsigned:
                //
                if (truncated_t && carry) {
                    NIL_CO3_MP_ASSERT_MSG(false, "how can this even happen");
                    // We need to calculate 2^n + t - rem
                    // where n is the number of bits in this type.
                    // Simplest way is to get 2^n - rem by complementing and incrementing
                    // rem, then add t to it.
                    for (std::size_t i = 0; i <= rem_order; ++i) {
                        rem.limbs()[i] = ~prem[i];
                    }
                    rem.normalize();
                    ++rem;
                    rem += t;
                    rem_neg = !rem_neg;
                } else if (rem > t) {
                    rem -= t;
                } else {
                    std::swap(rem, t);
                    rem -= t;
                    prem = rem.limbs();
                    rem_neg = !rem_neg;
                }
                //
                // First time through we need to strip any leading zero, otherwise
                // the termination condition goes belly-up:
                //
                // if (div && first_pass) {
                //     first_pass = false;
                //     // while (pdiv[div->size() - 1] == 0)
                //     //     div->resize(div->size() - 1, div->size() - 1);
                // }
                //
                // Update rem_order:
                //
                rem_order = rem.order();
            }
            // Termination condition is really just a check that rem > y, but with a common
            // short-circuit case handled first:
            while ((rem_order >= y_order) && ((rem_order > y_order) || (rem >= y)));

            //
            // We now just have to normalise the result:
            //
            if (rem_neg && !is_zero(rem)) {
                // We have one too many in the result:
                if (div) {
                    --*div;
                }
                rem = y - rem;
            }

            // remainder must be less than the divisor or our code has failed
            NIL_CO3_MP_ASSERT(rem < y);
        }

        // Multiplication

        // These should be called only for creation of Montgomery and Barett
        // params, calculation of inverse element and montgomery_reduce. Since these functions
        // are relatively slow and are not called very often, we will not optimize them. We do
        // NOT care about the execution speed.

        // Caller is responsible for the result to fit in Bits bits, we will NOT throw!!!

        template<std::size_t Bits2, std::size_t Bits3>
        static inline constexpr void multiply(big_integer& result, const big_integer<Bits2>& a,
                                              const big_integer<Bits3>& b) noexcept {
            std::size_t as = a.size();
            std::size_t bs = b.size();
            const_limb_pointer pa = a.limbs();
            const_limb_pointer pb = b.limbs();
            limb_pointer pr = result.limbs();
            for (std::size_t i = 0; i < result.size(); ++i) {
                pr[i] = 0;
            }

            double_limb_type carry = 0;
            for (std::size_t i = 0; i < as; ++i) {
                NIL_CO3_MP_ASSERT(result.size() > i);
                std::size_t inner_limit = (std::min)(result.size() - i, bs);
                std::size_t j = 0;
                for (; j < inner_limit; ++j) {
                    NIL_CO3_MP_ASSERT(i + j < result.size());
                    carry +=
                        static_cast<double_limb_type>(pa[i]) * static_cast<double_limb_type>(pb[j]);
                    NIL_CO3_MP_ASSERT(
                        !std::numeric_limits<double_limb_type>::is_specialized ||
                        ((std::numeric_limits<double_limb_type>::max)() - carry >= pr[i + j]));
                    carry += pr[i + j];
                    pr[i + j] = static_cast<limb_type>(carry);
                    carry >>= limb_bits;
                    NIL_CO3_MP_ASSERT(carry <= max_limb_value);
                }
                if (carry) {
                    NIL_CO3_MP_ASSERT(result.size() > i + j);
                    if (i + j < result.size()) {
                        pr[i + j] = static_cast<limb_type>(carry);
                    }
                }
                carry = 0;
            }
            result.normalize();
        }

      private:
        // Assignment

        template<typename T,
                 std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, int> = 0>
        inline constexpr void do_assign_integral(const T& a) noexcept {
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
                NIL_CO3_MP_ASSERT(big_integer<sizeof(T) * CHAR_BIT>(a).compare(*this) == 0);
            }
        }

        template<std::size_t Bits2>
        inline constexpr void do_assign(const big_integer<Bits2>& other) noexcept {
            unsigned count = (std::min)(other.size(), this->size());
            for (unsigned i = 0; i < count; ++i) {
                this->limbs()[i] = other.limbs()[i];
            }
            // Zero out everything after (std::min)(other.size(), size()), so if size of
            // other was less, we have 0s at the end.
            this->zero_after((std::min)(other.size(), this->size()));
            this->normalize();
        }

        // Data

        // m_data[0] contains the lowest bits.
        std::array<limb_type, internal_limb_count> m_data{0};

        // This is a temporary value which is set when carry has happend during addition.
        // If this value is true, reduction by modulus must happen next.
        bool m_carry = false;

        template<std::size_t>
        friend class big_integer;
    };

    namespace detail {
        template<typename T>
        static constexpr bool always_false = false;

        template<typename T>
        constexpr bool is_big_integer_v = false;

        template<std::size_t Bits>
        constexpr bool is_big_integer_v<big_integer<Bits>> = true;

        template<typename T>
        constexpr bool is_integral_v = std::is_integral_v<T> || is_big_integer_v<T>;

        template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
        constexpr std::size_t get_bits() {
            return sizeof(T) * CHAR_BIT;
        }

        template<typename T, std::enable_if_t<is_big_integer_v<T>, int> = 0>
        constexpr std::size_t get_bits() {
            return T::Bits;
        }
    }  // namespace detail

#define NIL_CO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE                                                  \
    template<typename T1, typename T2,                                                            \
             std::enable_if_t<detail::is_integral_v<T1> && detail::is_integral_v<T2> &&           \
                                  (detail::is_big_integer_v<T1> || detail::is_big_integer_v<T2>), \
                              int> = 0,                                                           \
             typename largest_t =                                                                 \
                 big_integer<std::max(detail::get_bits<T1>(), detail::get_bits<T2>())>>

#define NIL_CO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE                                        \
    template<typename big_integer_t, typename T,                                                   \
             std::enable_if_t<detail::is_big_integer_v<big_integer_t> && detail::is_integral_v<T>, \
                              int> = 0>

#define NIL_CO3_MP_BIG_INTEGER_UNARY_TEMPLATE \
    template<typename big_integer_t,          \
             std::enable_if_t<detail::is_big_integer_v<big_integer_t>, int> = 0>

    // Comparison

#define NIL_CO3_MP_BIG_INTEGER_IMPL_OPERATOR(op)                           \
    NIL_CO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE                               \
    inline constexpr bool operator op(const T1& a, const T2& b) noexcept { \
        largest_t ap = a;                                                  \
        largest_t bp = b;                                                  \
        return ap.compare(bp) op 0;                                        \
    }

    NIL_CO3_MP_BIG_INTEGER_IMPL_OPERATOR(<)
    NIL_CO3_MP_BIG_INTEGER_IMPL_OPERATOR(<=)
    NIL_CO3_MP_BIG_INTEGER_IMPL_OPERATOR(>)
    NIL_CO3_MP_BIG_INTEGER_IMPL_OPERATOR(>=)
    NIL_CO3_MP_BIG_INTEGER_IMPL_OPERATOR(==)
    NIL_CO3_MP_BIG_INTEGER_IMPL_OPERATOR(!=)

#undef NIL_CO3_MP_BIG_INTEGER_IMPL_OPERATOR

    // Arithmetic operations

    NIL_CO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator+(const T1& a, const T2& b) noexcept {
        big_integer<largest_t::Bits + 1> result = a;
        decltype(result)::add(result, result, b);
        return result;
    }
    NIL_CO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator+=(big_integer_t& a, const T& b) noexcept {
        big_integer_t::add(a, a, b);
        return a;
    }
    NIL_CO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto& operator++(big_integer_t& a) noexcept {
        a.increment();
        return a;
    }
    NIL_CO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator++(big_integer_t& a, int) noexcept {
        auto copy = a;
        ++a;
        return copy;
    }
    NIL_CO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator+(const big_integer_t& a) noexcept { return a; }

    NIL_CO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator-(const T1& a, const T2& b) noexcept {
        T1 result;
        T1::subtract(result, a, b);
        return result;
    }
    NIL_CO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator-=(big_integer_t& a, const T& b) {
        big_integer_t::subtract(a, a, b);
        return a;
    }
    NIL_CO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto& operator--(big_integer_t& a) noexcept {
        a.decrement();
        return a;
    }
    NIL_CO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator--(big_integer_t& a, int) noexcept {
        auto copy = a;
        --a;
        return copy;
    }

    NIL_CO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr big_integer_t operator-(const big_integer_t& /* unused */) noexcept {
        static_assert(detail::always_false<big_integer_t>, "can't negate unsigned type");
    }

    NIL_CO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator*(const T1& a, const T2& b) noexcept {
        big_integer<detail::get_bits<T1>() + detail::get_bits<T2>()> result;
        decltype(result)::multiply(result, a, b);
        return result;
    }
    NIL_CO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator*=(big_integer_t& a, const T& b) noexcept {
        big_integer<detail::get_bits<big_integer_t>() + detail::get_bits<T>()> result;
        decltype(result)::multiply(result, a, static_cast<big_integer_t>(b));
        a = result;
        return a;
    }

    NIL_CO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator/(const T1& a, const T2& b) noexcept {
        largest_t result;
        largest_t modulus;
        largest_t::divide(&result, a, b, modulus);
        return result;
    }
    NIL_CO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator/=(big_integer_t& a, const T& b) noexcept {
        big_integer_t result;
        big_integer_t modulus;
        big_integer_t::divide(&result, a, b, modulus);
        a = result;
        return a;
    }

    NIL_CO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator%(const T1& a, const T2& b) noexcept {
        largest_t modulus;
        largest_t::divide(nullptr, static_cast<largest_t>(a), static_cast<largest_t>(b), modulus);
        return modulus;
    }
    NIL_CO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator%=(big_integer_t& a, const T& b) {
        big_integer_t modulus;
        big_integer_t::divide(nullptr, a, b, modulus);
        a = modulus;
        return a;
    }

    NIL_CO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator&(const T1& a, const T2& b) noexcept {
        largest_t result = a;
        T1::bitwise_and(result, b);
        return result;
    }
    NIL_CO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator&=(big_integer_t& a, const T& b) {
        big_integer_t::bitwise_and(a, b);
        return a;
    }

    NIL_CO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator|(const T1& a, const T2& b) noexcept {
        largest_t result = a;
        T1::bitwise_or(result, b);
        return result;
    }
    NIL_CO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator|=(big_integer_t& a, const T& b) {
        big_integer_t::bitwise_or(a, b);
        return a;
    }

    NIL_CO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator^(const T1& a, const T2& b) noexcept {
        largest_t result = a;
        T1::bitwise_xor(result, b);
        return result;
    }
    NIL_CO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator^=(big_integer_t& a, const T& b) {
        big_integer_t::bitwise_or(a, b);
        return a;
    }

    NIL_CO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator~(const big_integer_t& a) noexcept {
        big_integer_t result;
        big_integer_t::complement(result, a);
        return result;
    }

    NIL_CO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator<<(const big_integer_t& a, unsigned shift) noexcept {
        big_integer_t result = a;
        big_integer_t::left_shift(result, shift);
        return result;
    }
    NIL_CO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto& operator<<=(big_integer_t& a, unsigned shift) noexcept {
        big_integer_t::left_shift(a, shift);
        return a;
    }

    NIL_CO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator>>(const big_integer_t& a, unsigned shift) noexcept {
        big_integer_t result = a;
        big_integer_t::right_shift(result, shift);
        return result;
    }
    NIL_CO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto& operator>>=(big_integer_t& a, unsigned shift) noexcept {
        big_integer_t::right_shift(a, shift);
        return a;
    }

    // Hash

    template<std::size_t Bits>
    inline constexpr std::size_t hash_value(const big_integer<Bits>& val) noexcept {
        std::size_t result = 0;
        for (unsigned i = 0; i < val.size(); ++i) {
            boost::hash_combine(result, val.limbs()[i]);
        }
        return result;
    }

    // IO

    NIL_CO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    std::ostream& operator<<(std::ostream& os, const big_integer_t& value) {
        os << value.str();
        return os;
    }

#undef NIL_CO3_MP_BIG_INTEGER_UNARY_TEMPLATE
#undef NIL_CO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
#undef NIL_CO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE
}  // namespace nil::crypto3::multiprecision
