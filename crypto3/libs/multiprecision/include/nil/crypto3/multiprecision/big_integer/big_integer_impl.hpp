#pragma once

// IWYU pragma: private; include "nil/crypto3/multiprecision/big_integer/big_integer.hpp"

#include <algorithm>
#include <array>
#include <climits>
#include <cstring>
#include <exception>
#include <functional>
#include <ios>
#include <iostream>
#include <ranges>
#include <string>
#include <tuple>
#include <type_traits>

// TODO(ioxid): replace with custom code
#include <boost/multiprecision/cpp_int.hpp>

#include "nil/crypto3/multiprecision/big_integer/detail/config.hpp"
#include "nil/crypto3/multiprecision/big_integer/storage.hpp"

namespace nil::crypto3::multiprecision {
    template<unsigned Bits_>
    class big_integer {
      public:
        constexpr static unsigned Bits = Bits_;
        using self_type = big_integer;

        using cpp_int_type = boost::multiprecision::number<boost::multiprecision::cpp_int_backend<
            Bits, Bits, boost::multiprecision::unsigned_magnitude,
            boost::multiprecision::unchecked>>;

        using limb_type = detail::limb_type;
        using double_limb_type = detail::double_limb_type;
        using signed_limb_type = detail::signed_limb_type;
        using signed_double_limb_type = detail::signed_double_limb_type;

        using unsigned_types = std::tuple<limb_type, double_limb_type>;
        using signed_types = std::tuple<signed_limb_type, signed_double_limb_type>;

        // Storage

        using limb_pointer = detail::limb_pointer;
        using const_limb_pointer = detail::const_limb_pointer;
        static constexpr unsigned limb_bits = detail::limb_bits;
        static constexpr unsigned max_limb_value = detail::max_limb_value;

        static constexpr unsigned internal_limb_count =
            (Bits / limb_bits) + (((Bits % limb_bits) != 0u) ? 1u : 0u);
        static constexpr limb_type upper_limb_mask =
            (Bits % limb_bits) ? (limb_type(1) << (Bits % limb_bits)) - 1 : (~limb_type(0u));

        //
        // Helper functions for getting at our internal data, and manipulating storage:
        //
        inline constexpr unsigned size() const noexcept {
            static_assert(internal_limb_count != 0, "No limbs in storage.");
            return internal_limb_count;
        }
        inline constexpr limb_pointer limbs() noexcept { return m_data.data(); }
        inline constexpr const_limb_pointer limbs() const noexcept { return m_data.data(); }
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
            limb_pointer p = limbs();
            p[internal_limb_count - 1] &= upper_limb_mask;
        }

        // Constructor

        inline constexpr big_integer() noexcept {}

        inline explicit constexpr big_integer(const cpp_int_type& other) {
            this->from_cpp_int(other);
        }

        // TODO(ioxid): forbid signed, implement comparison with signed instead
        template<class T, std::enable_if_t<std::is_integral_v<T> /*&& std::is_v<T>*/, int> = 0>
        inline constexpr big_integer(T val) noexcept {
            if (val < 0) {
                std::cerr << "big_integer: assignment from negative integer" << std::endl;
                std::terminate();
            }
            do_assign_integral(static_cast<std::make_unsigned_t<T>>(val));
        }

        // Copy construction

        template<unsigned Bits2>
        inline constexpr big_integer(const big_integer<Bits2>& other) noexcept {
            do_assign(other);
        }

        // Copy assignment

        template<unsigned Bits2>
        inline constexpr big_integer& operator=(const big_integer<Bits2>& other) noexcept {
            do_assign(other);
            return *this;
        }

        // Assignment from other types

        // TODO(ioxid): forbid signed, implement comparison with signed instead
        template<typename T, std::enable_if_t<std::is_integral_v<T> /*&& std::is_v<T>*/, int> = 0>
        inline constexpr big_integer& operator=(T val) noexcept {
            if (val < 0) {
                std::cerr << "big_integer: assignment from negative integer" << std::endl;
                std::terminate();
            }
            do_assign_integral(static_cast<std::make_unsigned_t<T>>(val));
            return *this;
        }

        inline constexpr auto& operator=(const char* s) {
            // TODO(ioxid): rewrite without cpp_int
            cpp_int_type value;
            value = s;
            this->from_cpp_int(value);
            return *this;
        }

        inline std::string str(std::streamsize digits = 0,
                               std::ios_base::fmtflags f = std::ios_base::fmtflags(0)) const {
            // TODO(ioxid): rewrite without cpp_int
            cpp_int_type value = to_cpp_int();
            return value.str(digits, f);
        }

        // cpp_int conversion

        inline constexpr void from_cpp_int(cpp_int_type cppint) {
            for (limb_type& limb : m_data) {
                limb = static_cast<limb_type>(cppint & static_cast<limb_type>(-1));
                cppint >>= limb_bits;
            }
        }

        // Converting to cpp_int. We need this for multiplication, division and string
        // conversions. Since these operations are rare, there's no reason to implement them for
        // big_integer, converting to cpp_int does not result to performance penalty.
        inline constexpr cpp_int_type to_cpp_int() const {
            cpp_int_type result;
            for (const limb_type limb : m_data | std::views::reverse) {
                result <<= limb_bits;
                result |= limb;
            }
            return result;
        }

        // cast to integral types

        template<typename T,
                 std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, int> = 0>
        explicit inline constexpr operator T() const {
            if constexpr (sizeof(T) <= sizeof(limb_type)) {
                return static_cast<T>(this->limbs()[0]);
            } else {
                constexpr std::size_t n = sizeof(T) / sizeof(limb_type);
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

        // TODO(ioxid): make them private?
      public:
        // Arithmetic operations

        // Addition/subtraction

        static inline constexpr void add_constexpr(big_integer& result, const big_integer& a,
                                                   const big_integer& b) noexcept {
            using ::boost::multiprecision::std_constexpr::swap;
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

            typename big_integer::const_limb_pointer pa = a.limbs();
            typename big_integer::const_limb_pointer pb = b.limbs();
            typename big_integer::limb_pointer pr = result.limbs();

            // First where a and b overlap:
            for (std::size_t i = 0; i < s; ++i) {
                carry += static_cast<double_limb_type>(*pa) + static_cast<double_limb_type>(*pb);
#ifdef _C_RUNTIME_CHECKS
                *pr = static_cast<limb_type>(carry & ~static_cast<limb_type>(0));
#else
                *pr = static_cast<limb_type>(carry);
#endif
                carry >>= big_integer::limb_bits;
                ++pr, ++pa, ++pb;
            }
            if (Bits % big_integer::limb_bits == 0) {
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
        // Core subtraction routine for all non-trivial cpp_int's:
        // It is the caller's responsibility to make sure that a >= b.
        //
        static inline constexpr void subtract_constexpr(big_integer& result, const big_integer& a,
                                                        const big_integer& b) noexcept {
            BOOST_ASSERT(a >= b);

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
            typename big_integer::const_limb_pointer pa = a.limbs();
            typename big_integer::const_limb_pointer pb = b.limbs();
            typename big_integer::limb_pointer pr = result.limbs();

            double_limb_type borrow = 0;
            // First where a and b overlap:
            for (std::size_t i = 0; i < s; ++i) {
                borrow = static_cast<double_limb_type>(pa[i]) -
                         static_cast<double_limb_type>(pb[i]) - borrow;
                pr[i] = static_cast<limb_type>(borrow);
                borrow = (borrow >> big_integer::limb_bits) & 1u;
            }
            // if a > b, then borrow must be 0 at the end.
            BOOST_ASSERT(0 == borrow);
        }

#ifdef CO3_MP_HAS_IMMINTRIN_H
        //
        // This is the key addition routine where all the argument types are non-trivial
        // cpp_int's:
        //
        //
        // This optimization is limited to: GCC, LLVM, ICC (Intel), MSVC for x86_64 and i386.
        // If your architecture and compiler supports ADC intrinsic, please file a bug
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
#ifndef BOOST_MP_NO_CONSTEXPR_DETECTION
            if (BOOST_MP_IS_CONST_EVALUATED(a.size())) {
                add_constexpr(result, a, b);
            } else
#endif
            {
                using std::swap;

                // Nothing fancy, just let uintmax_t take the strain:
                unsigned s = a.size();
                if (s == 1) {
                    double_limb_type v = static_cast<double_limb_type>(*a.limbs()) +
                                         static_cast<double_limb_type>(*b.limbs());
                    double_limb_type mask = big_integer::upper_limb_mask;
                    if (v & ~mask) {
                        v &= mask;
                        result.set_carry(true);
                    }
                    result = v;
                    return;
                }
                typename big_integer::const_limb_pointer pa = a.limbs();
                typename big_integer::const_limb_pointer pb = b.limbs();
                typename big_integer::limb_pointer pr = result.limbs();

                unsigned char carry = 0;
#if defined(BOOST_MSVC) && !defined(BOOST_HAS_INT128) && defined(_M_X64)
                //
                // Special case for 32-bit limbs on 64-bit architecture - we can process
                // 2 limbs with each instruction.
                //
                std::size_t i = 0;
                for (; i + 8 <= s; i += 8) {
                    carry = _addcarry_u64(carry, *(unsigned long long*)(pa + i + 0),
                                          *(unsigned long long*)(pb + i + 0),
                                          (unsigned long long*)(pr + i));
                    carry = _addcarry_u64(carry, *(unsigned long long*)(pa + i + 2),
                                          *(unsigned long long*)(pb + i + 2),
                                          (unsigned long long*)(pr + i + 2));
                    carry = _addcarry_u64(carry, *(unsigned long long*)(pa + i + 4),
                                          *(unsigned long long*)(pb + i + 4),
                                          (unsigned long long*)(pr + i + 4));
                    carry = _addcarry_u64(carry, *(unsigned long long*)(pa + i + 6),
                                          *(unsigned long long*)(pb + i + 6),
                                          (unsigned long long*)(pr + i + 6));
                }
#else
                for (; i + 4 <= s; i += 4) {
                    carry = ::boost::multiprecision::detail::addcarry_limb(carry, pa[i + 0],
                                                                           pb[i + 0], pr + i);
                    carry = ::boost::multiprecision::detail::addcarry_limb(carry, pa[i + 1],
                                                                           pb[i + 1], pr + i + 1);
                    carry = ::boost::multiprecision::detail::addcarry_limb(carry, pa[i + 2],
                                                                           pb[i + 2], pr + i + 2);
                    carry = ::boost::multiprecision::detail::addcarry_limb(carry, pa[i + 3],
                                                                           pb[i + 3], pr + i + 3);
                }
#endif
                for (; i < s; ++i)
                    carry =
                        ::boost::multiprecision::detail::addcarry_limb(carry, pa[i], pb[i], pr + i);

                if (Bits % big_integer::limb_bits == 0)
                    result.set_carry(carry);
                else {
                    limb_type mask = big_integer::upper_limb_mask;
                    // If we have set any bit above "Bits", then we have a carry.
                    if (result.limbs()[s - 1] & ~mask) {
                        result.limbs()[s - 1] &= mask;
                        result.set_carry(true);
                    }
                }
            }
        }

        // It is the caller's responsibility to make sure that a > b.
        static inline constexpr void subtract(big_integer& result, const big_integer& a,
                                              const big_integer& b) noexcept {
            BOOST_ASSERT(!eval_lt(a, b));

#ifndef TO3_MP_NO_CONSTEXPR_DETECTION
            if (BOOST_MP_IS_CONST_EVALUATED(a.size())) {
                subtract_constexpr(result, a, b);
            } else
#endif
            {
                using std::swap;

                // Nothing fancy, just let uintmax_t take the strain:
                std::size_t s = a.size();

                //
                // special cases for small limb counts:
                //
                if (s == 1) {
                    result = *a.limbs() - *b.limbs();
                    return;
                }
                // Now that a, b, and result are stable, get pointers to their limbs:
                typename big_integer::const_limb_pointer pa = a.limbs();
                typename big_integer::const_limb_pointer pb = b.limbs();
                typename big_integer::limb_pointer pr = result.limbs();

                std::size_t i = 0;
                unsigned char borrow = 0;
                // First where a and b overlap:
#if defined(BOOST_MSVC) && !defined(BOOST_HAS_INT128) && defined(_M_X64)
                //
                // Special case for 32-bit limbs on 64-bit architecture - we can process
                // 2 limbs with each instruction.
                //
                for (; i + 8 <= m; i += 8) {
                    borrow =
                        _subborrow_u64(borrow, *reinterpret_cast<const unsigned long long*>(pa + i),
                                       *reinterpret_cast<const unsigned long long*>(pb + i),
                                       reinterpret_cast<unsigned long long*>(pr + i));
                    borrow = _subborrow_u64(
                        borrow, *reinterpret_cast<const unsigned long long*>(pa + i + 2),
                        *reinterpret_cast<const unsigned long long*>(pb + i + 2),
                        reinterpret_cast<unsigned long long*>(pr + i + 2));
                    borrow = _subborrow_u64(
                        borrow, *reinterpret_cast<const unsigned long long*>(pa + i + 4),
                        *reinterpret_cast<const unsigned long long*>(pb + i + 4),
                        reinterpret_cast<unsigned long long*>(pr + i + 4));
                    borrow = _subborrow_u64(
                        borrow, *reinterpret_cast<const unsigned long long*>(pa + i + 6),
                        *reinterpret_cast<const unsigned long long*>(pb + i + 6),
                        reinterpret_cast<unsigned long long*>(pr + i + 6));
                }
#else
                for (; i + 4 <= m; i += 4) {
                    borrow =
                        boost::multiprecision::detail::subborrow_limb(borrow, pa[i], pb[i], pr + i);
                    borrow = boost::multiprecision::detail::subborrow_limb(borrow, pa[i + 1],
                                                                           pb[i + 1], pr + i + 1);
                    borrow = boost::multiprecision::detail::subborrow_limb(borrow, pa[i + 2],
                                                                           pb[i + 2], pr + i + 2);
                    borrow = boost::multiprecision::detail::subborrow_limb(borrow, pa[i + 3],
                                                                           pb[i + 3], pr + i + 3);
                }
#endif
                for (; i < m; ++i)
                    borrow =
                        boost::multiprecision::detail::subborrow_limb(borrow, pa[i], pb[i], pr + i);

                BOOST_ASSERT(0 == borrow);

            }  // constepxr.
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
            typename big_integer::limb_pointer pr = result.limbs();
            typename big_integer::const_limb_pointer pa = a.limbs();
            unsigned i = 0;
            // Addition with carry until we either run out of digits or carry is zero:
            for (; carry && (i < result.size()); ++i) {
                carry += static_cast<double_limb_type>(pa[i]);
                pr[i] = static_cast<limb_type>(carry);
                carry >>= big_integer::limb_bits;
            }
            // Just copy any remaining digits:
            if (&a != &result) {
                boost::multiprecision::std_constexpr::copy(pa + i, pa + a.size(), pr + i);
            }
            if (Bits % big_integer::limb_bits == 0) {
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
            BOOST_ASSERT(a >= b);

            // Subtract one limb.
            // Nothing fancy, just let uintmax_t take the strain:
            constexpr double_limb_type borrow =
                static_cast<double_limb_type>(big_integer::max_limb_value) + 1;
            typename big_integer::limb_pointer pr = result.limbs();
            typename big_integer::const_limb_pointer pa = a.limbs();
            if (*pa >= b) {
                *pr = *pa - b;
                if (&result != &a) {
                    boost::multiprecision::std_constexpr::copy(pa + 1, pa + a.size(), pr + 1);
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
                    boost::multiprecision::std_constexpr::copy(pa + i, pa + a.size(), pr + i);
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
            unsigned m(0), x(0);
            boost::multiprecision::minmax(rs, os, m, x);
            typename big_integer::limb_pointer pr = result.limbs();
            typename big_integer::const_limb_pointer po = o.limbs();
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
            typedef big_integer big_integer_t;

            typename big_integer_t::limb_pointer pr = result.limbs();

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
            using big_integer_t = big_integer;

            limb_type offset = static_cast<limb_type>(s / big_integer_t::limb_bits);
            BOOST_ASSERT(static_cast<limb_type>(s % big_integer_t::limb_bits) == 0);

            typename big_integer_t::limb_pointer pr = result.limbs();

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
            using big_integer_t = big_integer;

            if (s >= Bits) {
                // Set result to 0.
                result.zero_after(0);
            } else {
                limb_type offset = static_cast<limb_type>(s / big_integer_t::limb_bits);
                limb_type shift = static_cast<limb_type>(s % big_integer_t::limb_bits);

                typename big_integer_t::limb_pointer pr = result.limbs();
                std::size_t i = 0;
                std::size_t rs = result.size();
                // This code only works when shift is non-zero, otherwise we invoke undefined
                // behaviour!
                BOOST_ASSERT(shift);
                for (; rs - i >= 2 + offset; ++i) {
                    pr[rs - 1 - i] = pr[rs - 1 - i - offset] << shift;
                    pr[rs - 1 - i] |= pr[rs - 2 - i - offset] >> (big_integer_t::limb_bits - shift);
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

#if BOOST_ENDIAN_LITTLE_BYTE && defined(CRYPTO3_MP_USE_LIMB_SHIFT)
            constexpr const limb_type limb_shift_mask = big_integer::limb_bits - 1;
            constexpr const limb_type byte_shift_mask = CHAR_BIT - 1;

            if ((s & limb_shift_mask) == 0) {
                left_shift_limb(result, s);
            }
#ifdef BOOST_MP_NO_CONSTEXPR_DETECTION
            else if ((s & byte_shift_mask) == 0)
#else
            else if (((s & byte_shift_mask) == 0) && !BOOST_MP_IS_CONST_EVALUATED(s))
#endif
            {
                left_shift_byte(result, s);
            }
#elif BOOST_ENDIAN_LITTLE_BYTE
            constexpr const limb_type byte_shift_mask = CHAR_BIT - 1;

#ifdef BOOST_MP_NO_CONSTEXPR_DETECTION
            if ((s & byte_shift_mask) == 0)
#else
            constexpr limb_type limb_shift_mask = big_integer::limb_bits - 1;
            if (BOOST_MP_IS_CONST_EVALUATED(s) && ((s & limb_shift_mask) == 0)) {
                left_shift_limb(result, s);
            } else if (((s & byte_shift_mask) == 0) && !BOOST_MP_IS_CONST_EVALUATED(s))
#endif
            {
                left_shift_byte(result, s);
            }
#else
            constexpr const limb_type limb_shift_mask = big_integer::limb_bits - 1;

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
            typedef big_integer big_integer_t;

            limb_type offset = static_cast<limb_type>(s / big_integer_t::limb_bits);
            BOOST_ASSERT((s % CHAR_BIT) == 0);
            unsigned ors = result.size();
            unsigned rs = ors;
            if (offset >= rs) {
                result.zero_after(0);
                return;
            }
            rs -= offset;
            typename big_integer_t::limb_pointer pr = result.limbs();
            unsigned char* pc = reinterpret_cast<unsigned char*>(pr);
            limb_type shift = static_cast<limb_type>(s / CHAR_BIT);
            std::memmove(pc, pc + shift, ors * sizeof(pr[0]) - shift);
            shift = (sizeof(limb_type) - shift % sizeof(limb_type)) * CHAR_BIT;
            if (shift < big_integer_t::limb_bits) {
                pr[ors - offset - 1] &= (static_cast<limb_type>(1u) << shift) - 1;
                if (!pr[ors - offset - 1] && (rs > 1)) {
                    --rs;
                }
            }
            // Set zeros after 'rs', alternative to resizing to size 'rs'.
            result.zero_after(rs);
        }

        static inline constexpr void right_shift_limb(big_integer& result, double_limb_type s) {
            typedef big_integer big_integer_t;

            limb_type offset = static_cast<limb_type>(s / big_integer_t::limb_bits);
            BOOST_ASSERT((s % big_integer_t::limb_bits) == 0);
            unsigned ors = result.size();
            unsigned rs = ors;
            if (offset >= rs) {
                result.zero_after(0);
                return;
            }
            rs -= offset;
            typename big_integer_t::limb_pointer pr = result.limbs();
            unsigned i = 0;
            for (; i < rs; ++i) {
                pr[i] = pr[i + offset];
            }
            // Set zeros after 'rs', alternative to resizing to size 'rs'.
            result.zero_after(rs);
        }

        static inline constexpr void right_shift_generic(big_integer& result, double_limb_type s) {
            typedef big_integer big_integer_t;
            limb_type offset = static_cast<limb_type>(s / big_integer_t::limb_bits);
            limb_type shift = static_cast<limb_type>(s % big_integer_t::limb_bits);
            unsigned ors = result.size();
            unsigned rs = ors;

            if (offset >= rs) {
                result = limb_type(0);
                return;
            }
            rs -= offset;
            typename big_integer_t::limb_pointer pr = result.limbs();
            if ((pr[ors - 1] >> shift) == 0) {
                if (--rs == 0) {
                    result = limb_type(0);
                    return;
                }
            }
            unsigned i = 0;

            // This code only works for non-zero shift, otherwise we invoke undefined behaviour!
            BOOST_ASSERT(shift);
            for (; i + offset + 1 < ors; ++i) {
                pr[i] = pr[i + offset] >> shift;
                pr[i] |= pr[i + offset + 1] << (big_integer_t::limb_bits - shift);
            }
            pr[i] = pr[i + offset] >> shift;

            // We cannot resize any more, so we need to set all the limbs to zero.
            result.zero_after(rs);
        }

        static inline constexpr void right_shift(big_integer& result, double_limb_type s) noexcept {
            if (!s) {
                return;
            }

#if BOOST_ENDIAN_LITTLE_BYTE && defined(CRYPTO3_MP_USE_LIMB_SHIFT)
            constexpr const limb_type limb_shift_mask = big_integer::limb_bits - 1;
            constexpr const limb_type byte_shift_mask = CHAR_BIT - 1;

            if ((s & limb_shift_mask) == 0) right_shift_limb(result, s);
#ifdef BOOST_MP_NO_CONSTEXPR_DETECTION
            else if ((s & byte_shift_mask) == 0)
#else
            else if (((s & byte_shift_mask) == 0) && !BOOST_MP_IS_CONST_EVALUATED(s))
#endif
            {
                right_shift_byte(result, s);
            }
#elif BOOST_ENDIAN_LITTLE_BYTE
            constexpr const limb_type byte_shift_mask = CHAR_BIT - 1;

#ifdef BOOST_MP_NO_CONSTEXPR_DETECTION
            if ((s & byte_shift_mask) == 0)
#else
            constexpr limb_type limb_shift_mask = big_integer::limb_bits - 1;
            if (BOOST_MP_IS_CONST_EVALUATED(s) && ((s & limb_shift_mask) == 0)) {
                right_shift_limb(result, s);
            } else if (((s & byte_shift_mask) == 0) && !BOOST_MP_IS_CONST_EVALUATED(s))
#endif
            {
                right_shift_byte(result, s);
            }
#else
            constexpr const limb_type limb_shift_mask = big_integer::limb_bits - 1;

            if ((s & limb_shift_mask) == 0) {
                right_shift_limb(result, s);
            }
#endif
            else {
                right_shift_generic(result, s);
            }
        }

        // Modulus/divide

        // These should be called only for creation of Montgomery and Barett
        // params, no during "normal" execution, so we do NOT care about the execution speed,
        // and will just redirect calls to normal boost::cpp_int.

        // Just a call to the upper function, similar to operator*=.
        // Caller is responsible for the result to fit in Bits1 Bits, we will NOT throw!
        template<unsigned Bits2>
        static inline constexpr void modulus(big_integer& result,
                                             const big_integer<Bits2>& a) noexcept {
            auto result_cpp_int = result.to_cpp_int();
            result_cpp_int %= a.to_cpp_int();
            result.from_cpp_int(result_cpp_int);
        }

        template<unsigned Bits2>
        static inline constexpr void divide(big_integer& result,
                                            const big_integer<Bits2>& a) noexcept {
            auto result_cpp_int = result.to_cpp_int();
            result_cpp_int /= a.to_cpp_int();
            result.from_cpp_int(result_cpp_int);
        }

        // Multiplication

        // These should be called only for creation of Montgomery and Barett
        // params, calculation of inverse element and montgomery_reduce. Since these functions
        // are relatively slow and are not called very often, we will not optimize them. We do
        // NOT care about the execution speed, and will just redirect calls to normal
        // boost::cpp_int.

        // Caller is responsible for the result to fit in Bits1 Bits, we will NOT throw!!!

        static inline constexpr void multiply(big_integer& result, const limb_type& b) noexcept {
            auto result_cpp_int = result.to_cpp_int();
            result_cpp_int *= b;
            result.from_cpp_int(result_cpp_int);
        }

        template<unsigned Bits2>
        static inline constexpr void multiply(big_integer& result,
                                              const big_integer<Bits2>& a) noexcept {
            auto result_cpp_int = result.to_cpp_int();
            result_cpp_int = static_cast<decltype(result_cpp_int)>(result_cpp_int * a.to_cpp_int());
            result.from_cpp_int(result_cpp_int);
        }

        // Assignment

        template<typename T,
                 std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, int> = 0>
        inline constexpr void do_assign_integral(T a) noexcept {
            if constexpr (sizeof(T) <= sizeof(limb_type)) {
                this->limbs()[0] = a;
                this->zero_after(1);
            } else {
                static_assert(sizeof(T) % sizeof(limb_type) == 0);
                constexpr std::size_t n = sizeof(T) / sizeof(limb_type);
                for (std::size_t i = 0; i < n; ++i) {
                    limbs()[i] = a & static_cast<T>(static_cast<limb_type>(-1));
                    a >>= limb_bits;
                }
                zero_after(n);
            }
            this->normalize();
        }

        template<unsigned Bits2>
        inline constexpr void do_assign(const big_integer<Bits2>& other) noexcept {
            unsigned count = (std::min)(other.size(), this->size());
            for (unsigned i = 0; i < count; ++i) {
                this->limbs()[i] = other.limbs()[i];
            }
            // Zero out everything after (std::min)(other.size(), this->size()), so if size of
            // other was less, we have 0s at the end.
            this->zero_after((std::min)(other.size(), this->size()));
            this->normalize();
        }

      private:
        // Data

        // m_data[0] contains the lowest bits.
        std::array<limb_type, internal_limb_count> m_data{0};

        // This is a temporary value which is set when carry has happend during addition.
        // If this value is true, reduction by modulus must happen next.
        bool m_carry = false;
    };
}  // namespace nil::crypto3::multiprecision
