//---------------------------------------------------------------------------//
// Copyright (c) 2012 John Maddock
// Copyright (c) 2020 Madhur Chauhan
// Copyright (c) 2020 John Maddock
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <algorithm>
#include <climits>
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <type_traits>

#include <boost/assert.hpp>

#include "nil/crypto3/multiprecision/detail/big_uint/internal_conversions.hpp"
#include "nil/crypto3/multiprecision/detail/big_uint/storage.hpp"
#include "nil/crypto3/multiprecision/detail/intel_intrinsics.hpp"
#include "nil/crypto3/multiprecision/type_traits.hpp"
#include "nil/crypto3/multiprecision/unsigned_utils.hpp"

namespace nil::crypto3::multiprecision {
    template<std::size_t Bits>
    class big_uint;

    namespace detail {

        enum class operation_mode { checked, wrapping };

        // Addition/subtraction

        template<std::size_t Bits1, std::size_t Bits2, std::size_t Bits3>
        [[nodiscard]] constexpr bool add_constexpr_unsigned(big_uint<Bits1>& result,
                                                            const big_uint<Bits2>& a,
                                                            const big_uint<Bits3>& b) noexcept {
            static_assert(Bits1 >= Bits2 && Bits1 >= Bits3, "invalid argument size");
            //
            // This is the generic, C++ only version of addition.
            // It's also used for all constexpr branches, hence the name.
            //
            double_limb_type carry = 0;
            std::size_t as = a.used_limbs();
            std::size_t bs = b.used_limbs();
            auto [m, x] = std::minmax(as, bs);

            if (x <= 1) {
                double_limb_type v = static_cast<double_limb_type>(*a.limbs()) +
                                     static_cast<double_limb_type>(*b.limbs());
                if (result.limb_count() == 1) {
                    constexpr double_limb_type mask = big_uint<Bits1>::upper_limb_mask;
                    if (v & ~mask) {
                        v &= mask;
                        carry = 1;
                    }
                }
                result = v;
                return carry;
            }

            result.zero_after(x);

            const_limb_pointer pa = a.limbs();
            const_limb_pointer pb = b.limbs();
            limb_pointer pr = result.limbs();
            limb_pointer pr_end = pr + m;

            if (as < bs) {
                std::swap(pa, pb);
            }

            // First where a and b overlap:
            while (pr != pr_end) {
                carry += static_cast<double_limb_type>(*pa) + static_cast<double_limb_type>(*pb);
                *pr = static_cast<limb_type>(carry);
                carry >>= limb_bits;
                ++pr, ++pa, ++pb;
            }
            pr_end += x - m;

            // Now where only a has digits:
            while (pr != pr_end) {
                if (!carry) {
                    if (pa != pr) {
                        std::copy(pa, pa + (pr_end - pr), pr);
                    }
                    break;
                }
                carry += static_cast<double_limb_type>(*pa);
                *pr = static_cast<limb_type>(carry);
                carry >>= limb_bits;
                ++pr, ++pa;
            }

            BOOST_ASSERT(carry <= 1);

            if (carry) {
                if (result.limb_count() > x) {
                    result.limbs()[x] = static_cast<limb_type>(1u);
                    carry = 0;
                }
            }

            if constexpr (Bits1 % limb_bits != 0) {
                // If we have set any bit above "Bits", then we have a carry.
                carry = result.normalize();
                BOOST_ASSERT(carry <= 1);
            }

            return carry;
        }

        template<operation_mode Mode>
        constexpr void subtract_overflow() noexcept(Mode == operation_mode::wrapping) {
            if constexpr (Mode == operation_mode::checked) {
                throw std::overflow_error("big_uint: subtraction overflow");
            }
        }

        //
        // Core subtraction routine:
        //
        template<operation_mode Mode, std::size_t Bits1, std::size_t Bits2, std::size_t Bits3>
        constexpr void subtract_constexpr_unsigned(big_uint<Bits1>& result,
                                                   const big_uint<Bits2>& a,
                                                   const big_uint<Bits3>& b) {
            static_assert(Bits1 >= Bits2 && Bits1 >= Bits3, "invalid argument size");
            //
            // This is the generic, C++ only version of subtraction.
            // It's also used for all constexpr branches, hence the name.
            //
            double_limb_type borrow = 0;
            std::size_t as = a.used_limbs();
            std::size_t bs = b.used_limbs();
            auto [m, x] = std::minmax(as, bs);
            //
            // special cases for small limb counts:
            //
            if (x <= 1) {
                bool s = false;
                limb_type al = *a.limbs();
                limb_type bl = *b.limbs();
                if (al < bl) {
                    subtract_overflow<Mode>();
                    std::swap(al, bl);
                    s = true;
                }
                result = al - bl;
                if (s) {
                    result.wrapping_neg_inplace();
                }
                return;
            }

            int c = a.compare(b);
            result.zero_after(x);

            const_limb_pointer pa = a.limbs();
            const_limb_pointer pb = b.limbs();
            limb_pointer pr = result.limbs();

            bool swapped = false;
            if (c < 0) {
                subtract_overflow<Mode>();
                std::swap(pa, pb);
                swapped = true;
            } else if (c == 0) {
                result = static_cast<limb_type>(0u);
                return;
            }

            std::size_t i = 0;
            // First where a and b overlap:
            while (i < m) {
                borrow = static_cast<double_limb_type>(pa[i]) -
                         static_cast<double_limb_type>(pb[i]) - borrow;
                pr[i] = static_cast<limb_type>(borrow);
                borrow = (borrow >> limb_bits) & 1u;
                ++i;
            }
            // Now where only a has digits, only as long as we've borrowed:
            while (borrow && (i < x)) {
                borrow = static_cast<double_limb_type>(pa[i]) - borrow;
                pr[i] = static_cast<limb_type>(borrow);
                borrow = (borrow >> limb_bits) & 1u;
                ++i;
            }
            // Any remaining digits are the same as those in pa:
            if ((x != i) && (pa != pr)) {
                std::copy(pa + i, pa + x, pr + i);
            }
            BOOST_ASSERT(0 == borrow);

            if (swapped) {
                result.wrapping_neg_inplace();
            }
        }

#ifdef NIL_CO3_MP_HAS_INTRINSICS
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
        template<std::size_t Bits1, std::size_t Bits2, std::size_t Bits3>
        [[nodiscard]] constexpr bool add_unsigned(big_uint<Bits1>& result, const big_uint<Bits2>& a,
                                                  const big_uint<Bits3>& b) noexcept {
            static_assert(Bits1 >= Bits2 && Bits1 >= Bits3, "invalid argument size");

            if (std::is_constant_evaluated()) {
                return add_constexpr_unsigned(result, a, b);
            }

            std::size_t as = a.used_limbs();
            std::size_t bs = b.used_limbs();
            auto [m, x] = std::minmax(as, bs);

            if (x <= 1) {
                double_limb_type v = static_cast<double_limb_type>(*a.limbs()) +
                                     static_cast<double_limb_type>(*b.limbs());
                bool carry = false;
                if (result.limb_count() == 1) {
                    constexpr double_limb_type mask = big_uint<Bits1>::upper_limb_mask;
                    if (v & ~mask) {
                        v &= mask;
                        carry = true;
                    }
                }
                result = v;
                return carry;
            }

            result.zero_after(x);

            const_limb_pointer pa = a.limbs();
            const_limb_pointer pb = b.limbs();
            limb_pointer pr = result.limbs();

            if (as < bs) {
                std::swap(pa, pb);
            }

            std::size_t i = 0;
            unsigned char carry = 0;
            for (; i + 4 <= m; i += 4) {
                carry = addcarry_limb(carry, pa[i + 0], pb[i + 0], pr + i);
                carry = addcarry_limb(carry, pa[i + 1], pb[i + 1], pr + i + 1);
                carry = addcarry_limb(carry, pa[i + 2], pb[i + 2], pr + i + 2);
                carry = addcarry_limb(carry, pa[i + 3], pb[i + 3], pr + i + 3);
            }
            for (; i < m; ++i) {
                carry = addcarry_limb(carry, pa[i], pb[i], pr + i);
            }
            for (; i < x && carry; ++i) {
                // We know carry is 1, so we just need to increment pa[i] (ie add a literal 1)
                // and capture the carry:
                carry = addcarry_limb(0, pa[i], 1, pr + i);
            }
            if (i == x && carry) {
                if (result.limb_count() > x) {
                    result.limbs()[x] = static_cast<limb_type>(1u);
                    carry = 0;
                }
            } else if ((x != i) && (pa != pr)) {
                // Copy remaining digits only if we need to:
                std::copy(pa + i, pa + x, pr + i);
            }

            BOOST_ASSERT(carry <= 1);

            if constexpr (Bits1 % limb_bits != 0) {
                // If we have set any bit above "Bits", then we have a carry.
                carry = result.normalize();
                BOOST_ASSERT(carry <= 1);
            }

            return carry;
        }

        template<operation_mode Mode, std::size_t Bits1, std::size_t Bits2, std::size_t Bits3>
        constexpr void subtract_unsigned(big_uint<Bits1>& result, const big_uint<Bits2>& a,
                                         const big_uint<Bits3>& b) {
            static_assert(Bits1 >= Bits2 && Bits1 >= Bits3, "invalid argument size");

            if (std::is_constant_evaluated()) {
                subtract_constexpr_unsigned<Mode>(result, a, b);
                return;
            }

            std::size_t as = a.used_limbs();
            std::size_t bs = b.used_limbs();
            auto [m, x] = std::minmax(as, bs);
            //
            // special cases for small limb counts:
            //
            if (x <= 1) {
                bool s = false;
                limb_type al = *a.limbs();
                limb_type bl = *b.limbs();
                if (al < bl) {
                    subtract_overflow<Mode>();
                    std::swap(al, bl);
                    s = true;
                }
                result = al - bl;
                if (s) {
                    result.wrapping_neg_inplace();
                }
                return;
            }

            int c = a.compare(b);
            result.zero_after(x);

            const_limb_pointer pa = a.limbs();
            const_limb_pointer pb = b.limbs();
            limb_pointer pr = result.limbs();

            bool swapped = false;
            if (c < 0) {
                subtract_overflow<Mode>();
                std::swap(pa, pb);
                swapped = true;
            } else if (c == 0) {
                result = static_cast<limb_type>(0u);
                return;
            }

            std::size_t i = 0;
            unsigned char borrow = 0;
            // First where a and b overlap:
            for (; i + 4 <= m; i += 4) {
                borrow = subborrow_limb(borrow, pa[i], pb[i], pr + i);
                borrow = subborrow_limb(borrow, pa[i + 1], pb[i + 1], pr + i + 1);
                borrow = subborrow_limb(borrow, pa[i + 2], pb[i + 2], pr + i + 2);
                borrow = subborrow_limb(borrow, pa[i + 3], pb[i + 3], pr + i + 3);
            }
            for (; i < m; ++i) {
                borrow = subborrow_limb(borrow, pa[i], pb[i], pr + i);
            }
            // Now where only a has digits, only as long as we've borrowed:
            while (borrow && (i < x)) {
                borrow = subborrow_limb(borrow, pa[i], 0, pr + i);
                ++i;
            }
            // Any remaining digits are the same as those in pa:
            if ((x != i) && (pa != pr)) {
                std::copy(pa + i, pa + x, pr + i);
            }
            BOOST_ASSERT(0 == borrow);

            if (swapped) {
                result.wrapping_neg_inplace();
            }
        }

#else

        template<std::size_t Bits1, std::size_t Bits2, std::size_t Bits3>
        [[nodiscard]] constexpr bool add_unsigned(big_uint<Bits1>& result, const big_uint<Bits2>& a,
                                                  const big_uint<Bits3>& b) noexcept {
            return add_constexpr_unsigned(result, a, b);
        }

        template<operation_mode Mode, std::size_t Bits1, std::size_t Bits2, std::size_t Bits3>
        constexpr void subtract_unsigned(big_uint<Bits1>& result, const big_uint<Bits2>& a,
                                         const big_uint<Bits3>& b) {
            subtract_constexpr_unsigned<Mode>(result, a, b);
        }

#endif

        template<std::size_t Bits1, std::size_t Bits2>
        [[nodiscard]] constexpr limb_type add_unsigned(big_uint<Bits1>& result,
                                                       const big_uint<Bits2>& a,
                                                       const limb_type& b) noexcept {
            static_assert(Bits1 >= Bits2, "invalid argument size");

            double_limb_type carry = b;
            limb_pointer pr = result.limbs();
            const_limb_pointer pa = a.limbs();

            std::size_t i = 0;
            // Addition with carry until we either run out of digits or carry is zero:
            for (; carry && (i < result.limb_count()); ++i) {
                carry += static_cast<double_limb_type>(pa[i]);
                pr[i] = static_cast<limb_type>(carry);
                carry >>= limb_bits;
            }
            // Just copy any remaining digits:
            if (&a != &result) {
                std::copy(pa + i, pa + a.limb_count(), pr + i);
            }

            BOOST_ASSERT(carry <= 1);

            if (carry) {
                if (result.limb_count() > a.limb_count()) {
                    result.limbs()[a.limb_count()] = static_cast<limb_type>(1u);
                    carry = 0;
                }
            }

            if constexpr (Bits1 % limb_bits != 0) {
                // If we have set any bit above "Bits", then we have a carry.
                carry = result.normalize();
            }

            BOOST_ASSERT(carry <= max_limb_value);

            return carry;
        }

        //
        // And again to subtract a single limb:
        //
        template<operation_mode Mode, std::size_t Bits1, std::size_t Bits2>
        constexpr void subtract_unsigned(big_uint<Bits1>& result, const big_uint<Bits2>& a,
                                         const limb_type& b) {
            static_assert(Bits1 >= Bits2, "invalid argument size");

            // Subtract one limb.
            std::size_t as = a.used_limbs();
            result.zero_after(as);
            constexpr double_limb_type borrow = static_cast<double_limb_type>(max_limb_value) + 1;

            limb_pointer pr = result.limbs();
            const_limb_pointer pa = a.limbs();

            if (*pa >= b) {
                *pr = *pa - b;
                if (&result != &a) {
                    std::copy(pa + 1, pa + as, pr + 1);
                }
            } else if (as <= 1) {
                subtract_overflow<Mode>();
                *pr = b - *pa;
                result.wrapping_neg_inplace();
            } else {
                *pr = static_cast<limb_type>((borrow + *pa) - b);
                std::size_t i = 1;
                while (!pa[i]) {
                    pr[i] = max_limb_value;
                    ++i;
                }
                pr[i] = pa[i] - 1;
                if (&result != &a) {
                    ++i;
                    std::copy(pa + i, pa + as, pr + i);
                }
            }
        }

        template<operation_mode Mode>
        constexpr void check_addition(bool carry) noexcept(Mode == operation_mode::wrapping) {
            if constexpr (Mode == operation_mode::checked) {
                if (carry) {
                    throw std::overflow_error("fixed precision overflow");
                }
            }
        }

        template<operation_mode Mode, std::size_t Bits1, std::size_t Bits2, typename T>
        constexpr void add(big_uint<Bits1>& result, const big_uint<Bits2>& a,
                           const T& b) noexcept(Mode == operation_mode::wrapping) {
            static_assert(is_integral_v<T>);
            if constexpr (std::is_signed_v<T>) {
                auto b_abs = unsigned_abs(b);
                if (b < 0) {
                    subtract_unsigned<Mode>(result, a, as_limb_type_or_big_uint(b_abs));
                } else {
                    check_addition<Mode>(add_unsigned(result, a, as_limb_type_or_big_uint(b_abs)));
                }
            } else {
                check_addition<Mode>(add_unsigned(result, a, as_limb_type_or_big_uint(b)));
            }
        }

        template<operation_mode Mode, std::size_t Bits1, std::size_t Bits2, typename T>
        constexpr void subtract(big_uint<Bits1>& result, const big_uint<Bits2>& a,
                                const T& b) noexcept(Mode == operation_mode::wrapping) {
            static_assert(is_integral_v<T>);
            if constexpr (std::is_signed_v<T>) {
                auto b_abs = unsigned_abs(b);
                if (b < 0) {
                    check_addition<Mode>(add_unsigned(result, a, as_limb_type_or_big_uint(b_abs)));
                } else {
                    subtract_unsigned<Mode>(result, a, as_limb_type_or_big_uint(b_abs));
                }
            } else {
                subtract_unsigned<Mode>(result, a, as_limb_type_or_big_uint(b));
            }
        }

        // Modulus/divide

        // This should be called only for creation of Montgomery and
        // Barett params, not during "normal" execution, so we do not
        // care about the execution speed.

        template<std::size_t Bits1, std::size_t Bits2>
        constexpr void divide(big_uint<Bits1>* div, const big_uint<Bits1>& x,
                              const big_uint<Bits2>& y, big_uint<Bits1>& rem) {
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
            and avoids the normalisation step which would require extra
            storage.
            */

            if (y.is_zero()) {
                throw std::overflow_error("integer division by zero");
            }

            const_limb_pointer px = x.limbs();
            const_limb_pointer py = y.limbs();

            if (x.is_zero()) {
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
            // Check if the remainder is already less than the divisor,
            // if so we already have the result.  Note we try and avoid
            // a full compare if we can:
            //
            if (rem < y) {
                return;
            }

            big_uint<Bits1> t;
            bool rem_neg = false;

            //
            // See if we can short-circuit long division, and use basic
            // arithmetic instead:
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
            // This is initialised just to keep the compiler from
            // emitting useless warnings later on:
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
                // Calculate our best guess for how many times y divides
                // into rem:
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
                    BOOST_ASSERT(b);
                    double_limb_type v = a / b;
                    guess = static_cast<limb_type>(v);
                }
                BOOST_ASSERT(guess);  // If the guess ever gets to
                                      // zero we go on forever....
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
                // Calculate guess * y, we use a fused mutiply-shift
                // O(N) for this rather than a full O(N^2) multiply:
                //
                double_limb_type carry = 0;
                // t.resize(y.limb_count() + shift + 1, y.limb_count()
                // + shift); bool truncated_t = (t.limb_count() !=
                // y.limb_count() + shift + 1);
                const bool truncated_t = y_order + shift + 2 > big_uint<Bits1>::static_limb_count;
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
                    // t.resize(t.limb_count() - 1, t.limb_count() -
                    // 1);
                }
                //
                // Update rem in a way that won't actually produce a
                // negative result in case the argument types are
                // unsigned:
                //
                if (truncated_t && carry) {
                    BOOST_ASSERT_MSG(false, "how can this even happen");
                    // We need to calculate 2^n + t - rem
                    // where n is the number of bits in this type.
                    // Simplest way is to get 2^n - rem by complementing
                    // and incrementing rem, then add t to it.
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
                // First time through we need to strip any leading zero,
                // otherwise the termination condition goes belly-up:
                //
                // if (div && first_pass) {
                //     first_pass = false;
                //     // while (pdiv[div->limb_count() - 1] == 0)
                //     //     div->resize(div->limb_count() - 1,
                //     div->limb_count() - 1);
                // }
                //
                // Update rem_order:
                //
                rem_order = rem.order();
            }
            // Termination condition is really just a check that rem >
            // y, but with a common short-circuit case handled first:
            while ((rem_order >= y_order) && ((rem_order > y_order) || (rem >= y)));

            //
            // We now just have to normalise the result:
            //
            if (rem_neg && !rem.is_zero()) {
                // We have one too many in the result:
                if (div) {
                    --*div;
                }
                rem = static_cast<big_uint<Bits1>>(y - rem);
            }

            // remainder must be less than the divisor or our code has
            // failed
            BOOST_ASSERT(rem < y);
        }

        // Multiplication

        template<operation_mode Mode>
        constexpr void multiplication_overflow_when(bool condition) noexcept(
            Mode == operation_mode::wrapping) {
            if constexpr (Mode == operation_mode::checked) {
                if (condition) {
                    throw std::overflow_error("big_uint: multiplication overflow");
                }
            }
        }

        // This is called during creation of Montgomery and Barett
        // params, calculation of inverse element and montgomery_reduce. If they are slow
        // or multiplication is needed in some other hot path this should be optimized.
        template<operation_mode Mode, std::size_t Bits1, std::size_t Bits2, typename T>
        constexpr void multiply(big_uint<Bits1>& final_result, const big_uint<Bits2>& a,
                                const T& b_orig) {
            static_assert(Bits1 >= Bits2);

            auto b = as_big_uint(b_orig);
            big_uint<Bits1> result;
            std::size_t as = a.used_limbs();
            std::size_t bs = b.used_limbs();
            const_limb_pointer pa = a.limbs();
            const_limb_pointer pb = b.limbs();
            limb_pointer pr = result.limbs();
            result.zero_after(0);

            double_limb_type carry = 0;
            for (std::size_t i = 0; i < as; ++i) {
                BOOST_ASSERT(result.limb_count() > i);
                std::size_t inner_limit = (std::min)(result.limb_count() - i, bs);
                multiplication_overflow_when<Mode>(inner_limit < bs);
                std::size_t j = 0;
                for (; j < inner_limit; ++j) {
                    BOOST_ASSERT(i + j < result.limb_count());
                    carry +=
                        static_cast<double_limb_type>(pa[i]) * static_cast<double_limb_type>(pb[j]);
                    BOOST_ASSERT(max_double_limb_value - carry >= pr[i + j]);
                    carry += pr[i + j];
                    pr[i + j] = static_cast<limb_type>(carry);
                    carry >>= limb_bits;
                    BOOST_ASSERT(carry <= max_limb_value);
                }
                if (carry) {
                    multiplication_overflow_when<Mode>(i + j >= result.limb_count());
                    if (i + j < result.limb_count()) {
                        pr[i + j] = static_cast<limb_type>(carry);
                    }
                    carry = 0;
                }
            }
            bool truncated = result.normalize();
            multiplication_overflow_when<Mode>(truncated);
            // TODO(ioxid): optimize this copy
            final_result = result;
        }
    }  // namespace detail
}  // namespace nil::crypto3::multiprecision
