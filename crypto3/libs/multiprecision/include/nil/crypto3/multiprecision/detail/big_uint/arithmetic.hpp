#pragma once

#include <algorithm>
#include <climits>
#include <cstddef>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <type_traits>

#include "nil/crypto3/multiprecision/detail/assert.hpp"
#include "nil/crypto3/multiprecision/detail/big_uint/storage.hpp"
#include "nil/crypto3/multiprecision/detail/big_uint/type_traits.hpp"
#include "nil/crypto3/multiprecision/detail/integer_utils.hpp"
#include "nil/crypto3/multiprecision/detail/intel_intrinsics.hpp"

namespace nil::crypto3::multiprecision {
    template<std::size_t Bits>
    class big_uint;

    namespace detail {

        // Addition/subtraction

        template<std::size_t Bits1, std::size_t Bits2, std::size_t Bits3>
        constexpr void add_constexpr_unsigned(big_uint<Bits1>& result, const big_uint<Bits2>& a,
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
            if (x == 1) {
                double_limb_type v = static_cast<double_limb_type>(*a.limbs()) +
                                     static_cast<double_limb_type>(*b.limbs());
                if (result.limbs_count() == 1) {
                    double_limb_type mask = big_uint<Bits1>::upper_limb_mask;
                    if (v & ~mask) {
                        v &= mask;
                        result.set_carry(true);
                    }
                }
                result = v;
                return;
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

            if (carry) {
                if (result.limbs_count() > x) {
                    result.limbs()[x] = static_cast<limb_type>(1u);
                    carry = 0;
                }
            }

            if constexpr (Bits1 % limb_bits == 0) {
                result.set_carry(carry);
            } else {
                limb_type mask = big_uint<Bits1>::upper_limb_mask;
                // If we have set any bit above "Bits", then we have a carry.
                if (result.limbs()[result.limbs_count() - 1] & ~mask) {
                    result.limbs()[result.limbs_count() - 1] &= mask;
                    result.set_carry(true);
                }
            }
        }

        //
        // Core subtraction routine:
        //
        template<std::size_t Bits1, std::size_t Bits2, std::size_t Bits3>
        constexpr void subtract_constexpr_unsigned(big_uint<Bits1>& result,
                                                   const big_uint<Bits2>& a,
                                                   const big_uint<Bits3>& b) noexcept {
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
            if (x == 1) {
                bool s = false;
                limb_type al = *a.limbs();
                limb_type bl = *b.limbs();
                if (bl > al) {
                    std::swap(al, bl);
                    s = true;
                }
                result = al - bl;
                if (s) {
                    result.negate();
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
            NIL_CO3_MP_ASSERT(0 == borrow);

            //
            // We may have lost digits, if so update limb usage count:
            //
            result.normalize();
            if (swapped) {
                result.negate();
            }
        }

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
        template<std::size_t Bits1, std::size_t Bits2, std::size_t Bits3>
        constexpr void add_unsigned(big_uint<Bits1>& result, const big_uint<Bits2>& a,
                                    const big_uint<Bits3>& b) noexcept {
            static_assert(Bits1 >= Bits2 && Bits1 >= Bits3, "invalid argument size");
            if (std::is_constant_evaluated()) {
                add_constexpr_unsigned(result, a, b);
            } else {
                std::size_t as = a.used_limbs();
                std::size_t bs = b.used_limbs();
                auto [m, x] = std::minmax(as, bs);

                if (x == 1) {
                    double_limb_type v = static_cast<double_limb_type>(*a.limbs()) +
                                         static_cast<double_limb_type>(*b.limbs());
                    if (result.limbs_count() == 1) {
                        double_limb_type mask = big_uint<Bits1>::upper_limb_mask;
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
                    if (big_uint<Bits1>::internal_limb_count > x) {
                        result.limbs()[x] = static_cast<limb_type>(1u);
                    }
                } else if ((x != i) && (pa != pr)) {
                    // Copy remaining digits only if we need to:
                    std::copy(pa + i, pa + x, pr + i);
                }

                if constexpr (Bits1 % limb_bits == 0) {
                    result.set_carry(carry);
                } else {
                    limb_type mask = big_uint<Bits1>::upper_limb_mask;
                    // If we have set any bit above "Bits", then we have a carry.
                    if (result.limbs()[result.limbs_count() - 1] & ~mask) {
                        result.limbs()[result.limbs_count() - 1] &= mask;
                        result.set_carry(true);
                    }
                }
            }
        }

        template<std::size_t Bits1, std::size_t Bits2, std::size_t Bits3>
        constexpr void subtract_unsigned(big_uint<Bits1>& result, const big_uint<Bits2>& a,
                                         const big_uint<Bits3>& b) noexcept {
            static_assert(Bits1 >= Bits2 && Bits1 >= Bits3, "invalid argument size");

            if (std::is_constant_evaluated()) {
                subtract_constexpr_unsigned(result, a, b);
            } else {
                std::size_t as = a.used_limbs();
                std::size_t bs = b.used_limbs();
                auto [m, x] = std::minmax(as, bs);
                //
                // special cases for small limb counts:
                //
                if (x == 1) {
                    bool s = false;
                    limb_type al = *a.limbs();
                    limb_type bl = *b.limbs();
                    if (bl > al) {
                        std::swap(al, bl);
                        s = true;
                    }
                    result = al - bl;
                    if (s) {
                        result.negate();
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
                    borrow = detail::subborrow_limb(borrow, pa[i], pb[i], pr + i);
                    borrow = detail::subborrow_limb(borrow, pa[i + 1], pb[i + 1], pr + i + 1);
                    borrow = detail::subborrow_limb(borrow, pa[i + 2], pb[i + 2], pr + i + 2);
                    borrow = detail::subborrow_limb(borrow, pa[i + 3], pb[i + 3], pr + i + 3);
                }
                for (; i < m; ++i) {
                    borrow = detail::subborrow_limb(borrow, pa[i], pb[i], pr + i);
                }
                // Now where only a has digits, only as long as we've borrowed:
                while (borrow && (i < x)) {
                    borrow = detail::subborrow_limb(borrow, pa[i], 0, pr + i);
                    ++i;
                }
                // Any remaining digits are the same as those in pa:
                if ((x != i) && (pa != pr)) {
                    std::copy(pa + i, pa + x, pr + i);
                }
                NIL_CO3_MP_ASSERT(0 == borrow);
                result.normalize();
                if (swapped) {
                    result.negate();
                }
            }  // constexpr.
        }

#else

        template<std::size_t Bits1, std::size_t Bits2, std::size_t Bits3>
        constexpr void add_unsigned(big_uint<Bits1>& result, const big_uint<Bits2>& a,
                                    const big_uint<Bits3>& b) noexcept {
            add_constexpr_unsigned(result, a, b);
        }

        template<std::size_t Bits1, std::size_t Bits2, std::size_t Bits3>
        constexpr void subtract_unsigned(big_uint<Bits1>& result, const big_uint<Bits2>& a,
                                         const big_uint<Bits3>& b) noexcept {
            subtract_constexpr_unsigned(result, a, b);
        }

#endif

        template<std::size_t Bits1, std::size_t Bits2>
        constexpr void add_unsigned(big_uint<Bits1>& result, const big_uint<Bits2>& a,
                                    const limb_type& b) noexcept {
            static_assert(Bits1 >= Bits2, "invalid argument size");

            double_limb_type carry = b;
            limb_pointer pr = result.limbs();
            const_limb_pointer pa = a.limbs();
            std::size_t i = 0;
            // Addition with carry until we either run out of digits or carry is zero:
            for (; carry && (i < result.limbs_count()); ++i) {
                carry += static_cast<double_limb_type>(pa[i]);
                pr[i] = static_cast<limb_type>(carry);
                carry >>= limb_bits;
            }
            // Just copy any remaining digits:
            if (&a != &result) {
                std::copy(pa + i, pa + a.limbs_count(), pr + i);
            }

            if (carry) {
                if (result.limbs_count() > a.limbs_count()) {
                    result.limbs()[a.limbs_count()] = static_cast<limb_type>(carry);
                    carry = 0;
                }
            }

            if constexpr (Bits1 % limb_bits == 0) {
                result.set_carry(carry);
            } else {
                limb_type mask = big_uint<Bits1>::upper_limb_mask;
                // If we have set any bit above "Bits", then we have a carry.
                if (pr[result.limbs_count() - 1] & ~mask) {
                    pr[result.limbs_count() - 1] &= mask;
                    result.set_carry(true);
                }
            }
        }

        //
        // And again to subtract a single limb:
        //
        template<std::size_t Bits1, std::size_t Bits2>
        constexpr void subtract_unsigned(big_uint<Bits1>& result, const big_uint<Bits2>& a,
                                         const limb_type& b) noexcept {
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
            } else if (as == 1) {
                *pr = b - *pa;
                result.negate();
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
                result.normalize();
            }
        }

        template<std::size_t Bits1, std::size_t Bits2, typename T>
        constexpr void add(big_uint<Bits1>& result, const big_uint<Bits2>& a, const T& b) noexcept {
            static_assert(detail::is_integral_v<T>);
            if constexpr (std::is_signed_v<T>) {
                auto b_abs = unsigned_abs(b);
                if (b < 0) {
                    subtract_unsigned(result, a, detail::as_limb_type_or_big_uint(b_abs));
                }
                add_unsigned(result, a, detail::as_limb_type_or_big_uint(b_abs));
            } else {
                add_unsigned(result, a, detail::as_limb_type_or_big_uint(b));
            }
        }

        template<std::size_t Bits1, std::size_t Bits2, typename T>
        constexpr void subtract(big_uint<Bits1>& result, const big_uint<Bits2>& a,
                                const T& b) noexcept {
            static_assert(detail::is_integral_v<T>);
            if constexpr (std::is_signed_v<T>) {
                auto b_abs = unsigned_abs(b);
                if (b < 0) {
                    detail::add_unsigned(result, a, detail::as_limb_type_or_big_uint(b_abs));
                } else {
                    detail::subtract_unsigned(result, a, detail::as_limb_type_or_big_uint(b_abs));
                }
            } else {
                detail::subtract_unsigned(result, a, detail::as_limb_type_or_big_uint(b));
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
                    NIL_CO3_MP_ASSERT(b);
                    double_limb_type v = a / b;
                    guess = static_cast<limb_type>(v);
                }
                NIL_CO3_MP_ASSERT(guess);  // If the guess ever gets to
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
                // t.resize(y.limbs_count() + shift + 1, y.limbs_count()
                // + shift); bool truncated_t = (t.limbs_count() !=
                // y.limbs_count() + shift + 1);
                const bool truncated_t = y_order + shift + 2 > big_uint<Bits1>::internal_limb_count;
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
                    // t.resize(t.limbs_count() - 1, t.limbs_count() -
                    // 1);
                }
                //
                // Update rem in a way that won't actually produce a
                // negative result in case the argument types are
                // unsigned:
                //
                if (truncated_t && carry) {
                    NIL_CO3_MP_ASSERT_MSG(false, "how can this even happen");
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
                //     // while (pdiv[div->limbs_count() - 1] == 0)
                //     //     div->resize(div->limbs_count() - 1,
                //     div->limbs_count() - 1);
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
                rem = y - rem;
            }

            // remainder must be less than the divisor or our code has
            // failed
            NIL_CO3_MP_ASSERT(rem < y);
        }

        // Multiplication

        // These should be called only for creation of Montgomery and Barett
        // params, calculation of inverse element and montgomery_reduce. Since these functions
        // are relatively slow and are not called very often, we will not optimize them. We do
        // NOT care about the execution speed.

        // Caller is responsible for the result to fit in Bits bits, we will NOT throw!!!

        template<std::size_t Bits1, std::size_t Bits2, typename T>
        constexpr void multiply(big_uint<Bits1>& final_result, const big_uint<Bits2>& a,
                                const T& b_orig) noexcept {
            auto b = detail::as_big_uint(b_orig);
            big_uint<Bits1> result;
            std::size_t as = a.used_limbs();
            std::size_t bs = b.used_limbs();
            const_limb_pointer pa = a.limbs();
            const_limb_pointer pb = b.limbs();
            limb_pointer pr = result.limbs();
            for (std::size_t i = 0; i < result.limbs_count(); ++i) {
                pr[i] = 0;
            }

            double_limb_type carry = 0;
            for (std::size_t i = 0; i < as; ++i) {
                NIL_CO3_MP_ASSERT(result.limbs_count() > i);
                std::size_t inner_limit = (std::min)(result.limbs_count() - i, bs);
                std::size_t j = 0;
                for (; j < inner_limit; ++j) {
                    NIL_CO3_MP_ASSERT(i + j < result.limbs_count());
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
                    NIL_CO3_MP_ASSERT(result.limbs_count() > i + j);
                    if (i + j < result.limbs_count()) {
                        pr[i + j] = static_cast<limb_type>(carry);
                    }
                }
                carry = 0;
            }
            result.normalize();
            final_result = result;
        }
    }  // namespace detail
}  // namespace nil::crypto3::multiprecision
