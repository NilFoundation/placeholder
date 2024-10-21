///////////////////////////////////////////////////////////////
//  Copyright 2012 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt
//
// Comparison operators for big_integer:
//
#pragma once

// #include <boost/multiprecision/detail/constexpr.hpp>
#include <type_traits>

#include "nil/crypto3/multiprecision/big_integer/basic_ops/add_unsigned.hpp"
#include "nil/crypto3/multiprecision/big_integer/big_integer_impl.hpp"
#include "nil/crypto3/multiprecision/big_integer/detail/config.hpp"
#include "nil/crypto3/multiprecision/big_integer/storage.hpp"

namespace nil::crypto3::multiprecision::detail {

    template<unsigned Bits>
    inline constexpr void add_unsigned(big_integer<Bits>& result, const big_integer<Bits>& a,
                                       const limb_type& o) noexcept {
        // Addition using modular arithmetic.
        // Nothing fancy, just let uintmax_t take the strain:

        double_limb_type carry = o;
        typename big_integer<Bits>::limb_pointer pr = result.limbs();
        typename big_integer<Bits>::const_limb_pointer pa = a.limbs();
        unsigned i = 0;
        // Addition with carry until we either run out of digits or carry is zero:
        for (; carry && (i < result.size()); ++i) {
            carry += static_cast<double_limb_type>(pa[i]);
            pr[i] = static_cast<limb_type>(carry);
            carry >>= big_integer<Bits>::limb_bits;
        }
        // Just copy any remaining digits:
        if (&a != &result) {
            boost::multiprecision::std_constexpr::copy(pa + i, pa + a.size(), pr + i);
        }
        if (Bits % big_integer<Bits>::limb_bits == 0) {
            result.set_carry(carry);
        } else {
            limb_type mask = big_integer<Bits>::upper_limb_mask;
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
    template<unsigned Bits>
    inline constexpr void subtract_unsigned(big_integer<Bits>& result, const big_integer<Bits>& a,
                                            const limb_type& b) noexcept {
        BOOST_ASSERT(a >= b);

        // Subtract one limb.
        // Nothing fancy, just let uintmax_t take the strain:
        constexpr double_limb_type borrow =
            static_cast<double_limb_type>(big_integer<Bits>::max_limb_value) + 1;
        typename big_integer<Bits>::limb_pointer pr = result.limbs();
        typename big_integer<Bits>::const_limb_pointer pa = a.limbs();
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
                pr[i] = big_integer<Bits>::max_limb_value;
                ++i;
            }
            pr[i] = pa[i] - 1;
            if (&result != &a) {
                ++i;
                boost::multiprecision::std_constexpr::copy(pa + i, pa + a.size(), pr + i);
            }
        }
    }

    //
    // Now the actual functions called by the front end, all of which forward to one of the
    // above:
    //
    template<unsigned Bits>
    NIL_CO3_MP_FORCEINLINE constexpr void add(big_integer<Bits>& result, const big_integer<Bits>& a,
                                              const big_integer<Bits>& b) noexcept {
        add_unsigned(result, a, b);
    }
    template<unsigned Bits>
    NIL_CO3_MP_FORCEINLINE constexpr void add(big_integer<Bits>& result,
                                              const big_integer<Bits>& o) noexcept {
        add(result, result, o);
    }

    template<unsigned Bits>
    NIL_CO3_MP_FORCEINLINE constexpr void add(big_integer<Bits>& result,
                                              const limb_type& o) noexcept {
        add_unsigned(result, result, o);
    }
    template<unsigned Bits>
    NIL_CO3_MP_FORCEINLINE constexpr void add(big_integer<Bits>& result, const big_integer<Bits>& a,
                                              const limb_type& o) noexcept {
        add_unsigned(result, a, o);
    }
    template<unsigned Bits>
    NIL_CO3_MP_FORCEINLINE constexpr void subtract(big_integer<Bits>& result,
                                                   const limb_type& o) noexcept {
        subtract_unsigned(result, result, o);
    }
    template<unsigned Bits>
    NIL_CO3_MP_FORCEINLINE constexpr void subtract(big_integer<Bits>& result,
                                                   const big_integer<Bits>& a,
                                                   const limb_type& o) noexcept {
        subtract_unsigned(result, a, o);
    }

    template<unsigned Bits>
    NIL_CO3_MP_FORCEINLINE constexpr void increment(big_integer<Bits>& result) noexcept {
        if ((result.limbs()[0] < big_integer<Bits>::max_limb_value)) {
            ++result.limbs()[0];
        } else {
            add(result, static_cast<limb_type>(1u));
        }
    }

    template<unsigned Bits>
    NIL_CO3_MP_FORCEINLINE constexpr void decrement(big_integer<Bits>& result) noexcept {
        if (result.limbs()[0]) {
            --result.limbs()[0];
        } else {
            subtract(result, static_cast<limb_type>(1u));
        }
    }

    template<unsigned Bits>
    NIL_CO3_MP_FORCEINLINE constexpr void subtract(big_integer<Bits>& result,
                                                   const big_integer<Bits>& a,
                                                   const big_integer<Bits>& b) noexcept {
        subtract_unsigned(result, a, b);
    }
    template<unsigned Bits>
    NIL_CO3_MP_FORCEINLINE constexpr void subtract(big_integer<Bits>& result,
                                                   const big_integer<Bits>& o) noexcept {
        subtract(result, result, o);
    }

    template<unsigned Bits1, unsigned Bits2>
    NIL_CO3_MP_FORCEINLINE constexpr typename std::enable_if<(Bits1 >= Bits2)>::type subtract(
        big_integer<Bits1>& result, const big_integer<Bits2>& o) noexcept {
        big_integer<Bits1> o_larger = o;
        subtract(result, result, o_larger);
    }

    template<unsigned Bits1, unsigned Bits2>
    NIL_CO3_MP_FORCEINLINE constexpr typename std::enable_if<(Bits1 >= Bits2)>::type subtract(
        big_integer<Bits1>& result, const big_integer<Bits1>& a,
        const big_integer<Bits2>& b) noexcept {
        big_integer<Bits1> b_larger = b;
        subtract_unsigned(result, a, b_larger);
    }
}  // namespace nil::crypto3::multiprecision::detail
