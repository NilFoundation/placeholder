///////////////////////////////////////////////////////////////
//  Copyright 2012-2020 John Maddock.
//  Copyright 2020 Madhur Chauhan.
//  Distributed under the Boost Software License, Version 1.0.
//  (See accompanying file LICENSE_1_0.txt or copy at
//   https://www.boost.org/LICENSE_1_0.txt)
///////////////////////////////////////////////////////////////

#pragma once

// IWYU pragma: private; include "nil/crypto3/multiprecision/big_int/big_uint.hpp"

#include <bit>
#include <cstddef>
#include <stdexcept>

#include "nil/crypto3/multiprecision/big_int/big_uint_impl.hpp"
#include "nil/crypto3/multiprecision/big_int/detail/config.hpp"
#include "nil/crypto3/multiprecision/big_int/storage.hpp"

namespace nil::crypto3::multiprecision {
    template<std::size_t Bits>
    NIL_CO3_MP_FORCEINLINE constexpr bool is_zero(const big_uint<Bits> &val) noexcept {
        for (std::size_t i = 0; i < val.limbs_count(); ++i) {
            if (val.limbs()[i] != 0) {
                return false;
            }
        }
        return true;
    }

    template<std::size_t Bits>
    constexpr std::size_t lsb(const big_uint<Bits> &a) {
        //
        // Find the index of the least significant limb that is non-zero:
        //
        std::size_t index = 0;
        while ((index < a.limbs_count()) && !a.limbs()[index]) {
            ++index;
        }

        if (index == a.limbs_count()) {
            throw std::invalid_argument("zero has no lsb");
        }

        //
        // Find the index of the least significant bit within that limb:
        //
        std::size_t result = std::countr_zero(a.limbs()[index]);

        return result + index * big_uint<Bits>::limb_bits;
    }

    template<std::size_t Bits>
    constexpr std::size_t msb(const big_uint<Bits> &a) {
        //
        // Find the index of the most significant bit that is non-zero:
        //
        for (std::size_t i = a.limbs_count() - 1; i > 0; --i) {
            if (a.limbs()[i] != 0) {
                return i * big_uint<Bits>::limb_bits + std::bit_width(a.limbs()[i]) - 1;
            }
        }
        if (a.limbs()[0] == 0) {
            throw std::invalid_argument("zero has no msb");
        }
        return std::bit_width(a.limbs()[0]) - 1;
    }

    template<std::size_t Bits>
    constexpr bool bit_test(const big_uint<Bits> &val, std::size_t index) noexcept {
        using detail::limb_type;

        std::size_t offset = index / big_uint<Bits>::limb_bits;
        std::size_t shift = index % big_uint<Bits>::limb_bits;
        limb_type mask = limb_type(1u) << shift;
        if (offset >= val.limbs_count()) {
            return false;
        }
        return static_cast<bool>(val.limbs()[offset] & mask);
    }

    template<std::size_t Bits>
    constexpr void bit_set(big_uint<Bits> &val, std::size_t index) {
        using detail::limb_type;

        std::size_t offset = index / big_uint<Bits>::limb_bits;
        std::size_t shift = index % big_uint<Bits>::limb_bits;
        limb_type mask = limb_type(1u) << shift;
        if (offset >= val.limbs_count()) {
            return;  // fixed precision overflow
        }
        val.limbs()[offset] |= mask;
    }

    template<std::size_t Bits>
    constexpr void bit_unset(big_uint<Bits> &val, std::size_t index) noexcept {
        using detail::limb_type;

        std::size_t offset = index / big_uint<Bits>::limb_bits;
        std::size_t shift = index % big_uint<Bits>::limb_bits;
        limb_type mask = limb_type(1u) << shift;
        if (offset >= val.limbs_count()) {
            return;
        }
        val.limbs()[offset] &= ~mask;
        val.normalize();
    }

    template<std::size_t Bits>
    constexpr void bit_flip(big_uint<Bits> &val, std::size_t index) {
        using detail::limb_type;

        std::size_t offset = index / big_uint<Bits>::limb_bits;
        std::size_t shift = index % big_uint<Bits>::limb_bits;
        limb_type mask = limb_type(1u) << shift;
        if (offset >= val.limbs_count()) {
            return;  // fixed precision overflow
        }
        val.limbs()[offset] ^= mask;
        val.normalize();
    }
}  // namespace nil::crypto3::multiprecision