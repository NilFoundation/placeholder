//---------------------------------------------------------------------------//
// Copyright (c) 2020 Madhur Chauhan
// Copyright (c) 2020 John Maddock
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <climits>
#include <cstdint>
#include <type_traits>
#include "nil/crypto3/multiprecision/detail/force_inline.hpp"
#include "nil/crypto3/multiprecision/detail/intel_intrinsics.hpp"

namespace nil::crypto3::multiprecision::detail {
    template<typename T, std::enable_if_t<std::is_unsigned_v<T>, int> = 0>
    constexpr std::uint8_t addcarry_constexpr(std::uint8_t carry, T a, T b, T* p_result) {
        T r = a + b + carry;
        *p_result = r;
        return r < a || (r == a && carry);
    }

    template<typename T, std::enable_if_t<std::is_unsigned_v<T>, int> = 0>
    constexpr std::uint8_t subborrow_constexpr(std::uint8_t borrow, T a, T b,
                                               T* p_result) {
        T r = a - b - borrow;
        *p_result = r;
        return r > a || (r == a && borrow);
    }
}  // namespace nil::crypto3::multiprecision::detail

#ifdef NIL_CO3_MP_HAS_INTRINSICS

namespace nil::crypto3::multiprecision::detail {
    static_assert(std::is_same_v<std::uint8_t, unsigned char>);

    template<typename T, std::enable_if_t<std::is_unsigned_v<T>, int> = 0>
    NIL_CO3_MP_FORCEINLINE constexpr std::uint8_t addcarry(std::uint8_t carry, T a, T b,
                                                           T* p_result) {
        if (!std::is_constant_evaluated()) {
            if constexpr (sizeof(T) * CHAR_BIT == 64) {
                return _addcarry_u64(carry, a, b,
                                     reinterpret_cast<unsigned long long*>(p_result));
            } else if constexpr (sizeof(T) * CHAR_BIT == 32) {
                return _addcarry_u32(carry, a, b,
                                     reinterpret_cast<unsigned int*>(p_result));
            } else {
                return addcarry_constexpr(carry, a, b, p_result);
            }
        }
        return addcarry_constexpr(carry, a, b, p_result);
    }

    template<typename T, std::enable_if_t<std::is_unsigned_v<T>, int> = 0>
    NIL_CO3_MP_FORCEINLINE constexpr std::uint8_t subborrow(std::uint8_t borrow, T a, T b,
                                                            T* p_result) {
        if (!std::is_constant_evaluated()) {
            if constexpr (sizeof(T) * CHAR_BIT == 64) {
                return _subborrow_u64(borrow, a, b,
                                      reinterpret_cast<unsigned long long*>(p_result));
            } else if constexpr (sizeof(T) * CHAR_BIT == 32) {
                return _subborrow_u32(borrow, a, b,
                                      reinterpret_cast<unsigned int*>(p_result));
            } else {
                return subborrow_constexpr(borrow, a, b, p_result);
            }
        }
        return subborrow_constexpr(borrow, a, b, p_result);
    }
}  // namespace nil::crypto3::multiprecision::detail

#else

#ifndef NIL_CO3_MP_DISABLE_INTRINSICS
//#warning "x86 intrinsics are not available, addcarry and subborrow optimizations disabled"
#endif

namespace nil::crypto3::multiprecision::detail {
    template<typename T, std::enable_if_t<std::is_unsigned_v<T>, int> = 0>
    NIL_CO3_MP_FORCEINLINE constexpr std::uint8_t addcarry(std::uint8_t carry, T a, T b,
                                                           T* p_result) {
        return addcarry_constexpr(carry, a, b, p_result);
    }

    template<typename T, std::enable_if_t<std::is_unsigned_v<T>, int> = 0>
    NIL_CO3_MP_FORCEINLINE constexpr std::uint8_t subborrow(std::uint8_t borrow, T a, T b,
                                                            T* p_result) {
        return subborrow_constexpr(borrow, a, b, p_result);
    }
}  // namespace nil::crypto3::multiprecision::detail

#endif
