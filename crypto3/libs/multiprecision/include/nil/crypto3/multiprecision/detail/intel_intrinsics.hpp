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

#include "nil/crypto3/multiprecision/detail/big_uint/storage.hpp"
#include "nil/crypto3/multiprecision/detail/config.hpp"
#include "nil/crypto3/multiprecision/detail/int128.hpp"

// nix will sometimes have immintrin.h even on non-x86 platforms
// so we additionally check for x86_64 or i386 (using the same checks as in immintrin.h)
#if __has_include(<immintrin.h>) && (defined(__x86_64__) || defined(__i386__))

#define NIL_CO3_MP_HAS_INTRINSICS

#include <immintrin.h>  // IWYU pragma: keep (this is a portable umbrella header for intrinsics)

namespace nil::crypto3::multiprecision::detail {

#if defined(NIL_CO3_MP_HAS_INT128)

    NIL_CO3_MP_FORCEINLINE unsigned char addcarry_limb(unsigned char carry, limb_type a,
                                                       limb_type b, limb_type* p_result) {
        using cast_type = unsigned long long;
        return _addcarry_u64(carry, a, b, reinterpret_cast<cast_type*>(p_result));
    }

    NIL_CO3_MP_FORCEINLINE unsigned char subborrow_limb(unsigned char carry, limb_type a,
                                                        limb_type b,
                                                        limb_type* p_result) {
        using cast_type = unsigned long long;
        return _subborrow_u64(carry, a, b, reinterpret_cast<cast_type*>(p_result));
    }

#else

    NIL_CO3_MP_FORCEINLINE unsigned char addcarry_limb(unsigned char carry, limb_type a,
                                                       limb_type b, limb_type* p_result) {
        using cast_type = unsigned int;
        return _addcarry_u32(carry, a, b, reinterpret_cast<cast_type*>(p_result));
    }

    NIL_CO3_MP_FORCEINLINE unsigned char subborrow_limb(unsigned char carry, limb_type a,
                                                        limb_type b,
                                                        limb_type* p_result) {
        using cast_type = unsigned int;
        return _subborrow_u32(carry, a, b, reinterpret_cast<cast_type*>(p_result));
    }

#endif
}  // namespace nil::crypto3::multiprecision::detail

#else
#warning "Missing immintrin.h, addcarry and subborrow optimizations disabled"

namespace nil::crypto3::multiprecision::detail {

    NIL_CO3_MP_FORCEINLINE unsigned char addcarry_limb(unsigned char carry, limb_type a,
                                                       limb_type b, limb_type* p_result) {
        limb_type r = a + b + carry;
        *p_result = r;
        return r < a || (r == a && carry);
    }

    NIL_CO3_MP_FORCEINLINE unsigned char subborrow_limb(unsigned char carry, limb_type a,
                                                        limb_type b,
                                                        limb_type* p_result) {
        limb_type r = a - b - carry;
        *p_result = r;
        return r > a || (r == a && carry);
    }
}  // namespace nil::crypto3::multiprecision::detail

#endif
