#pragma once

#include "nil/crypto3/multiprecision/detail/big_uint/storage.hpp"
#include "nil/crypto3/multiprecision/detail/config.hpp"
#include "nil/crypto3/multiprecision/detail/helper_macros.hpp"
#include "nil/crypto3/multiprecision/detail/int128.hpp"

#if __has_include(<immintrin.h>)
#define NIL_CO3_MP_HAS_IMMINTRIN_H
#endif

//
// If the compiler supports the intrinsics used by GCC internally
// inside <immintrin.h> then we'll use them directly.
// This is a bit of defensive programming, mostly for a modern clang
// sitting on top of an older GCC header install.
//
#if defined(__has_builtin)

#if __has_builtin(__builtin_ia32_addcarryx_u64)
#define NIL_CO3_MP_ADDC __builtin_ia32_addcarryx_u
#endif

#if __has_builtin(__builtin_ia32_subborrow_u64)
#define NIL_CO3_MP_SUBB __builtin_ia32_subborrow_u
#elif __has_builtin(__builtin_ia32_sbb_u64)
#define NIL_CO3_MP_SUBB __builtin_ia32_sbb_u
#endif

#endif

#ifndef NIL_CO3_MP_ADDC
#define NIL_CO3_MP_ADDC _addcarry_u
#endif
#ifndef NIL_CO3_MP_SUBB
#define NIL_CO3_MP_SUBB _subborrow_u
#endif

#ifdef NIL_CO3_MP_HAS_IMMINTRIN_H

#include <immintrin.h>  // IWYU pragma: keep

#if defined(NIL_CO3_MP_HAS_INT128)

namespace nil::crypto3::multiprecision::detail {

    NIL_CO3_MP_FORCEINLINE unsigned char addcarry_limb(unsigned char carry, limb_type a,
                                                       limb_type b, limb_type* p_result) {
        using cast_type = unsigned long long;

        return NIL_CO3_MP_JOIN(NIL_CO3_MP_ADDC, 64)(carry, a, b,
                                                    reinterpret_cast<cast_type*>(p_result));
    }

    NIL_CO3_MP_FORCEINLINE unsigned char subborrow_limb(unsigned char carry, limb_type a,
                                                        limb_type b, limb_type* p_result) {
        using cast_type = unsigned long long;

        return NIL_CO3_MP_JOIN(NIL_CO3_MP_SUBB, 64)(carry, a, b,
                                                    reinterpret_cast<cast_type*>(p_result));
    }

}  // namespace nil::crypto3::multiprecision::detail

#else

namespace nil::crypto3::multiprecision::detail {

    NIL_CO3_MP_FORCEINLINE unsigned char addcarry_limb(unsigned char carry, limb_type a,
                                                       limb_type b, limb_type* p_result) {
        return NIL_CO3_MP_JOIN(NIL_CO3_MP_ADDC, 32)(carry, a, b,
                                                    reinterpret_cast<unsigned int*>(p_result));
    }

    NIL_CO3_MP_FORCEINLINE unsigned char subborrow_limb(unsigned char carry, limb_type a,
                                                        limb_type b, limb_type* p_result) {
        return NIL_CO3_MP_JOIN(NIL_CO3_MP_SUBB, 32)(carry, a, b,
                                                    reinterpret_cast<unsigned int*>(p_result));
    }

}  // namespace nil::crypto3::multiprecision::detail

#endif

#endif
