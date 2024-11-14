#pragma once

#include "nil/crypto3/multiprecision/big_int/detail/config.hpp"
#include "nil/crypto3/multiprecision/big_int/storage.hpp"

#if __has_include(<immintrin.h>)
#include <immintrin.h>  // IWYU pragma: keep
#define NIL_CO3_MP_HAS_IMMINTRIN_H
#endif

#ifdef NIL_CO3_MP_HAS_IMMINTRIN_H

namespace nil::crypto3::multiprecision::detail {

    NIL_CO3_MP_FORCEINLINE unsigned char addcarry_limb(unsigned char carry, limb_type a,
                                                       limb_type b, limb_type* p_result) {
        return _addcarry_u32(carry, a, b, reinterpret_cast<unsigned int*>(p_result));
    }

    NIL_CO3_MP_FORCEINLINE unsigned char subborrow_limb(unsigned char carry, limb_type a,
                                                        limb_type b, limb_type* p_result) {
        return _subborrow_u32(carry, a, b, reinterpret_cast<unsigned int*>(p_result));
    }

}  // namespace nil::crypto3::multiprecision::detail

#endif
