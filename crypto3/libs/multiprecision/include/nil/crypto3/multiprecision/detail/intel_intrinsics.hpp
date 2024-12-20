#pragma once

#include "nil/crypto3/multiprecision/detail/big_uint/storage.hpp"
#include "nil/crypto3/multiprecision/detail/config.hpp"
#include "nil/crypto3/multiprecision/detail/helper_macros.hpp"
#include "nil/crypto3/multiprecision/detail/int128.hpp"

#if __has_include(<immintrin.h>)

#define NIL_CO3_MP_HAS_IMMINTRIN_H

#include <immintrin.h>  // IWYU pragma: keep

#if defined(NIL_CO3_MP_HAS_INT128)

namespace nil::crypto3::multiprecision::detail {

    NIL_CO3_MP_FORCEINLINE unsigned char addcarry_limb(unsigned char carry, limb_type a,
                                                       limb_type b, limb_type* p_result) {
        using cast_type = unsigned long long;

        return NIL_CO3_MP_JOIN(_addcarry_u, 64)(carry, a, b,
                                                    reinterpret_cast<cast_type*>(p_result));
    }

    NIL_CO3_MP_FORCEINLINE unsigned char subborrow_limb(unsigned char carry, limb_type a,
                                                        limb_type b, limb_type* p_result) {
        using cast_type = unsigned long long;

        return NIL_CO3_MP_JOIN(_subborrow_u, 64)(carry, a, b,
                                                    reinterpret_cast<cast_type*>(p_result));
    }

}  // namespace nil::crypto3::multiprecision::detail

#else

namespace nil::crypto3::multiprecision::detail {

    NIL_CO3_MP_FORCEINLINE unsigned char addcarry_limb(unsigned char carry, limb_type a,
                                                       limb_type b, limb_type* p_result) {
        return NIL_CO3_MP_JOIN(_addcarry_u, 32)(carry, a, b,
                                                    reinterpret_cast<unsigned int*>(p_result));
    }

    NIL_CO3_MP_FORCEINLINE unsigned char subborrow_limb(unsigned char carry, limb_type a,
                                                        limb_type b, limb_type* p_result) {
        return NIL_CO3_MP_JOIN(_subborrow_u, 32)(carry, a, b,
                                                    reinterpret_cast<unsigned int*>(p_result));
    }

}  // namespace nil::crypto3::multiprecision::detail

#endif

#endif
