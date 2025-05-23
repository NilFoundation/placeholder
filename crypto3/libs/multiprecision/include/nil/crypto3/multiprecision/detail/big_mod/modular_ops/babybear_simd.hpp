//---------------------------------------------------------------------------//
// Copyright (c) 2025 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <array>
#include <bit>
#include <climits>
#include <cstdint>

#include <nil/crypto3/multiprecision/detail/big_mod/modular_ops/babybear.hpp>

#include <nil/crypto3/multiprecision/detail/intel_intrinsics.hpp>

namespace nil::crypto3::multiprecision::detail::babybear {
    using u32 = std::uint32_t;
    using u32x4 = std::array<u32, 4>;
    using u32x8 = std::array<u32, 8>;

#if defined(NIL_CO3_MP_HAS_INTRINSICS) && defined(__AVX2__)
    inline constexpr __m256i pack(u32 v) {
        return std::bit_cast<__m256i>(u32x8{v, v, v, v, v, v, v, v});
    }

    inline constexpr __m256i PACKED_P = pack(0x78000001);
    inline constexpr __m256i PACKED_MU = pack(0x88000001);

    inline __m256i partial_monty_red_unsigned_to_signed(__m256i input) {
        auto q = _mm256_mul_epu32(input, PACKED_MU);
        auto q_p = _mm256_mul_epu32(q, PACKED_P);

        return _mm256_sub_epi32(input, q_p);
    }

    inline __m256i partial_monty_red_signed_to_signed(__m256i input) {
        auto q = _mm256_mul_epi32(input, PACKED_MU);
        auto q_p = _mm256_mul_epi32(q, PACKED_P);

        return _mm256_sub_epi32(input, q_p);
    }

    inline __m256i monty_mul(__m256i lhs, __m256i rhs) {
        auto prod = _mm256_mul_epu32(lhs, rhs);
        return partial_monty_red_unsigned_to_signed(prod);
    }

    inline __m256i monty_mul_signed(__m256i lhs, __m256i rhs) {
        auto prod = _mm256_mul_epi32(lhs, rhs);
        return partial_monty_red_signed_to_signed(prod);
    }

    inline __m256i movehdup_epi32(__m256i x) {
        return _mm256_castps_si256(_mm256_movehdup_ps(_mm256_castsi256_ps(x)));
    }

    inline __m256i babybear_mul8_avx2(__m256i lhs, __m256i rhs) {
        auto lhs_evn = lhs;
        auto rhs_evn = rhs;
        auto lhs_odd = movehdup_epi32(lhs);
        auto rhs_odd = movehdup_epi32(rhs);

        auto d_evn = monty_mul(lhs_evn, rhs_evn);
        auto d_odd = monty_mul(lhs_odd, rhs_odd);

        auto d_evn_hi = movehdup_epi32(d_evn);
        auto t = _mm256_blend_epi32(d_evn_hi, d_odd, 0b10101010);

        auto u = _mm256_add_epi32(t, PACKED_P);
        return _mm256_min_epu32(t, u);
    }

    inline __m256i babybear_add8_avx2(__m256i lhs, __m256i rhs) {
        auto t = _mm256_add_epi32(lhs, rhs);
        auto u = _mm256_sub_epi32(t, PACKED_P);
        return _mm256_min_epu32(t, u);
    }
#endif

    inline constexpr const auto& babybear_ops() {
        return babybear_modular_ops_storage::ops();
    }

    constexpr inline u32x8 babybear_mul8_impl(u32x8 a, u32x8 b) {
#if defined(NIL_CO3_MP_HAS_INTRINSICS) && defined(__AVX2__)
        if (!std::is_constant_evaluated()) {
            return std::bit_cast<u32x8>(
                babybear_mul8_avx2(std::bit_cast<__m256i>(a), std::bit_cast<__m256i>(b)));
        }
#endif
        u32x8 result;
        for (u32 i = 0; i < 8; ++i) {
            result[i] = a[i];
            babybear_ops().mul(result[i], b[i]);
        }
        return result;
    }

    constexpr inline u32x8 babybear_add8_impl(u32x8 a, u32x8 b) {
#if defined(NIL_CO3_MP_HAS_INTRINSICS) && defined(__AVX2__)
        if (!std::is_constant_evaluated()) {
            return std::bit_cast<u32x8>(
                babybear_add8_avx2(std::bit_cast<__m256i>(a), std::bit_cast<__m256i>(b)));
        }
#endif
        u32x8 result;
        for (u32 i = 0; i < 8; ++i) {
            result[i] = a[i];
            babybear_ops().add(result[i], b[i]);
        }
        return result;
    }

    template<typename T>
    constexpr inline std::array<T, 8> babybear_mul8(std::array<T, 8> a, std::array<T, 8> b) {
        static_assert(sizeof(T) == 4);
        return std::bit_cast<std::array<T, 8>>(babybear_mul8_impl(
            std::bit_cast<u32x8>(a), std::bit_cast<u32x8>(b)));
    }

    template<typename T>
    constexpr inline std::array<T, 8> babybear_add8(std::array<T, 8> a, std::array<T, 8> b) {
        static_assert(sizeof(T) == 4);
        return std::bit_cast<std::array<T, 8>>(babybear_add8_impl(
            std::bit_cast<u32x8>(a), std::bit_cast<u32x8>(b)));
    }

    constexpr inline u32x8 av_x_b1_av_x_b2(u32x4 av, u32 b1, u32 b2) {
        return babybear_mul8_impl({av[0], av[1], av[2], av[3], av[0], av[1], av[2], av[3]},
                             {b1, b1, b1, b1, b2, b2, b2, b2});
    }

    constexpr inline u32x4 babybear_fp4_vec_mul_impl(u32x4 a, u32x4 b) {
        constexpr u32 nonres = babybear_ops().to_montgomery(11);
        auto m01 = av_x_b1_av_x_b2(a, b[0], b[1]);
        u32x8 r{0};
        for (u32 i = 0; i < 4; ++i) {
            babybear_ops().add(r[i], m01[i]);
            babybear_ops().add(r[i + 1], m01[i + 4]);
        }
        auto m23 = av_x_b1_av_x_b2(a, b[2], b[3]);
        for (u32 i = 0; i < 4; ++i) {
            babybear_ops().add(r[i + 2], m23[i]);
            babybear_ops().add(r[i + 3], m23[i + 4]);
        }
        for (u32 i = 0; i < 3; ++i) {
            babybear_ops().mul(r[4 + i], nonres);
            babybear_ops().add(r[i], r[4 + i]);
        }
        return {r[0], r[1], r[2], r[3]};
    }

    template<typename T>
    constexpr std::array<T, 4> babybear_fp4_vec_mul(std::array<T, 4> a, std::array<T, 4> b) {
        static_assert(sizeof(T) == 4);
        return std::bit_cast<std::array<T, 4>>(
            babybear_fp4_vec_mul_impl(std::bit_cast<u32x4>(a), std::bit_cast<u32x4>(b)));
    }
}  // namespace nil::crypto3::multiprecision::detail
