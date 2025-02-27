//---------------------------------------------------------------------------//
// Copyright (c) 2024 Martun Karapetyan <martun@nil.foundation>
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
// Copyright (c) 2024-2025 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE big_mod_benchmark

#include <nil/crypto3/bench/benchmark.hpp>

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <tuple>

#include <nil/crypto3/multiprecision/big_mod.hpp>
#include <nil/crypto3/multiprecision/big_uint.hpp>
#include <nil/crypto3/multiprecision/inverse.hpp>
#include <nil/crypto3/multiprecision/literals.hpp>

#include <nil/crypto3/multiprecision/detail/big_mod/test_support.hpp>

using namespace nil::crypto3::multiprecision;
using namespace nil::crypto3::bench;
using nil::crypto3::multiprecision::detail::get_raw_base;
using nil::crypto3::multiprecision::detail::pow_unsigned;

constexpr auto modulus_256 =
    0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_big_uint256;
constexpr auto x_256 =
    0xb5d724ce6f44c3c587867bbcb417e9eb6fa05e7e2ef029166568f14eb3161387_big_uint256;
constexpr auto y_256 =
    0xad6e1fcc680392abfb075838eafa513811112f14c593e0efacb6e9d0d7770b4_big_uint256;

struct MontgomeryCompileTimeCase {
    using big_mod_t = montgomery_big_mod<modulus_256>;
    static constexpr big_mod_t x{x_256};
    static constexpr big_mod_t y{y_256};
    static constexpr auto name = "[montgomery][compile-time]";
};

struct MontgomeryRuntimeCase {
    using big_mod_t = montgomery_big_mod_rt<256>;
    static constexpr big_mod_t x{x_256, modulus_256};
    static constexpr big_mod_t y{y_256, modulus_256};
    static constexpr auto name = "[montgomery][     runtime]";
};

struct BarrettCompileTimeCase {
    using big_mod_t = big_mod<modulus_256>;
    static constexpr big_mod_t x{x_256};
    static constexpr big_mod_t y{y_256};
    static constexpr auto name = "[   barrett][compile-time]";
};

struct BarrettRuntimeCase {
    using big_mod_t = big_mod_rt<256>;
    static constexpr big_mod_t x{x_256, modulus_256};
    static constexpr big_mod_t y{y_256, modulus_256};
    static constexpr auto name = "[   barrett][     runtime]";
};

constexpr std::uint64_t x_64 = 0xbf02e7bacaf6f977ULL;
constexpr std::uint64_t y_64 = 0x95ac1bce79f93335ULL;
constexpr big_uint<64> goldilocks_modulus_big_uint = goldilocks_modulus;

struct GoldilocksMontgomery {
    using big_mod_t = montgomery_big_mod<goldilocks_modulus_big_uint>;
    static constexpr big_mod_t x{x_64};
    static constexpr big_mod_t y{y_64};
    static constexpr auto name = "[montgomery][  goldilocks]";
};

struct GoldilocksBarrett {
    using big_mod_t = big_mod<goldilocks_modulus_big_uint>;
    static constexpr big_mod_t x{x_64};
    static constexpr big_mod_t y{y_64};
    static constexpr auto name = "[   barrett][  goldilocks]";
};

struct GoldilocksCustom {
    using big_mod_t = goldilocks_mod;
    static constexpr big_mod_t x{x_64};
    static constexpr big_mod_t y{y_64};
    static constexpr auto name = "[    custom][  goldilocks]";
};

constexpr std::uint64_t x_31 = 0xaf6f977ULL;
constexpr std::uint64_t y_31 = 0x9f93335ULL;
constexpr big_uint<31> babybear_modulus_big_uint = 0x78000001_big_uint31;

struct BabyBearMontgomery {
    using big_mod_t = montgomery_big_mod<babybear_modulus_big_uint>;
    static constexpr big_mod_t x{x_31};
    static constexpr big_mod_t y{y_31};
    static constexpr auto name = "[montgomery][    babybear]";
};

struct BabyBearBarrett {
    using big_mod_t = big_mod<babybear_modulus_big_uint>;
    static constexpr big_mod_t x{x_31};
    static constexpr big_mod_t y{y_31};
    static constexpr auto name = "[   barrett][    babybear]";
};

struct BabyBearCustom {
    using big_mod_t = babybear_mod;
    static constexpr big_mod_t x{x_31};
    static constexpr big_mod_t y{y_31};
    static constexpr auto name = "[    custom][    babybear]";
};

constexpr big_uint<31> mersenne31_modulus_big_uint = 0x7fffffff_big_uint31;

struct Mersenne31Montgomery {
    using big_mod_t = montgomery_big_mod<mersenne31_modulus_big_uint>;
    static constexpr big_mod_t x{x_31};
    static constexpr big_mod_t y{y_31};
    static constexpr auto name = "[montgomery][  mersenne31]";
};

struct Mersenne31Barrett {
    using big_mod_t = big_mod<mersenne31_modulus_big_uint>;
    static constexpr big_mod_t x{x_31};
    static constexpr big_mod_t y{y_31};
    static constexpr auto name = "[   barrett][  mersenne31]";
};

struct Mersenne31Custom {
    using big_mod_t = mersenne31_mod;
    static constexpr big_mod_t x{x_31};
    static constexpr big_mod_t y{y_31};
    static constexpr auto name = "[    custom][  mersenne31]";
};

using cases =
    std::tuple<MontgomeryCompileTimeCase, MontgomeryRuntimeCase, BarrettCompileTimeCase,
               BarrettRuntimeCase, GoldilocksMontgomery, GoldilocksBarrett,
               GoldilocksCustom, BabyBearMontgomery, BabyBearBarrett, BabyBearCustom,
               Mersenne31Montgomery, Mersenne31Barrett, Mersenne31Custom>;

BOOST_AUTO_TEST_CASE_TEMPLATE(direct_mul_perf, Case, cases) {
    auto x_raw_base = get_raw_base(Case::x);
    const auto y_raw_base = get_raw_base(Case::y);
    const auto &ops = Case::x.ops_storage().ops();
    run_benchmark<>(std::string(Case::name) + " direct mul", [&]() {
        ops.mul(x_raw_base, y_raw_base);
        return x_raw_base;
    });
}

BOOST_AUTO_TEST_CASE_TEMPLATE(mul_perf, Case, cases) {
    auto x = Case::x;
    run_benchmark<>(std::string(Case::name) + "        mul", [&]() {
        x *= Case::y;
        return x;
    });
}

BOOST_AUTO_TEST_CASE_TEMPLATE(add_perf, Case, cases) {
    auto x = Case::x;
    run_benchmark<>(std::string(Case::name) + "        add", [&]() {
        x += Case::y;
        return x;
    });
}

BOOST_AUTO_TEST_CASE_TEMPLATE(sub_perf, Case, cases) {
    auto x = Case::x;
    run_benchmark<>(std::string(Case::name) + "        sub", [&]() {
        x -= Case::y;
        return x;
    });
}

BOOST_AUTO_TEST_CASE_TEMPLATE(inverse_perf, Case, cases) {
    auto x = Case::x;
    run_benchmark<>(std::string(Case::name) + "    inverse", [&]() {
        x = inverse(x);
        ++x;
        return x;
    });
}

BOOST_AUTO_TEST_CASE_TEMPLATE(pow_perf, Case, cases) {
    auto x_raw_base = get_raw_base(Case::x);
    const auto &ops = Case::x.ops_storage().ops();
    run_benchmark<>(std::string(Case::name) + " direct pow", [&]() {
        pow_unsigned(x_raw_base, x_raw_base, 0xf309d588016520ddULL, ops);
        return x_raw_base;
    });
}
