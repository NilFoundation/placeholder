//---------------------------------------------------------------------------//
// Copyright (c) 2024 Martun Karapetyan <martun@nil.foundation>
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
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

using cases = std::tuple<MontgomeryCompileTimeCase, MontgomeryRuntimeCase,
                         BarrettCompileTimeCase, BarrettRuntimeCase, GoldilocksMontgomery,
                         GoldilocksBarrett, GoldilocksCustom>;

BOOST_AUTO_TEST_CASE_TEMPLATE(direct_mul_perf, Case, cases) {
    auto raw_base = detail::get_raw_base(Case::x);
    const auto &mod_ops = Case::x.ops_storage().ops();
    run_benchmark<>(std::string(Case::name) + " direct mul", [&]() {
        mod_ops.mul(raw_base, detail::get_raw_base(Case::y));
        return raw_base;
    });
}

BOOST_AUTO_TEST_CASE_TEMPLATE(mul_perf, Case, cases) {
    auto x_modular = Case::x;
    run_benchmark<>(std::string(Case::name) + "        mul", [&]() {
        x_modular *= Case::y;
        return x_modular;
    });
}

BOOST_AUTO_TEST_CASE_TEMPLATE(add_perf, Case, cases) {
    auto x_modular = Case::x;
    run_benchmark<>(std::string(Case::name) + "        add", [&]() {
        x_modular += Case::y;
        return x_modular;
    });
}

BOOST_AUTO_TEST_CASE_TEMPLATE(sub_perf, Case, cases) {
    auto x_modular = Case::x;
    run_benchmark<>(std::string(Case::name) + "        sub", [&]() {
        x_modular -= Case::y;
        return x_modular;
    });
}

BOOST_AUTO_TEST_CASE_TEMPLATE(inverse_perf, Case, cases) {
    auto x_modular = Case::x;
    run_benchmark<>(std::string(Case::name) + "    inverse", [&]() {
        x_modular = inverse(x_modular);
        ++x_modular;
        return x_modular;
    });
}

BOOST_AUTO_TEST_CASE_TEMPLATE(pow_perf, Case, cases) {
    auto raw_base = detail::get_raw_base(Case::x);
    const auto &mod_ops = Case::x.ops_storage().ops();
    run_benchmark<>(std::string(Case::name) + " direct pow", [&]() {
        detail::pow_unsigned(raw_base, raw_base, 0xf309d588016520ddULL, mod_ops);
        return raw_base;
    });
}
