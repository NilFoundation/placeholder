//---------------------------------------------------------------------------//
// Copyright (c) 2024 Martun Karapetyan <martun@nil.foundation>
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE big_int_benchmark_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <cstddef>
#include <iostream>

#include <nil/crypto3/multiprecision/big_int/big_uint.hpp>
#include <nil/crypto3/multiprecision/big_int/literals.hpp>
#include <nil/crypto3/multiprecision/big_int/modular/big_mod.hpp>

#include <nil/crypto3/bench/benchmark.hpp>

using namespace nil::crypto3::multiprecision::literals;

constexpr std::size_t Bits = 256;
using standart_number = nil::crypto3::multiprecision::big_uint<Bits>;

constexpr standart_number modulus_odd = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_bigui256;
constexpr standart_number modulus_even = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e_bigui256;

using modular_number_ct_odd = nil::crypto3::multiprecision::montgomery_big_mod<modulus_odd>;
using modular_number_ct_even = nil::crypto3::multiprecision::big_mod<modulus_even>;
using modular_number_rt_montgomery = nil::crypto3::multiprecision::montgomery_big_mod_rt<Bits>;
using modular_number_rt = nil::crypto3::multiprecision::big_mod_rt<Bits>;

constexpr standart_number x = 0xb5d724ce6f44c3c587867bbcb417e9eb6fa05e7e2ef029166568f14eb3161387_bigui256;
constexpr modular_number_ct_odd x_mod_ct_odd = x;
constexpr modular_number_ct_even x_mod_ct_even = x;
constexpr modular_number_rt_montgomery x_mod_rt_odd{x, modulus_odd};
constexpr modular_number_rt x_mod_rt_even{x, modulus_even};

constexpr standart_number y = 0xad6e1fcc680392abfb075838eafa513811112f14c593e0efacb6e9d0d7770b4_bigui256;
constexpr modular_number_ct_odd y_mod_ct_odd = y;
constexpr modular_number_ct_even y_mod_ct_even = y;
constexpr modular_number_rt_montgomery y_mod_rt_odd{y, modulus_odd};
constexpr modular_number_rt y_mod_rt_even{y, modulus_even};

BOOST_AUTO_TEST_SUITE(runtime_odd_tests)

// This directly calls montgomery mul from modular_ops.hpp.
BOOST_AUTO_TEST_CASE(montgomery_mul_perf_test) {
    auto raw_base = x_mod_rt_odd.raw_base();
    auto mod_ops = x_mod_rt_odd.ops();

    nil::crypto3::bench::run_benchmark<>(
            "[odd modulus][runtime] montgomery mul (direct call)",
            [&]() {
                mod_ops.mul(raw_base, y_mod_rt_odd.raw_base());
                return raw_base;
            });

    std::cout << raw_base << std::endl;
}

BOOST_AUTO_TEST_CASE(big_mod_sub_perf_test) {
    auto x_modular = x_mod_rt_odd;

    nil::crypto3::bench::run_benchmark<>(
            "[odd modulus][runtime] big_mod_subtract",
            [&]() {
                x_modular -= y_mod_rt_odd;
                return x_modular;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x_modular << std::endl;
}

BOOST_AUTO_TEST_CASE(big_mod_add_perf_test) {
    auto x_modular = x_mod_rt_odd;

    nil::crypto3::bench::run_benchmark<>(
            "[odd modulus][runtime] big_mod_add",
            [&]() {
                x_modular += y_mod_rt_odd;
                return x_modular;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x_modular << std::endl;
}

BOOST_AUTO_TEST_CASE(big_mod_mul_perf_test) {
    auto x_modular = x_mod_rt_odd;

    nil::crypto3::bench::run_benchmark<>(
            "[odd modulus][runtime] big_mod_multiply",
            [&]() {
                x_modular *= y_mod_rt_odd;
                return x_modular;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x_modular << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(compile_time_odd_tests)

// This directly calls montgomery mul from modular_ops.hpp.
BOOST_AUTO_TEST_CASE(montgomery_mul_perf_test) {
    auto raw_base = x_mod_ct_odd.raw_base();
    auto mod_ops = x_mod_ct_odd.ops();

    nil::crypto3::bench::run_benchmark<>(
            "[odd modulus][compile time] montgomery mul (direct call)",
            [&]() {
                mod_ops.mul(raw_base, y_mod_ct_odd.raw_base());
                return raw_base;
            });

    std::cout << raw_base << std::endl;
}

BOOST_AUTO_TEST_CASE(big_mod_sub_perf_test) {
    auto x_modular = x_mod_ct_odd;

    nil::crypto3::bench::run_benchmark<>(
            "[odd modulus][compile time] big_mod_subtract",
            [&]() {
                x_modular -= y_mod_ct_odd;
                return x_modular;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x_modular << std::endl;
}

BOOST_AUTO_TEST_CASE(big_mod_add_perf_test) {
    auto x_modular = x_mod_ct_odd;

    nil::crypto3::bench::run_benchmark<>(
            "[odd modulus][compile time] big_mod_add",
            [&]() {
                x_modular += y_mod_ct_odd;
                return x_modular;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x_modular << std::endl;
}

BOOST_AUTO_TEST_CASE(big_mod_mul_perf_test) {
    auto x_modular = x_mod_ct_odd;

    nil::crypto3::bench::run_benchmark<>(
            "[odd modulus][compile time] big_mod_multiply",
            [&]() {
                x_modular *= y_mod_ct_odd;
                return x_modular;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x_modular << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(runtime_even_tests)

// This directly calls barrett mul from modular_ops.hpp.
BOOST_AUTO_TEST_CASE(barrett_mul_perf_test) {
    auto raw_base = x_mod_rt_even.raw_base();
    auto mod_ops = x_mod_rt_even.ops();

    nil::crypto3::bench::run_benchmark<>(
            "[even modulus][runtime] barrett mul (direct call)",
            [&]() {
                mod_ops.mul(raw_base, y_mod_rt_even.raw_base());
                return raw_base;
            });

    std::cout << raw_base << std::endl;
}

BOOST_AUTO_TEST_CASE(big_mod_sub_perf_test) {
    auto x_modular = x_mod_rt_even;

    nil::crypto3::bench::run_benchmark<>(
            "[even modulus][runtime] big_mod_subtract",
            [&]() {
                x_modular -= y_mod_rt_even;
                return x_modular;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x_modular << std::endl;
}

BOOST_AUTO_TEST_CASE(big_mod_add_perf_test) {
    auto x_modular = x_mod_rt_even;

    nil::crypto3::bench::run_benchmark<>(
            "[even modulus][runtime] big_mod_add",
            [&]() {
                x_modular += y_mod_rt_even;
                return x_modular;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x_modular << std::endl;
}

BOOST_AUTO_TEST_CASE(big_mod_mul_perf_test) {
    auto x_modular = x_mod_rt_even;

    nil::crypto3::bench::run_benchmark<>(
            "[even modulus][runtime] big_mod_multiply",
            [&]() {
                x_modular *= y_mod_rt_even;
                return x_modular;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x_modular << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(compile_time_even_tests)

// This directly calls mul from modular_ops.hpp.
BOOST_AUTO_TEST_CASE(barrett_mul_perf_test) {
    auto raw_base = x_mod_ct_even.raw_base();
    auto mod_ops = x_mod_ct_even.ops();

    nil::crypto3::bench::run_benchmark<>(
            "[even modulus][compile time] barrett mul (direct call)",
            [&]() {
                mod_ops.mul(raw_base, y_mod_ct_even.raw_base());
                return raw_base;
            });

    std::cout << raw_base << std::endl;
}

BOOST_AUTO_TEST_CASE(big_mod_sub_perf_test) {
    auto x_modular = x_mod_ct_even;

    nil::crypto3::bench::run_benchmark<>(
            "[even modulus][compile time] big_mod_subtract",
            [&]() {
                x_modular -= y_mod_ct_even;
                return x_modular;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x_modular << std::endl;
}

BOOST_AUTO_TEST_CASE(big_mod_add_perf_test) {
    auto x_modular = x_mod_ct_even;

    nil::crypto3::bench::run_benchmark<>(
            "[even modulus][compile time] big_mod_add",
            [&]() {
                x_modular += y_mod_ct_even;
                return x_modular;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x_modular << std::endl;
}

BOOST_AUTO_TEST_CASE(big_mod_mul_perf_test) {
    auto x_modular = x_mod_ct_even;

    nil::crypto3::bench::run_benchmark<>(
            "[even modulus][compile time] big_mod_multiply",
            [&]() {
                x_modular *= y_mod_ct_even;
                return x_modular;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x_modular << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()
