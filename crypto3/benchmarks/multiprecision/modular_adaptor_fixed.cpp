//---------------------------------------------------------------------------//
// Copyright (c) 2024 Martun Karapetyan <martun@nil.foundation>
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#include "nil/crypto3/multiprecision/boost_backends/modular/modular_params.hpp"
#define BOOST_TEST_MODULE modular_fixed_multiprecision_test

#define TEST_CPP_INT

// Suddenly, BOOST_MP_ASSERT is NOT constexpr, and it is used in constexpr
// functions throughout the boost, resulting to compilation errors on all
// compilers in debug mode. We need to switch assertions off inside cpp_int
// to make this code compile in debug mode. So we use this workaround to
// turn off file 'boost/multiprecision/detail/assert.hpp' which contains
// definition of BOOST_MP_ASSERT and BOOST_MP_ASSERT_MSG.
#ifndef BOOST_MP_DETAIL_ASSERT_HPP
    #define BOOST_MP_DETAIL_ASSERT_HPP
    #define BOOST_MP_ASSERT(expr) ((void)0)
    #define BOOST_MP_ASSERT_MSG(expr, msg) ((void)0)
#endif

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <iostream>

#include <nil/crypto3/multiprecision/boost_backends/cpp_int_modular.hpp>
#include <nil/crypto3/multiprecision/boost_backends/cpp_int_modular/literals.hpp>
#include <nil/crypto3/multiprecision/boost_backends/cpp_modular.hpp>

#include <nil/crypto3/multiprecision/boost_backends/modular/modular_adaptor.hpp>
#include <nil/crypto3/multiprecision/boost_backends/modular/modular_params_fixed.hpp>

#include <nil/crypto3/multiprecision/boost_backends/inverse.hpp>

#include <nil/crypto3/bench/benchmark.hpp>

using namespace boost::multiprecision;

using boost::multiprecision::backends::cpp_int_modular_backend;
using boost::multiprecision::backends::modular_adaptor;
using boost::multiprecision::backends::modular_params_ct;
using boost::multiprecision::backends::modular_params_rt;

using Backend = cpp_int_modular_backend<256>;
using standart_number = boost::multiprecision::number<Backend>;

constexpr standart_number modulus_odd = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_cppui_modular256;
constexpr standart_number modulus_even = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e_cppui_modular256;
constexpr backends::modular_params<Backend> params_odd{modulus_odd.backend()};
constexpr backends::modular_params<Backend> params_even{modulus_even.backend()};

using params_ct_odd = modular_params_ct<Backend, params_odd>;
using params_ct_even = modular_params_ct<Backend, params_even>;
using params_rt = modular_params_rt<Backend>;

using modular_backend_ct_odd = modular_adaptor<Backend, params_ct_odd>;
using modular_backend_ct_even = modular_adaptor<Backend, params_ct_even>;
using modular_backend_rt = modular_adaptor<Backend, params_rt>;

using modular_number_ct_odd = boost::multiprecision::number<modular_backend_ct_odd>;
using modular_number_ct_even = boost::multiprecision::number<modular_backend_ct_even>;
using modular_number_rt = boost::multiprecision::number<modular_backend_rt>;

constexpr standart_number x = 0xb5d724ce6f44c3c587867bbcb417e9eb6fa05e7e2ef029166568f14eb3161387_cppui_modular256;
constexpr modular_number_ct_odd x_mod_ct_odd = modular_backend_ct_odd(x.backend());
constexpr modular_number_ct_even x_mod_ct_even = modular_backend_ct_even(x.backend());
constexpr modular_number_rt x_mod_rt_odd = modular_backend_rt(x.backend(), modulus_odd.backend());
constexpr modular_number_rt x_mod_rt_even = modular_backend_rt(x.backend(), modulus_even.backend());

constexpr standart_number y = 0xad6e1fcc680392abfb075838eafa513811112f14c593e0efacb6e9d0d7770b4_cppui_modular256;
constexpr modular_number_ct_odd y_mod_ct_odd = modular_backend_ct_odd(y.backend());
constexpr modular_number_ct_even y_mod_ct_even = modular_backend_ct_even(y.backend());
constexpr modular_number_rt y_mod_rt_odd = modular_backend_rt(y.backend(), modulus_odd.backend());
constexpr modular_number_rt y_mod_rt_even = modular_backend_rt(y.backend(), modulus_even.backend());

BOOST_AUTO_TEST_SUITE(runtime_odd_tests)

// This directly calls montgomery_mul from modular_functions_fixed.hpp.
BOOST_AUTO_TEST_CASE(montgomery_mul_perf_test) {
    auto base_data = x_mod_rt_odd.backend().base_data();
    const auto &mod_object = x_mod_rt_odd.backend().mod_data().get_mod_obj();

    nil::crypto3::bench::run_benchmark<>(
            "[odd modulus][runtime] montgomery_mul (direct call)",
            [&]() {
                mod_object.montgomery_mul(base_data, y_mod_rt_odd.backend().base_data(),
                    std::integral_constant<bool, boost::multiprecision::backends::is_trivial_cpp_int_modular<Backend>::value>());
                return base_data;
            });

    std::cout << base_data << std::endl;
}

BOOST_AUTO_TEST_CASE(modular_adaptor_backend_sub_perf_test) {
    using namespace boost::multiprecision::default_ops;

    auto x_modular = x_mod_rt_odd.backend();

    nil::crypto3::bench::run_benchmark<>(
            "[odd modulus][runtime] modular_adaptor_backend_subtract",
            [&]() {
                eval_subtract(x_modular, y_mod_rt_odd.backend());
                return x_modular;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x_modular << std::endl;
}

BOOST_AUTO_TEST_CASE(modular_adaptor_backend_add_perf_test) {
    using namespace boost::multiprecision::default_ops;

    auto x_modular = x_mod_rt_odd.backend();

    nil::crypto3::bench::run_benchmark<>(
            "[odd modulus][runtime] modular_adaptor_backend_add",
            [&]() {
                eval_add(x_modular, y_mod_rt_odd.backend());
                return x_modular;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x_modular << std::endl;
}

BOOST_AUTO_TEST_CASE(modular_adaptor_backend_mul_perf_test) {
    auto x_modular = x_mod_rt_odd.backend();

    nil::crypto3::bench::run_benchmark<>(
            "[odd modulus][runtime] modular_adaptor_backend_multiply",
            [&]() {
                eval_multiply(x_modular, y_mod_rt_odd.backend());
                return x_modular;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x_modular << std::endl;
}

BOOST_AUTO_TEST_CASE(modular_adaptor_number_mul_perf_test) {
    auto x = x_mod_rt_odd;

    nil::crypto3::bench::run_benchmark<>(
            "[odd modulus][runtime] modular_adaptor_number_multiply",
            [&]() {
                x *= y_mod_rt_odd;
                return x;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(compile_time_odd_tests)

// This directly calls montgomery_mul from modular_functions_fixed.hpp.
BOOST_AUTO_TEST_CASE(montgomery_mul_perf_test) {
    auto base_data = x_mod_ct_odd.backend().base_data();
    const auto &mod_object = x_mod_ct_odd.backend().mod_data().get_mod_obj();

    nil::crypto3::bench::run_benchmark<>(
            "[odd modulus][compile time] montgomery_mul (direct call)",
            [&]() {
                mod_object.montgomery_mul(base_data, y_mod_ct_odd.backend().base_data(),
                    std::integral_constant<bool, boost::multiprecision::backends::is_trivial_cpp_int_modular<Backend>::value>());
                return base_data;
            });

    std::cout << base_data << std::endl;
}

BOOST_AUTO_TEST_CASE(modular_adaptor_backend_sub_perf_test) {
    using namespace boost::multiprecision::default_ops;

    auto x_modular = x_mod_ct_odd.backend();

    nil::crypto3::bench::run_benchmark<>(
            "[odd modulus][compile time] modular_adaptor_backend_subtract",
            [&]() {
                eval_subtract(x_modular, y_mod_ct_odd.backend());
                return x_modular;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x_modular << std::endl;
}

BOOST_AUTO_TEST_CASE(modular_adaptor_backend_add_perf_test) {
    using namespace boost::multiprecision::default_ops;

    auto x_modular = x_mod_ct_odd.backend();

    nil::crypto3::bench::run_benchmark<>(
            "[odd modulus][compile time] modular_adaptor_backend_add",
            [&]() {
                eval_add(x_modular, y_mod_ct_odd.backend());
                return x_modular;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x_modular << std::endl;
}

BOOST_AUTO_TEST_CASE(modular_adaptor_backend_mul_perf_test) {
    auto x_modular = x_mod_ct_odd.backend();

    nil::crypto3::bench::run_benchmark<>(
            "[odd modulus][compile time] modular_adaptor_backend_multiply",
            [&]() {
                eval_multiply(x_modular, y_mod_ct_odd.backend());
                return x_modular;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x_modular << std::endl;
}

BOOST_AUTO_TEST_CASE(modular_adaptor_number_mul_perf_test) {
    auto x = x_mod_ct_odd;

    nil::crypto3::bench::run_benchmark<>(
            "[odd modulus][compile time] modular_adaptor_number_multiply",
            [&]() {
                x *= y_mod_ct_odd;
                return x;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(runtime_even_tests)

// This directly calls regular_mul from modular_functions_fixed.hpp.
BOOST_AUTO_TEST_CASE(barrett_mul_perf_test) {
    auto base_data = x_mod_rt_even.backend().base_data();
    const auto &mod_object = x_mod_rt_even.backend().mod_data().get_mod_obj();

    nil::crypto3::bench::run_benchmark<>(
            "[even modulus][runtime] regular_mul (direct call)",
            [&]() {
                mod_object.regular_mul(base_data, y_mod_rt_even.backend().base_data());
                return base_data;
            });

    std::cout << base_data << std::endl;
}

BOOST_AUTO_TEST_CASE(modular_adaptor_backend_sub_perf_test) {
    using namespace boost::multiprecision::default_ops;

    auto x_modular = x_mod_rt_even.backend();

    nil::crypto3::bench::run_benchmark<>(
            "[even modulus][runtime] modular_adaptor_backend_subtract",
            [&]() {
                eval_subtract(x_modular, y_mod_rt_even.backend());
                return x_modular;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x_modular << std::endl;
}

BOOST_AUTO_TEST_CASE(modular_adaptor_backend_add_perf_test) {
    using namespace boost::multiprecision::default_ops;

    auto x_modular = x_mod_rt_even.backend();

    nil::crypto3::bench::run_benchmark<>(
            "[even modulus][runtime] modular_adaptor_backend_add",
            [&]() {
                eval_add(x_modular, y_mod_rt_even.backend());
                return x_modular;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x_modular << std::endl;
}

BOOST_AUTO_TEST_CASE(modular_adaptor_backend_mul_perf_test) {
    auto x_modular = x_mod_rt_even.backend();

    nil::crypto3::bench::run_benchmark<>(
            "[even modulus][runtime] modular_adaptor_backend_multiply",
            [&]() {
                eval_multiply(x_modular, y_mod_rt_even.backend());
                return x_modular;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x_modular << std::endl;
}

BOOST_AUTO_TEST_CASE(modular_adaptor_number_mul_perf_test) {
    auto x = x_mod_rt_even;

    nil::crypto3::bench::run_benchmark<>(
            "[even modulus][runtime] modular_adaptor_number_multiply",
            [&]() {
                x *= y_mod_rt_even;
                return x;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(compile_time_even_tests)

// This directly calls regular_mul from modular_functions_fixed.hpp.
BOOST_AUTO_TEST_CASE(barrett_mul_perf_test) {
    auto base_data = x_mod_ct_even.backend().base_data();
    const auto &mod_object = x_mod_ct_even.backend().mod_data().get_mod_obj();

    nil::crypto3::bench::run_benchmark<>(
            "[even modulus][compile time] regular_mul (direct call)",
            [&]() {
                mod_object.regular_mul(base_data, y_mod_ct_even.backend().base_data());
                return base_data;
            });

    std::cout << base_data << std::endl;
}

BOOST_AUTO_TEST_CASE(modular_adaptor_backend_sub_perf_test) {
    using namespace boost::multiprecision::default_ops;

    auto x_modular = x_mod_ct_even.backend();

    nil::crypto3::bench::run_benchmark<>(
            "[even modulus][compile time] modular_adaptor_backend_subtract",
            [&]() {
                eval_subtract(x_modular, y_mod_ct_even.backend());
                return x_modular;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x_modular << std::endl;
}

BOOST_AUTO_TEST_CASE(modular_adaptor_backend_add_perf_test) {
    using namespace boost::multiprecision::default_ops;

    auto x_modular = x_mod_ct_even.backend();

    nil::crypto3::bench::run_benchmark<>(
            "[even modulus][compile time] modular_adaptor_backend_add",
            [&]() {
                eval_add(x_modular, y_mod_ct_even.backend());
                return x_modular;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x_modular << std::endl;
}

BOOST_AUTO_TEST_CASE(modular_adaptor_backend_mul_perf_test) {
    auto x_modular = x_mod_ct_even.backend();

    nil::crypto3::bench::run_benchmark<>(
            "[even modulus][compile time] modular_adaptor_backend_multiply",
            [&]() {
                eval_multiply(x_modular, y_mod_ct_even.backend());
                return x_modular;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x_modular << std::endl;
}

BOOST_AUTO_TEST_CASE(modular_adaptor_number_mul_perf_test) {
    auto x = x_mod_ct_even;

    nil::crypto3::bench::run_benchmark<>(
            "[even modulus][compile time] modular_adaptor_number_multiply",
            [&]() {
                x *= y_mod_ct_even;
                return x;
            });

    // Print something so the whole computation is not optimized out.
    std::cout << x << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()