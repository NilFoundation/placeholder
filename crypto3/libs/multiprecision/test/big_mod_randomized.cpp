//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2024 Martun Karapetyan <martun@nil.foundation>
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE big_mod_randomized_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <ostream>
#include <string>
#include <type_traits>
#include <vector>

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include "nil/crypto3/multiprecision/big_mod.hpp"
#include "nil/crypto3/multiprecision/pow.hpp"

using namespace nil::crypto3::multiprecision;

template<typename T>
std::vector<T> as_vector(const boost::property_tree::ptree &pt) {
    std::vector<T> r;
    for (const auto &item : pt) {
        r.push_back(item.second);
    }
    return r;
}

template<typename T>
auto test_dataset(const std::string &test_name) {
    static std::string test_data =
        std::string(TEST_DATA_DIR) + R"(big_mod_randomized.json)";
    boost::property_tree::ptree test_dataset;
    boost::property_tree::read_json(test_data, test_dataset);

    return as_vector<T>(test_dataset.get_child(test_name));
}

template<typename modular_number_t, bool fixed_mod_ = false>
struct ModularArithmeticSample {
    static constexpr bool fixed_mod = fixed_mod_;
    using base_type = typename modular_number_t::base_type;

    static modular_number_t default_init() {
        if constexpr (fixed_mod) {
            return 0u;
        } else {
            return modular_number_t{0u, 1u};
        }
    }

    static base_type parse_number(const std::string &s) {
        if constexpr (std::is_same_v<base_type, std::uint64_t>) {
            return std::stoull(s, nullptr, 16);
        } else if constexpr (std::is_same_v<base_type, std::uint32_t>) {
            return std::stoul(s, nullptr, 16);
        } else {
            return s;
        }
    }

    ModularArithmeticSample(const boost::property_tree::ptree &sample) : ptree(sample) {
        a = parse_number(sample.get<std::string>("a"));
        b = parse_number(sample.get<std::string>("b"));
        m = parse_number(sample.get<std::string>("m"));
        if constexpr (fixed_mod) {
            BOOST_CHECK_EQUAL(modular_number_t::modular_ops_storage_t::ops().mod(), m);
            a_m = a;
            b_m = b;
        } else {
            a_m = modular_number_t{a, m};
            b_m = modular_number_t{b, m};
        }
        a_m_add_b_m = parse_number(sample.get<std::string>("a_m_add_b_m"));
        a_m_sub_b_m = parse_number(sample.get<std::string>("a_m_sub_b_m"));
        a_m_mul_b_m = parse_number(sample.get<std::string>("a_m_mul_b_m"));
        a_eq_b = sample.get<bool>("a_eq_b");
        a_m_pow_b = parse_number(sample.get<std::string>("a_m_pow_b"));
    }

    friend std::ostream &operator<<(std::ostream &os,
                                    const ModularArithmeticSample &sample) {
        boost::property_tree::json_parser::write_json(os, sample.ptree);
        return os;
    }

    base_type a;
    base_type b;
    base_type m;
    modular_number_t a_m{default_init()};
    modular_number_t b_m{default_init()};
    base_type a_m_add_b_m;
    base_type a_m_sub_b_m;
    base_type a_m_mul_b_m;
    bool a_eq_b;
    base_type a_m_pow_b;

    boost::property_tree::ptree ptree;
};

template<typename modular_number_t, bool fixed_mod>
void base_operations_test(
    const ModularArithmeticSample<modular_number_t, fixed_mod> sample) {
    const auto &a_m = sample.a_m;
    const auto &b_m = sample.b_m;
    const auto &b = sample.b;

    BOOST_CHECK_EQUAL(a_m + b_m, sample.a_m_add_b_m);
    BOOST_CHECK_EQUAL(a_m - b_m, sample.a_m_sub_b_m);
    BOOST_CHECK_EQUAL(a_m * b_m, sample.a_m_mul_b_m);

    modular_number_t x = a_m;
    x += b_m;
    BOOST_CHECK_EQUAL(x, sample.a_m_add_b_m);
    x = a_m;
    x -= b_m;
    BOOST_CHECK_EQUAL(x, sample.a_m_sub_b_m);
    x = a_m;
    x *= b_m;
    BOOST_CHECK_EQUAL(x, sample.a_m_mul_b_m);

    BOOST_CHECK_EQUAL(a_m == b_m, sample.a_eq_b);
    BOOST_CHECK_EQUAL(a_m != b_m, !sample.a_eq_b);

    BOOST_CHECK_EQUAL(pow(a_m, b), sample.a_m_pow_b);
}

BOOST_AUTO_TEST_SUITE(base_operations)

BOOST_DATA_TEST_CASE(prime_mod_montgomery_130,
                     (test_dataset<ModularArithmeticSample<montgomery_big_mod_rt<130>>>(
                         "prime_mod_montgomery_130"))) {
    base_operations_test(sample);
}

BOOST_DATA_TEST_CASE(
    even_mod_130,
    (test_dataset<ModularArithmeticSample<big_mod_rt<130>>>("even_mod_130"))) {
    base_operations_test(sample);
}

BOOST_DATA_TEST_CASE(
    goldilocks_montgomery,
    (test_dataset<ModularArithmeticSample<montgomery_big_mod_rt<64>>>("goldilocks"))) {
    base_operations_test(sample);
}

BOOST_DATA_TEST_CASE(
    goldilocks,
    (test_dataset<ModularArithmeticSample<goldilocks_mod, /*fixed_mod=*/true>>(
        "goldilocks"))) {
    base_operations_test(sample);
}

BOOST_DATA_TEST_CASE(
    mersenne31_montgomery,
    (test_dataset<ModularArithmeticSample<montgomery_big_mod_rt<31>>>("mersenne31"))) {
    base_operations_test(sample);
}

BOOST_DATA_TEST_CASE(
    mersenne31,
    (test_dataset<ModularArithmeticSample<mersenne31_mod, /*fixed_mod=*/true>>(
        "mersenne31"))) {
    base_operations_test(sample);
}

BOOST_DATA_TEST_CASE(
    koalabear_montgomery,
    (test_dataset<ModularArithmeticSample<montgomery_big_mod_rt<31>>>("koalabear"))) {
    base_operations_test(sample);
}

BOOST_DATA_TEST_CASE(
    koalabear, (test_dataset<ModularArithmeticSample<koalabear_mod, /*fixed_mod=*/true>>(
                   "koalabear"))) {
    base_operations_test(sample);
}

BOOST_DATA_TEST_CASE(
    babybear_montgomery,
    (test_dataset<ModularArithmeticSample<montgomery_big_mod_rt<31>>>("babybear"))) {
    base_operations_test(sample);
}

BOOST_DATA_TEST_CASE(
    babybear, (test_dataset<ModularArithmeticSample<babybear_mod, /*fixed_mod=*/true>>(
                  "babybear"))) {
    base_operations_test(sample);
}

BOOST_DATA_TEST_CASE(
    even_mod_17, (test_dataset<ModularArithmeticSample<big_mod_rt<17>>>("even_mod_17"))) {
    base_operations_test(sample);
}

BOOST_DATA_TEST_CASE(
    montgomery_17,
    (test_dataset<ModularArithmeticSample<montgomery_big_mod_rt<17>>>("montgomery_17"))) {
    base_operations_test(sample);
}

BOOST_AUTO_TEST_SUITE_END()
