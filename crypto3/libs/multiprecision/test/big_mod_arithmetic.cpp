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

#define BOOST_TEST_MODULE big_mod_arithmetic_test

#include <cstddef>
#include <ostream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include "nil/crypto3/multiprecision/big_mod.hpp"
#include "nil/crypto3/multiprecision/big_uint.hpp"

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
    static std::string test_data = std::string(TEST_DATA_DIR) + R"(modular_arithmetic.json)";
    boost::property_tree::ptree test_dataset;
    boost::property_tree::read_json(test_data, test_dataset);

    return as_vector<T>(test_dataset.get_child(test_name));
}

template<std::size_t Bits, bool Montgomery>
struct ModularArithmeticSample {
    ModularArithmeticSample(const boost::property_tree::ptree &sample) : ptree(sample) {
        a = sample.get<std::string>("a");
        b = sample.get<std::string>("b");
        m = sample.get<std::string>("m");
        a_m_add_b_m = sample.get<std::string>("a_m_add_b_m");
        a_m_sub_b_m = sample.get<std::string>("a_m_sub_b_m");
        a_m_mul_b_m = sample.get<std::string>("a_m_mul_b_m");
        a_eq_b = sample.get<bool>("a_eq_b");
        a_m_pow_b = sample.get<std::string>("a_m_pow_b");

        if (Montgomery && !m.bit_test(0)) {
            throw std::runtime_error("ModularArithmeticSample: Montgomery requires m to be odd");
        }
    }

    friend std::ostream &operator<<(std::ostream &os, const ModularArithmeticSample &sample) {
        boost::property_tree::json_parser::write_json(os, sample.ptree);
        return os;
    }

    big_uint<Bits> a;
    big_uint<Bits> b;
    big_uint<Bits> m;
    big_uint<Bits> a_m_add_b_m;
    big_uint<Bits> a_m_sub_b_m;
    big_uint<Bits> a_m_mul_b_m;
    bool a_eq_b;
    big_uint<Bits> a_m_pow_b;

    boost::property_tree::ptree ptree;
};

template<std::size_t Bits, bool Montgomery>
void base_operations_test(const ModularArithmeticSample<Bits, Montgomery> sample) {
    using modular_number =
        std::conditional_t<Montgomery, montgomery_big_mod_rt<Bits>, big_mod_rt<Bits>>;

    const auto &a = sample.a;
    const auto &b = sample.b;
    const auto &m = sample.m;

    modular_number a_m(a, m);
    modular_number b_m(b, m);

    BOOST_CHECK_EQUAL(a_m + b_m, sample.a_m_add_b_m);
    BOOST_CHECK_EQUAL(a_m - b_m, sample.a_m_sub_b_m);
    BOOST_CHECK_EQUAL(a_m * b_m, sample.a_m_mul_b_m);

    BOOST_CHECK_EQUAL(a_m == b_m, sample.a_eq_b);
    BOOST_CHECK_EQUAL(a_m != b_m, !sample.a_eq_b);

    BOOST_CHECK_EQUAL(pow(a_m, b), sample.a_m_pow_b);
}

BOOST_AUTO_TEST_SUITE(base_operations)

BOOST_DATA_TEST_CASE(prime_mod_montgomery_130, (test_dataset<ModularArithmeticSample<130, true>>(
                                                   "prime_mod_montgomery_130"))) {
    base_operations_test(sample);
}

BOOST_DATA_TEST_CASE(even_mod_130,
                     (test_dataset<ModularArithmeticSample<130, false>>("even_mod_130"))) {
    base_operations_test(sample);
}

// This one tests 64-bit numbers used in Goldilock fields.
BOOST_DATA_TEST_CASE(goldilock, (test_dataset<ModularArithmeticSample<64, true>>("goldilock"))) {
    base_operations_test(sample);
}

BOOST_DATA_TEST_CASE(even_mod_17,
                     (test_dataset<ModularArithmeticSample<17, false>>("even_mod_17"))) {
    base_operations_test(sample);
}

BOOST_DATA_TEST_CASE(montgomery_17,
                     (test_dataset<ModularArithmeticSample<17, true>>("montgomery_17"))) {
    base_operations_test(sample);
}

BOOST_AUTO_TEST_SUITE_END()
