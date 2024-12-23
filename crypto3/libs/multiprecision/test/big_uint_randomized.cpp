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

#define BOOST_TEST_MODULE big_uint_randomized_test

#include <algorithm>
#include <cstddef>
#include <optional>
#include <ostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

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
    static std::string test_data =
        std::string(TEST_DATA_DIR) + R"(big_uint_randomized.json)";
    boost::property_tree::ptree test_dataset;
    boost::property_tree::read_json(test_data, test_dataset);

    return as_vector<T>(test_dataset.get_child(test_name));
}

template<std::size_t Bits1, std::size_t Bits2>
struct ArithmeticSample {
    static constexpr std::size_t ResBits = std::max(Bits1, Bits2);

    std::optional<big_uint<ResBits>> parse_or_empty(const std::string &s) {
        if (s.empty()) {
            return std::nullopt;
        }
        return big_uint<ResBits>(s);
    }

    ArithmeticSample(const boost::property_tree::ptree &sample) : ptree(sample) {
        a = sample.get<std::string>("a");
        b = sample.get<std::string>("b");

        a_add_b = parse_or_empty(sample.get<std::string>("a_add_b"));
        a_sub_b = parse_or_empty(sample.get<std::string>("a_sub_b"));
        a_mul_b = parse_or_empty(sample.get<std::string>("a_mul_b"));
        a_div_b = parse_or_empty(sample.get<std::string>("a_div_b"));
        a_mod_b = parse_or_empty(sample.get<std::string>("a_mod_b"));

        a_wrapping_add_b = sample.get<std::string>("a_wrapping_add_b");
        a_wrapping_sub_b = sample.get<std::string>("a_wrapping_sub_b");
        a_wrapping_mul_b = sample.get<std::string>("a_wrapping_mul_b");

        a_or_b = sample.get<std::string>("a_or_b");
        a_and_b = sample.get<std::string>("a_and_b");
        a_xor_b = sample.get<std::string>("a_xor_b");

        cmp_a_b = sample.get<int>("cmp_a_b");
    }

    friend std::ostream &operator<<(std::ostream &os, const ArithmeticSample &sample) {
        boost::property_tree::json_parser::write_json(os, sample.ptree);
        return os;
    }

    big_uint<Bits1> a;
    big_uint<Bits2> b;
    std::optional<big_uint<ResBits>> a_add_b;
    std::optional<big_uint<ResBits>> a_sub_b;
    std::optional<big_uint<ResBits>> a_mul_b;
    std::optional<big_uint<ResBits>> a_div_b;
    std::optional<big_uint<ResBits>> a_mod_b;
    big_uint<ResBits> a_wrapping_add_b;
    big_uint<ResBits> a_wrapping_sub_b;
    big_uint<ResBits> a_wrapping_mul_b;
    big_uint<ResBits> a_or_b;
    big_uint<ResBits> a_and_b;
    big_uint<ResBits> a_xor_b;
    int cmp_a_b;

    boost::property_tree::ptree ptree;
};

template<std::size_t Bits1, std::size_t Bits2>
void base_operations_test(const ArithmeticSample<Bits1, Bits2> sample) {
    const auto &a = sample.a;
    const auto &b = sample.b;
    const auto &cmp_a_b = sample.cmp_a_b;

    if (sample.a_add_b) {
        BOOST_CHECK_EQUAL(a + b, *sample.a_add_b);
    } else {
        BOOST_CHECK_THROW(a + b, std::overflow_error);
    }

    if (sample.a_add_b) {
        BOOST_CHECK_EQUAL(a + b, *sample.a_add_b);
    } else {
        BOOST_CHECK_THROW(a + b, std::overflow_error);
    }

    if (sample.a_sub_b) {
        BOOST_CHECK_EQUAL(a - b, *sample.a_sub_b);
    } else {
        BOOST_CHECK_THROW(a - b, std::overflow_error);
    }

    if (sample.a_mul_b) {
        BOOST_CHECK_EQUAL(a * b, *sample.a_mul_b);
    } else {
        BOOST_CHECK_THROW(a * b, std::overflow_error);
    }

    if (sample.a_div_b) {
        BOOST_CHECK_EQUAL(a / b, *sample.a_div_b);
    } else {
        BOOST_CHECK_THROW(a / b, std::overflow_error);
    }

    if (sample.a_mod_b) {
        BOOST_CHECK_EQUAL(a % b, *sample.a_mod_b);
    } else {
        BOOST_CHECK_THROW(a % b, std::overflow_error);
    }

    BOOST_CHECK_EQUAL(wrapping_add(a, b), sample.a_wrapping_add_b);
    BOOST_CHECK_EQUAL(wrapping_sub(a, b), sample.a_wrapping_sub_b);
    BOOST_CHECK_EQUAL(wrapping_mul(a, b), sample.a_wrapping_mul_b);

    BOOST_CHECK_EQUAL(a | b, sample.a_or_b);
    BOOST_CHECK_EQUAL(a & b, sample.a_and_b);
    BOOST_CHECK_EQUAL(a ^ b, sample.a_xor_b);

    BOOST_CHECK_EQUAL(a > b, cmp_a_b > 0);
    BOOST_CHECK_EQUAL(a >= b, cmp_a_b >= 0);
    BOOST_CHECK_EQUAL(a == b, cmp_a_b == 0);
    BOOST_CHECK_EQUAL(a < b, cmp_a_b < 0);
    BOOST_CHECK_EQUAL(a <= b, cmp_a_b <= 0);
    BOOST_CHECK_EQUAL(a != b, cmp_a_b != 0);
}

BOOST_AUTO_TEST_SUITE(base_operations)

BOOST_DATA_TEST_CASE(base_operations_12_17,
                     (test_dataset<ArithmeticSample<12, 17>>("base_operations_12_17"))) {
    base_operations_test(sample);
}

BOOST_DATA_TEST_CASE(base_operations_260_130, (test_dataset<ArithmeticSample<260, 130>>(
                                                  "base_operations_260_130"))) {
    base_operations_test(sample);
}

BOOST_DATA_TEST_CASE(base_operations_128_256, (test_dataset<ArithmeticSample<128, 256>>(
                                                  "base_operations_128_256"))) {
    base_operations_test(sample);
}

BOOST_DATA_TEST_CASE(base_operations_128_128, (test_dataset<ArithmeticSample<128, 128>>(
                                                  "base_operations_128_128"))) {
    base_operations_test(sample);
}

BOOST_AUTO_TEST_SUITE_END()
