//---------------------------------------------------------------------------//
// Copyright (c) 2024 Martun Karapetyan <martun@nil.foundation>
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE big_uint_comparison_test

#include <cstddef>
#include <ostream>
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
    static std::string test_data = std::string(TEST_DATA_DIR) + R"(comparison.json)";
    boost::property_tree::ptree test_dataset;
    boost::property_tree::read_json(test_data, test_dataset);

    return as_vector<T>(test_dataset.get_child(test_name));
}

template<std::size_t Bits1, std::size_t Bits2>
struct ComparisonSample {
    ComparisonSample(const boost::property_tree::ptree &sample) : ptree(sample) {
        a = sample.get<std::string>("a");
        b = sample.get<std::string>("b");
        cmp_a_b = sample.get<int>("cmp_a_b");
    }

    friend std::ostream &operator<<(std::ostream &os, const ComparisonSample &sample) {
        boost::property_tree::json_parser::write_json(os, sample.ptree);
        return os;
    }

    big_uint<Bits1> a;
    big_uint<Bits2> b;
    int cmp_a_b;
    boost::property_tree::ptree ptree;
};

template<typename Sample>
void test_comparison(const Sample &sample) {
    const auto &a = sample.a;
    const auto &b = sample.b;
    const auto &cmp_a_b = sample.cmp_a_b;
    BOOST_CHECK_EQUAL(a > b, cmp_a_b > 0);
    BOOST_CHECK_EQUAL(a >= b, cmp_a_b >= 0);
    BOOST_CHECK_EQUAL(a == b, cmp_a_b == 0);
    BOOST_CHECK_EQUAL(a < b, cmp_a_b < 0);
    BOOST_CHECK_EQUAL(a <= b, cmp_a_b <= 0);
    BOOST_CHECK_EQUAL(a != b, cmp_a_b != 0);
}

BOOST_AUTO_TEST_SUITE(fields_manual_tests)

BOOST_DATA_TEST_CASE(test_comparison_12_17,
                     (test_dataset<ComparisonSample<12, 17>>("test_comparison_12_17"))) {
    test_comparison(sample);
}

BOOST_DATA_TEST_CASE(test_comparison_260_130,
                     (test_dataset<ComparisonSample<260, 130>>("test_comparison_260_130"))) {
    test_comparison(sample);
}

BOOST_DATA_TEST_CASE(test_comparison_128_256,
                     (test_dataset<ComparisonSample<128, 256>>("test_comparison_128_256"))) {
    test_comparison(sample);
}

BOOST_AUTO_TEST_SUITE_END()
