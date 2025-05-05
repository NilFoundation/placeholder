//---------------------------------------------------------------------------//
// Copyright (c) 2025 Valeh Farzaliyev <estoniaa@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//
#define BOOST_TEST_MODULE plonk_rlp_field_test
#include <array>
#include <boost/test/unit_test.hpp>
#include <cstdlib>
#include <ctime>
#include <random>
#include <nil/blueprint/bbf/circuit_builder.hpp>
#include <nil/blueprint/bbf/components/rlp/rlp_field.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>

using namespace nil::crypto3;
using namespace nil::blueprint;
template<typename field_type>
void test_bbf_rlp_field(const std::vector<std::uint8_t> &encoded_rlp, typename field_type::value_type RLC, std::size_t max_bytes, bool is_variable_len = false, bool expected_to_pass = true) {

    typename bbf::rlp_field<field_type, bbf::GenerationStage::ASSIGNMENT>::input_type input = {encoded_rlp, RLC};
    auto B = bbf::circuit_builder<field_type, bbf::rlp_field, std::size_t, bool>(max_bytes, is_variable_len);
    auto [at, A, desc] = B.assign(input);
    BOOST_TEST(expected_to_pass == B.is_satisfied(at), "constraints are not satisfied");
}


BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_rlp_field_bbf_empty_string) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;
    std::vector<std::uint8_t> encoded_rlp = {0x80};
    value_type rlc = 0;
    test_bbf_rlp_field<field_type>(encoded_rlp, rlc, encoded_rlp.size());
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_rlp_field_bbf_to_fail) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;
    std::vector<std::uint8_t> encoded_rlp = {0x79, 0x80};
    value_type rlc = 0;
    test_bbf_rlp_field<field_type>(encoded_rlp, rlc, encoded_rlp.size(), false, false);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_rlp_field_bbf_short) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;
    std::vector<std::uint8_t> encoded_rlp = {0x83,0x41,0x1a, 0x04};
    value_type rlc = 0;
    test_bbf_rlp_field<field_type>(encoded_rlp, rlc, encoded_rlp.size());
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_rlp_field_bbf_short_padded) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;
    std::vector<std::uint8_t> encoded_rlp = {0x83,0x41,0x1a, 0x04};
    value_type rlc = 0;
    test_bbf_rlp_field<field_type>(encoded_rlp, rlc, 10, true);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_rlp_field_bbf_hash) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;
    std::string rlp = "a0bb9abb994e8c193b54fe9819e0ef532d9149e26e64335fa71b665410d98bcace";
    std::vector<std::uint8_t> encoded_rlp(rlp.size()/2);
    for(int j = 0; j < rlp.size() / 2; j++) {
        sscanf(rlp.substr(2*j, 2).c_str(), "%02hhX", &encoded_rlp[j]);
    }
    value_type rlc = 0;
    test_bbf_rlp_field<field_type>(encoded_rlp, rlc, encoded_rlp.size());
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_rlp_field_bbf_hash_to_fail) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;
    std::string rlp = "a0bb9abb994e8c193b54fe9819e0ef532d9149e26e64335fa71b665410d98bca";
    std::vector<std::uint8_t> encoded_rlp(rlp.size()/2);
    for(int j = 0; j < rlp.size() / 2; j++) {
        sscanf(rlp.substr(2*j, 2).c_str(), "%02hhX", &encoded_rlp[j]);
    }
    value_type rlc = 0;
    test_bbf_rlp_field<field_type>(encoded_rlp, rlc, encoded_rlp.size(), false, false);
}

// BOOST_AUTO_TEST_CASE(blueprint_plonk_rlp_field_bbf_very_long) {
//     using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
//     using value_type = typename field_type::value_type;
//     std::string rlp = "";
//     std::vector<std::uint8_t> encoded_rlp(rlp.size()/2);
//     for(int j = 0; j < rlp.size() / 2; j++) {
//         sscanf(rlp.substr(2*j, 2).c_str(), "%02hhX", &encoded_rlp[j]);
//     }
//     value_type rlc = 0;
//     test_bbf_rlp_field<field_type>(encoded_rlp, rlc, encoded_rlp.size());
// }
BOOST_AUTO_TEST_SUITE_END()
