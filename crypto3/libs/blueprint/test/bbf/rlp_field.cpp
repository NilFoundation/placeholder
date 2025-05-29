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
void test_bbf_rlp_field(const std::vector<std::uint8_t> &encoded_rlp, std::size_t max_bytes, bool is_variable_len = false, bool expected_to_pass = true) {

    typename bbf::rlp_field<field_type, bbf::GenerationStage::ASSIGNMENT>::input_type input = {encoded_rlp};
    auto B = bbf::circuit_builder<field_type, bbf::rlp_field, std::size_t, bool>(max_bytes, is_variable_len);
    auto [at, A, desc] = B.assign(input);
    BOOST_TEST(expected_to_pass == B.is_satisfied(at), "constraints are not satisfied");
}


BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_rlp_field_bbf_empty_string) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;
    std::vector<std::uint8_t> encoded_rlp = {0x80};

    test_bbf_rlp_field<field_type>(encoded_rlp, 9, true);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_rlp_field_bbf_to_fail) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;
    std::vector<std::uint8_t> encoded_rlp = {0x79, 0x80};

    test_bbf_rlp_field<field_type>(encoded_rlp, encoded_rlp.size(), false, false);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_rlp_field_bbf_short) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;
    std::vector<std::uint8_t> encoded_rlp = {0x83,0x41,0x1a, 0x04};

    test_bbf_rlp_field<field_type>(encoded_rlp, encoded_rlp.size());
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_rlp_field_bbf_short_padded) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;
    std::vector<std::uint8_t> encoded_rlp = {0x83,0x41,0x1a, 0x04};

    test_bbf_rlp_field<field_type>(encoded_rlp, 10, true);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_rlp_field_bbf_hash) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;
    std::string rlp = "a0bb9abb994e8c193b54fe9819e0ef532d9149e26e64335fa71b665410d98bcace";
    std::vector<std::uint8_t> encoded_rlp(rlp.size()/2);
    for(int j = 0; j < rlp.size() / 2; j++) {
        sscanf(rlp.substr(2*j, 2).c_str(), "%02hhX", &encoded_rlp[j]);
    }

    test_bbf_rlp_field<field_type>(encoded_rlp, encoded_rlp.size());
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_rlp_field_bbf_hash_to_fail) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;
    std::string rlp = "a0bb9abb994e8c193b54fe9819e0ef532d9149e26e64335fa71b665410d98bca";
    std::vector<std::uint8_t> encoded_rlp(rlp.size()/2);
    for(int j = 0; j < rlp.size() / 2; j++) {
        sscanf(rlp.substr(2*j, 2).c_str(), "%02hhX", &encoded_rlp[j]);
    }

    test_bbf_rlp_field<field_type>(encoded_rlp, encoded_rlp.size(), false, false);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_rlp_field_bbf_long) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;
    std::string rlp = "b9010045a32c3ea9a0c10dd61c08dec141ca03514302a0696b01a3120d021ad2074a1222e52330b636881a428016002b97a5a04395a8449aa8e800338b14441bbe1b085640dd0c88df0d2dc856630af2c4806a9d01075912442890c317dc608fe0cdb7c1c608a04a72852739c8d45081866bd3c2bc58d10d842c48ec5bd4bec92c0245eac4b0552e67c000bdd001482c39c0901900766f858de10a917bb04844b8f2429be904026910e570024150d0a9210d00a4cd4158a40bc0c240c0888683ab14700d19404245100d8808a44985ae0779f22423bcef48e001101721764a1e30f01a9073bb455b1a8eb4a9452521a0284b874264f00a8aeaa8d09205f0223100d584";
    std::vector<std::uint8_t> encoded_rlp(rlp.size()/2);
    for(int j = 0; j < rlp.size() / 2; j++) {
        sscanf(rlp.substr(2*j, 2).c_str(), "%02hhX", &encoded_rlp[j]);
    }

    test_bbf_rlp_field<field_type>(encoded_rlp, encoded_rlp.size());
}
BOOST_AUTO_TEST_SUITE_END()
