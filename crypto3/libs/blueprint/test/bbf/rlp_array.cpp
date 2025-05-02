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
#include <nil/blueprint/bbf/components/rlp/rlp_array.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>

using namespace nil::crypto3;
using namespace nil::blueprint;
template<typename field_type>
void test_bbf_rlp_array(const std::vector<std::uint8_t> &encoded_rlp, typename field_type::value_type RLC, std::vector<std::size_t> &max_bytes, bool expected_to_pass = true) {

    typename bbf::rlp_array<field_type, bbf::GenerationStage::ASSIGNMENT>::input_type input = {encoded_rlp, RLC};
    auto B = bbf::circuit_builder<field_type, bbf::rlp_array, std::vector<std::size_t>>(max_bytes);
    auto [at, A, desc] = B.assign(input);
    BOOST_TEST(expected_to_pass == B.is_satisfied(at), "constraints are not satisfied");
}


BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_rlp_array_bbf_two_items) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;

    std::string rlp = "c283411a04a0bb9abb994e8c193b54fe9819e0ef532d9149e26e64335fa71b665410d98bcace";
    std::vector<std::uint8_t> encoded_rlp(rlp.size()/2);
    for(int j = 0; j < rlp.size() / 2; j++) {
        sscanf(rlp.substr(2*j, 2).c_str(), "%02hhX", &encoded_rlp[j]);
    }
    value_type rlc = 0;
    std::vector<std::size_t> max_bytes = {4,33};
    test_bbf_rlp_array<field_type>(encoded_rlp, rlc, max_bytes);
}


BOOST_AUTO_TEST_CASE(blueprint_plonk_rlp_array_bbf_block_header) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;

    std::string rlp = "f90201a0d7519abd494a823b2c9c28908eaf250fe4a6287d747f1cc53a5a193b6533a549a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944675c7e5baafbffbca748158becba61ef3b0a263a025000d51f040ee5c473fed74eda9ace87d55a35187b11bcde6f5176025c395bfa0a5800a6de6d28d7425ff72714af2af769b9f8f9e1baf56fb42f793fbb40fde07a056e1062a3dc63791e8a8496837606b14062da70ee69178cea97d6eeb5047550cb9010000236420014dc00423903000840002280080282100004704018340c0241c20011211400426000f900001d8088000011006020002ce98bc00c0000020c9a02040000688040200348c3a0082b81402002814922008085d008008200802802c4000130000101703124801400400018008a6108002020420144011200070020bc0202681810804221304004800088600300000040463614a000e200201c00611c0008e800b014081608010a0218a0b410010082000428209080200f50260a00840006700100f40a000000400000448301008c4a00341040e343500800d06250020010215200c008018002c88350404000bc5000a8000210c00724a0d0a4010210a448083eee2468401c9c3808343107884633899e780a07980d8d1f15474c9185e4d1cef5f207167735009daad2eb6af6da37ffba213c28800000000000000008501e08469e6";
    std::vector<std::uint8_t> encoded_rlp(rlp.size()/2);
    for(int j = 0; j < rlp.size() / 2; j++) {
        sscanf(rlp.substr(2*j, 2).c_str(), "%02hhX", &encoded_rlp[j]);
    }
    value_type rlc = 0;
    std::vector<std::size_t> max_bytes = {33,33,21,33,33,33,259,8,5,5,5,5,33,33,9,33};
    test_bbf_rlp_array<field_type>(encoded_rlp, rlc, max_bytes);
}


// BOOST_AUTO_TEST_CASE(blueprint_plonk_rlp_field_bbf_to_fail) {
//     using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
//     using value_type = typename field_type::value_type;
//     std::vector<std::uint8_t> encoded_rlp = {0x79, 0x80};
//     value_type rlc = 0;
//     test_bbf_rlp_field<field_type>(encoded_rlp, rlc, encoded_rlp.size(), false);
// }

// BOOST_AUTO_TEST_CASE(blueprint_plonk_rlp_field_bbf_short) {
//     using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
//     using value_type = typename field_type::value_type;
//     std::vector<std::uint8_t> encoded_rlp = {0x83,0x41,0x1a, 0x04};
//     value_type rlc = 0;
//     test_bbf_rlp_field<field_type>(encoded_rlp, rlc, encoded_rlp.size());
// }

// BOOST_AUTO_TEST_CASE(blueprint_plonk_rlp_field_bbf_short_padded) {
//     using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
//     using value_type = typename field_type::value_type;
//     std::vector<std::uint8_t> encoded_rlp = {0x83,0x41,0x1a, 0x04};
//     value_type rlc = 0;
//     test_bbf_rlp_field<field_type>(encoded_rlp, rlc, 10);
// }

// BOOST_AUTO_TEST_CASE(blueprint_plonk_rlp_field_bbf_hash) {
//     using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
//     using value_type = typename field_type::value_type;
//     std::string rlp = "c283411a04a1bb9abb994e8c193b54fe9819e0ef532d9149e26e64335fa71b665410d98bcace";
//     std::vector<std::uint8_t> encoded_rlp(rlp.size()/2);
//     for(int j = 0; j < rlp.size() / 2; j++) {
//         sscanf(rlp.substr(2*j, 2).c_str(), "%02hhX", &encoded_rlp[j]);
//     }
//     value_type rlc = 0;
//     test_bbf_rlp_field<field_type>(encoded_rlp, rlc, encoded_rlp.size());
// }

// BOOST_AUTO_TEST_CASE(blueprint_plonk_rlp_field_bbf_hash_to_fail) {
//     using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
//     using value_type = typename field_type::value_type;
//     std::string rlp = "a0bb9abb994e8c193b54fe9819e0ef532d9149e26e64335fa71b665410d98bca";
//     std::vector<std::uint8_t> encoded_rlp(rlp.size()/2);
//     for(int j = 0; j < rlp.size() / 2; j++) {
//         sscanf(rlp.substr(2*j, 2).c_str(), "%02hhX", &encoded_rlp[j]);
//     }
//     value_type rlc = 0;
//     test_bbf_rlp_field<field_type>(encoded_rlp, rlc, encoded_rlp.size(), false);
// }

// BOOST_AUTO_TEST_CASE(blueprint_plonk_rlp_field_bbf_long) {
//     using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
//     using value_type = typename field_type::value_type;
//     std::string rlp = "b90100102044006100018128200404a800800b2800010002000000200010410408020110000c400000000240024c0002008940120021400e4120b010c4200000220000000080000600200c09000208000080e101000031106401401010104180548000100802020020020005424804001026802600000100000434040c00904008000488a0902000100000010a715100000084880100050140880a1c480140201000000342080000002052020110c20081008a00880808120020000c300400000870241000050220220a024041060001081820000002000002801c0000200a04102406025a20200120800018601408222200008169000000800044200808104020c010";
//     std::vector<std::uint8_t> encoded_rlp(rlp.size()/2);
//     for(int j = 0; j < rlp.size() / 2; j++) {
//         sscanf(rlp.substr(2*j, 2).c_str(), "%02hhX", &encoded_rlp[j]);
//     }
//     value_type rlc = 0;
//     test_bbf_rlp_field<field_type>(encoded_rlp, rlc, encoded_rlp.size());
// }
BOOST_AUTO_TEST_SUITE_END()
