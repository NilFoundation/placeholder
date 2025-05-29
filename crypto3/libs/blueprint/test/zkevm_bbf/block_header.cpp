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
#define BOOST_TEST_MODULE plonk_block_header_test
#include <array>
#include <boost/test/unit_test.hpp>
#include <cstdlib>
#include <ctime>
#include <random>
#include <nil/blueprint/bbf/circuit_builder.hpp>
#include <nil/blueprint/zkevm_bbf/block_header.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_word.hpp>
#include <nil/crypto3/test_tools/random_test_initializer.hpp>

using namespace nil::crypto3;
using namespace nil::blueprint;


template<typename BlueprintFieldType>
void test_zkevm_bbf_block_header(const std::vector<std::uint8_t> &encoded_rlp, 
    const zkevm_word_type &expected_result,  
    std::size_t fork_type, 
    bool expected_to_pass = true) {

    nil::crypto3::test_tools::random_test_initializer<BlueprintFieldType> rnd;
    typename bbf::block_header<BlueprintFieldType, bbf::GenerationStage::ASSIGNMENT>::input_type input;
    input.input = encoded_rlp;
    input.rlc_challenge = rnd.alg_random_engines.template get_alg_engine<BlueprintFieldType>()();
    auto B = bbf::circuit_builder<BlueprintFieldType, bbf::block_header, std::size_t>(fork_type);
    auto [at, A, desc] = B.assign(input);
    BOOST_TEST(expected_to_pass == B.is_satisfied(at), "constraints are not satisfied");

    auto res = bbf::chunks8_to_chunks128<typename BlueprintFieldType::value_type>(A.result);
    BOOST_TEST(res.first == w_hi<BlueprintFieldType>(expected_result), "block hash doesn't match output");
    BOOST_TEST(res.second == w_lo<BlueprintFieldType>(expected_result), "block hash doesn't match output");
}


BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_block_header_before_london) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;

    std::string rlp = "f90220a0b8b861952bca93c10bc7c38f9ef5c4e047beae539cfe46fa456c78893d916927a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940501b62d81a3f072f1d393d2f74013bab8d36d5ca01fd1d6a626d5d72d433b776c0c348f0cab03d13c68ba39ca4a6d6f109032de34a0418c7fdf567a5989a727ea0fe6054008ecf4953aaf56c28f7f197f6e443f05c0a05f79bcb9839eb480350b541377d04c5088fc4bab6952ed27cb94c70dd6736d73b9010081029040054830208119a218064a503c384490dc2014a414e3148820851856c05008e643a88a4a0002242e1a702d8a516244220a18cd0121a13a20882930000e471369c142ad4323475013088accb068824a002cc35021640860a448405a904001094c200a6081d0420feb02802c2e090a121403213d2640c100503510300364e43020f55943142815080595b145040045890021412545119b9002891cfe41011a704100ca97641210002a3b22c10f24853849048420100465c361880421593000021022c90800008800750e546464068cc40290108c48741899114af9c52801403da6800c02000c6ea270992068b45618c46f1254d7601d4411104e41d00a0787074abe0f14de3383765fdd837a121d8379cbd7845cda8ef39fde830203088f5061726974792d457468657265756d86312e33332e30826c69a09d41f9f64af4ebd672dec132507a12a4c85c1a514f47969dbd9c2b5e9d7d214e882b8a102295423254";
    std::vector<std::uint8_t> encoded_rlp(rlp.size()/2);
    for(int j = 0; j < rlp.size() / 2; j++) {
        sscanf(rlp.substr(2*j, 2).c_str(), "%02hhX", &encoded_rlp[j]);
    }
    
    std::size_t fork_type = 0;
    auto block_hash = zkevm_keccak_hash(encoded_rlp);
    test_zkevm_bbf_block_header<field_type>(encoded_rlp, block_hash, fork_type, true);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_block_header_london) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;

    std::string rlp = "f90201a0d7519abd494a823b2c9c28908eaf250fe4a6287d747f1cc53a5a193b6533a549a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944675c7e5baafbffbca748158becba61ef3b0a263a025000d51f040ee5c473fed74eda9ace87d55a35187b11bcde6f5176025c395bfa0a5800a6de6d28d7425ff72714af2af769b9f8f9e1baf56fb42f793fbb40fde07a056e1062a3dc63791e8a8496837606b14062da70ee69178cea97d6eeb5047550cb9010000236420014dc00423903000840002280080282100004704018340c0241c20011211400426000f900001d8088000011006020002ce98bc00c0000020c9a02040000688040200348c3a0082b81402002814922008085d008008200802802c4000130000101703124801400400018008a6108002020420144011200070020bc0202681810804221304004800088600300000040463614a000e200201c00611c0008e800b014081608010a0218a0b410010082000428209080200f50260a00840006700100f40a000000400000448301008c4a00341040e343500800d06250020010215200c008018002c88350404000bc5000a8000210c00724a0d0a4010210a448083eee2468401c9c3808343107884633899e780a07980d8d1f15474c9185e4d1cef5f207167735009daad2eb6af6da37ffba213c28800000000000000008501e08469e6";
    std::vector<std::uint8_t> encoded_rlp(rlp.size()/2);
    for(int j = 0; j < rlp.size() / 2; j++) {
        sscanf(rlp.substr(2*j, 2).c_str(), "%02hhX", &encoded_rlp[j]);
    }

    std::size_t fork_type = 1;
    auto block_hash = zkevm_keccak_hash(encoded_rlp);
    test_zkevm_bbf_block_header<field_type>(encoded_rlp, block_hash, fork_type, true);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_block_header_shapella) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;

    std::string rlp = "f90232a0bb9abb994e8c193b54fe9819e0ef532d9149e26e64335fa71b665410d98bcacea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479495222290dd7278aa3ddd389cc1e1d165cc4bafe5a01b38d53a1944484c8c7e30177fd4dbde3f622d66a558ffdc786b362eb632595da0804129b64c1f93f4fd9ca715b5f89bc21a566e35e1d565e4b32a7cb46095d5dca01b00a9d69ae9b06c975a271bdabe7af8d20ef8045809500f2b03d3fd0c953c50b90100102044006100018128200404a800800b2800010002000000200010410408020110000c400000000240024c0002008940120021400e4120b010c4200000220000000080000600200c09000208000080e101000031106401401010104180548000100802020020020005424804001026802600000100000434040c00904008000488a0902000100000010a715100000084880100050140880a1c480140201000000342080000002052020110c20081008a00880808120020000c300400000870241000050220220a024041060001081820000002000002801c0000200a04102406025a20200120800018601408222200008169000000800044200808104020c0108084012029008401c9c38083411a0484658d8dab8f6265617665726275696c642e6f7267a03158187cb9f77ba10cfffae33421bbf595ce63a6e3e6218f425951468451a77c880000000000000000850ca9bd266da04979fa818fc34546275ae6dfd98418fcb0a2d0d81e187d13856571cc4c151ac8";
    std::vector<std::uint8_t> encoded_rlp(rlp.size()/2);
    for(int j = 0; j < rlp.size() / 2; j++) {
        sscanf(rlp.substr(2*j, 2).c_str(), "%02hhX", &encoded_rlp[j]);
    }

    std::size_t fork_type = 2;
    auto block_hash = zkevm_keccak_hash(encoded_rlp);
    test_zkevm_bbf_block_header<field_type>(encoded_rlp, block_hash, fork_type, true);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_block_header_dencun) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;

    std::string rlp = "f90249a0d7519abd494a823b2c9c28908eaf250fe4a6287d747f1cc53a5a193b6533a549a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944675c7e5baafbffbca748158becba61ef3b0a263a025000d51f040ee5c473fed74eda9ace87d55a35187b11bcde6f5176025c395bfa0a5800a6de6d28d7425ff72714af2af769b9f8f9e1baf56fb42f793fbb40fde07a056e1062a3dc63791e8a8496837606b14062da70ee69178cea97d6eeb5047550cb9010000236420014dc00423903000840002280080282100004704018340c0241c20011211400426000f900001d8088000011006020002ce98bc00c0000020c9a02040000688040200348c3a0082b81402002814922008085d008008200802802c4000130000101703124801400400018008a6108002020420144011200070020bc0202681810804221304004800088600300000040463614a000e200201c00611c0008e800b014081608010a0218a0b410010082000428209080200f50260a00840006700100f40a000000400000448301008c4a00341040e343500800d06250020010215200c008018002c88350404000bc5000a8000210c00724a0d0a4010210a448083eee2468401c9c3808343107884633899e780a07980d8d1f15474c9185e4d1cef5f207167735009daad2eb6af6da37ffba213c28800000000000000008501e08469e6a0f7519abd494a823b2c9c28908eaf250fe4a6287d747f1cc53a5a193b6533a549820123820456a07980d8d1f15474c9185e4d1cef5f207167735009daad2eb6af6da37ffba213c2";
    std::vector<std::uint8_t> encoded_rlp(rlp.size()/2);
    for(int j = 0; j < rlp.size() / 2; j++) {
        sscanf(rlp.substr(2*j, 2).c_str(), "%02hhX", &encoded_rlp[j]);
    }

    std::size_t fork_type = 3;
    auto block_hash = zkevm_keccak_hash(encoded_rlp);
    test_zkevm_bbf_block_header<field_type>(encoded_rlp, block_hash, fork_type, true);
}

BOOST_AUTO_TEST_SUITE_END()