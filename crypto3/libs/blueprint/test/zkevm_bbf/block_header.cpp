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
#include <boost/algorithm/string.hpp>
#include <cstdlib>
#include <ctime>
#include <random>
#include <nil/blueprint/bbf/circuit_builder.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/circuits/block_header.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_word.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_block.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/subcomponents/block_header_table.hpp>
#include <nil/crypto3/test_tools/random_test_initializer.hpp>
#include <nil/blueprint/zkevm_bbf/util/ptree.hpp>

#include "./circuit_test_fixture.hpp"

using namespace nil::crypto3;
using namespace nil::blueprint;
// using namespace nil::blueprint::bbf;


// std::vector<std::uint8_t> hex_string_to_bytes(std::string const &hex_string) {
//     std::vector<std::uint8_t> bytes;
//     for (std::size_t i = hex_string.size() - 2; i >= 2;i -= 2) {
//         std::string byte_string = hex_string.substr(i, 2);
//         bytes.push_back(std::stoi(byte_string, nullptr, 16));
//     }
//     if(hex_string.size() % 2 == 1){
//         bytes.push_back(std::stoi(hex_string.substr(2, 1), nullptr, 16));
//     }
//     std::reverse(bytes.begin(), bytes.end());
//     return bytes;
// }

boost::property_tree::ptree load_json_input(std::string path){
    std::ifstream ss;
    std::cout << "Open file " << std::string(TEST_DATA_DIR) + path << std::endl;
    ss.open(std::string(TEST_DATA_DIR) + path);
    if( !ss.is_open() ){
        BOOST_LOG_TRIVIAL(trace) << "Cannot open file " << std::string(TEST_DATA_DIR) + path ;
        exit(1);
    }
    boost::property_tree::ptree pt;
    boost::property_tree::read_json(ss, pt);
    ss.close();

    return pt;
}

bbf::zkevm_block block_loader(std::string path) {
    auto block_ptree = load_json_input(path + std::string("block.json"));

    bbf::zkevm_block block = {};
    block.hash = zkevm_word_from_string(block_ptree.get_child("block.hash").data());
    block.parent_hash = zkevm_word_from_string(block_ptree.get_child("block.parentHash").data());
    block.sha3_uncles = zkevm_word_from_string(block_ptree.get_child("block.sha3Uncles").data());
    block.miner = zkevm_word_from_string(block_ptree.get_child("block.miner").data());
    block.state_root = zkevm_word_from_string(block_ptree.get_child("block.stateRoot").data());
    block.tx_root = zkevm_word_from_string(block_ptree.get_child("block.transactionsRoot").data());
    block.receipts_root = zkevm_word_from_string(block_ptree.get_child("block.receiptsRoot").data());
    block.mix_hash = zkevm_word_from_string(block_ptree.get_child("block.mixHash").data());

    block.timestamp = hex_string_to_bytes(block_ptree.get_child("block.timestamp").data());
    block.block_number = hex_string_to_bytes(block_ptree.get_child("block.number").data());
    
    auto logsbloom  = block_ptree.get_child("block.logsBloom").data();
    for (std::size_t i = 0; i < 8; i++){
        block.logs_bloom[i] = zkevm_word_from_string(logsbloom.substr(64*i+2, 64));
    }

    std::size_t bn = 0;
    for (std::uint8_t b : block.block_number){
        bn = (bn << 8) | b;
    }
    // block numbers after each fork (https://ethereum.org/en/history/)
    if (bn >= 22431084) block.fork_type = 4;      // Pectra
    else if (bn >= 19426587) block.fork_type = 3; // Dencun
    else if (bn >= 17034870) block.fork_type = 2; // Shapella
    else if (bn >= 12965000) block.fork_type = 1; // London
    else block.fork_type = 0;

    auto nonce = hex_string_to_bytes(block_ptree.get_child("block.nonce").data());
    BOOST_ASSERT(nonce.size() == 8);
    for(std::size_t i = 0; i < nonce.size(); i++){
        block.nonce[i] = nonce[i];
    }
    // block.difficulty = hex_string_to_bytes(block_ptree.get_child("block.difficulty").data()); 
    block.gas_limit = hex_string_to_bytes(block_ptree.get_child("block.gasLimit").data()); 
    block.gas_used = hex_string_to_bytes(block_ptree.get_child("block.gasUsed").data()); 
    block.extra_data = hex_string_to_bytes(block_ptree.get_child("block.extraData").data()); 

    if (block.fork_type >= 1) {
        block.base_fee =  hex_string_to_bytes(block_ptree.get_child("block.baseFeePerGas").data());
    }

    if (block.fork_type >= 2) {
        block.withdrawals_root = zkevm_word_from_string(block_ptree.get_child("block.withdrawalsRoot").data());
    }

    if (block.fork_type >= 3) {
        block.blob_gas_used = hex_string_to_bytes(block_ptree.get_child("block.blobGasUsed").data()); 
        block.excess_blob_gas = hex_string_to_bytes(block_ptree.get_child("block.excessBlobGas").data()); 
        block.parent_beacon_root = zkevm_word_from_string(block_ptree.get_child("block.parentBeaconBlockRoot").data());
    }
    
    
    // BOOST_LOG_TRIVIAL(trace) << "Transactions amount = " << block.tx_amount;
    
    return block;
}

class zkEVMBlockHeaderTestFixture: public CircuitTestFixture {
public:
    template<typename field_type>
    void test_zkevm_bbf_block_header(const bbf::zkevm_block &block,
        bool expected_result = true) {

        nil::crypto3::test_tools::random_test_initializer<field_type> rnd;
        typename bbf::zkevm_big_field::block_header<field_type, bbf::GenerationStage::ASSIGNMENT>::input_type assignment_inputs;
        assignment_inputs.input_blocks = {block};
        assignment_inputs.rlc_challenge = 7 ;//rnd.alg_random_engines.template get_alg_engine<field_type>()();

        bool result = test_bbf_component<field_type, bbf::zkevm_big_field::block_header>(
            "block_header",
            {7},                        //  Public input
            assignment_inputs,  //  Assignment input
            block.fork_type                //  Fork type - to be changed
            // max_keccak_blocks           //  Keccak blocks amount
        );
        BOOST_CHECK((!check_satisfiability && !generate_proof) || result == expected_result);
    }
};


BOOST_FIXTURE_TEST_SUITE(blueprint_plonk_test_suite, zkEVMBlockHeaderTestFixture)

// BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_block_header_before_london) {
//     using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
//     using value_type = typename field_type::value_type;

//     std::string rlp = "f90220a0b8b861952bca93c10bc7c38f9ef5c4e047beae539cfe46fa456c78893d916927a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940501b62d81a3f072f1d393d2f74013bab8d36d5ca01fd1d6a626d5d72d433b776c0c348f0cab03d13c68ba39ca4a6d6f109032de34a0418c7fdf567a5989a727ea0fe6054008ecf4953aaf56c28f7f197f6e443f05c0a05f79bcb9839eb480350b541377d04c5088fc4bab6952ed27cb94c70dd6736d73b9010081029040054830208119a218064a503c384490dc2014a414e3148820851856c05008e643a88a4a0002242e1a702d8a516244220a18cd0121a13a20882930000e471369c142ad4323475013088accb068824a002cc35021640860a448405a904001094c200a6081d0420feb02802c2e090a121403213d2640c100503510300364e43020f55943142815080595b145040045890021412545119b9002891cfe41011a704100ca97641210002a3b22c10f24853849048420100465c361880421593000021022c90800008800750e546464068cc40290108c48741899114af9c52801403da6800c02000c6ea270992068b45618c46f1254d7601d4411104e41d00a0787074abe0f14de3383765fdd837a121d8379cbd7845cda8ef39fde830203088f5061726974792d457468657265756d86312e33332e30826c69a09d41f9f64af4ebd672dec132507a12a4c85c1a514f47969dbd9c2b5e9d7d214e882b8a102295423254";
//     std::vector<std::uint8_t> encoded_rlp(rlp.size()/2);
//     for(int j = 0; j < rlp.size() / 2; j++) {
//         sscanf(rlp.substr(2*j, 2).c_str(), "%02hhX", &encoded_rlp[j]);
//     }
    
//     std::size_t fork_type = 0;
//     auto block_hash = zkevm_keccak_hash(encoded_rlp);
//     test_zkevm_bbf_block_header<field_type>(encoded_rlp, block_hash, fork_type, true);
// }

// BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_block_header_london) {
//     using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
//     using value_type = typename field_type::value_type;

//     std::string rlp = "f90201a0d7519abd494a823b2c9c28908eaf250fe4a6287d747f1cc53a5a193b6533a549a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944675c7e5baafbffbca748158becba61ef3b0a263a025000d51f040ee5c473fed74eda9ace87d55a35187b11bcde6f5176025c395bfa0a5800a6de6d28d7425ff72714af2af769b9f8f9e1baf56fb42f793fbb40fde07a056e1062a3dc63791e8a8496837606b14062da70ee69178cea97d6eeb5047550cb9010000236420014dc00423903000840002280080282100004704018340c0241c20011211400426000f900001d8088000011006020002ce98bc00c0000020c9a02040000688040200348c3a0082b81402002814922008085d008008200802802c4000130000101703124801400400018008a6108002020420144011200070020bc0202681810804221304004800088600300000040463614a000e200201c00611c0008e800b014081608010a0218a0b410010082000428209080200f50260a00840006700100f40a000000400000448301008c4a00341040e343500800d06250020010215200c008018002c88350404000bc5000a8000210c00724a0d0a4010210a448083eee2468401c9c3808343107884633899e780a07980d8d1f15474c9185e4d1cef5f207167735009daad2eb6af6da37ffba213c28800000000000000008501e08469e6";
//     std::vector<std::uint8_t> encoded_rlp(rlp.size()/2);
//     for(int j = 0; j < rlp.size() / 2; j++) {
//         sscanf(rlp.substr(2*j, 2).c_str(), "%02hhX", &encoded_rlp[j]);
//     }

//     std::size_t fork_type = 1;
//     auto block_hash = zkevm_keccak_hash(encoded_rlp);
//     test_zkevm_bbf_block_header<field_type>(encoded_rlp, block_hash, fork_type, true);
// }

BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_block_header_shapella) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;

    bbf::zkevm_block block = block_loader("alchemy/sp1_block_26/");
    block.rlp_encoding = encode_rlp(block);
    test_zkevm_bbf_block_header<field_type>(block, true);
    
}

// BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_block_header_dencun) {
//     using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
//     using value_type = typename field_type::value_type;

//     std::string rlp = "f90249a0d7519abd494a823b2c9c28908eaf250fe4a6287d747f1cc53a5a193b6533a549a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944675c7e5baafbffbca748158becba61ef3b0a263a025000d51f040ee5c473fed74eda9ace87d55a35187b11bcde6f5176025c395bfa0a5800a6de6d28d7425ff72714af2af769b9f8f9e1baf56fb42f793fbb40fde07a056e1062a3dc63791e8a8496837606b14062da70ee69178cea97d6eeb5047550cb9010000236420014dc00423903000840002280080282100004704018340c0241c20011211400426000f900001d8088000011006020002ce98bc00c0000020c9a02040000688040200348c3a0082b81402002814922008085d008008200802802c4000130000101703124801400400018008a6108002020420144011200070020bc0202681810804221304004800088600300000040463614a000e200201c00611c0008e800b014081608010a0218a0b410010082000428209080200f50260a00840006700100f40a000000400000448301008c4a00341040e343500800d06250020010215200c008018002c88350404000bc5000a8000210c00724a0d0a4010210a448083eee2468401c9c3808343107884633899e780a07980d8d1f15474c9185e4d1cef5f207167735009daad2eb6af6da37ffba213c28800000000000000008501e08469e6a0f7519abd494a823b2c9c28908eaf250fe4a6287d747f1cc53a5a193b6533a549820123820456a07980d8d1f15474c9185e4d1cef5f207167735009daad2eb6af6da37ffba213c2";
//     std::vector<std::uint8_t> encoded_rlp(rlp.size()/2);
//     for(int j = 0; j < rlp.size() / 2; j++) {
//         sscanf(rlp.substr(2*j, 2).c_str(), "%02hhX", &encoded_rlp[j]);
//     }

//     std::size_t fork_type = 3;
//     auto block_hash = zkevm_keccak_hash(encoded_rlp);
//     test_zkevm_bbf_block_header<field_type>(encoded_rlp, block_hash, fork_type, true);
// }

BOOST_AUTO_TEST_SUITE_END()