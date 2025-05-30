//---------------------------------------------------------------------------//
// Copyright (c) 2025 Alexey Yashunsky <a.yashunsky@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_mpt_test

#include <boost/test/unit_test.hpp>
#include <boost/property_tree/ptree.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
// #include <nil/blueprint/zkevm_bbf/mpt.hpp>
#include <nil/blueprint/zkevm_bbf/mpt_leaf.hpp>
#include <nil/blueprint/zkevm_bbf/mpt_dynamic.hpp>

#include "./circuit_test_fixture.hpp"

using namespace nil::crypto3;
using namespace nil::blueprint;
using namespace nil::blueprint::bbf;

class zkEVMMPTTestFixture: public CircuitTestFixture {
public:
    boost::property_tree::ptree load_json_input(std::string path){
        std::ifstream ss;
        std::cout << "Open file " << std::string(TEST_DATA_DIR) + path << std::endl;
        ss.open(std::string(TEST_DATA_DIR) + path);
        if( !ss.is_open() ){
            std::cout << "Cannot open file " << std::string(TEST_DATA_DIR) + path << std::endl;
            exit(1);
        }
        boost::property_tree::ptree pt;
        boost::property_tree::read_json(ss, pt);
        ss.close();

        return pt;
    }

    template <typename field_type>
    void test_zkevm_mpt(
        std::string data_source,
        std::size_t max_mpt_size,
        bool expected_result = true
    ) {
        mpt_paths_vector paths;

        boost::property_tree::ptree src_data = load_json_input(data_source);

        mpt_path single_path;

        std::string path_key = src_data.get<std::string>("storageProof..key");
        boost::property_tree::ptree proof_path = src_data.get_child("storageProof..proof");

        // std::cout << "key = " << path_key << std::endl;
        single_path.slotNumber = zkevm_word_from_string(path_key); // TODO it's not slot number always

        for(const auto &v : proof_path) {
            boost::property_tree::ptree node = v.second;

            mpt_node single_node = {extension, {}, {}};
            if (node.size() == 17) {
                single_node.type = branch;
            }

            // std::cout << "[" << std::endl;

            for(const auto &w : node) {
                std::string hash_value = w.second.data();
                // std::cout << "    value = " << hash_value << std::endl;
                single_node.value.push_back(zkevm_word_from_string(hash_value));
                single_node.len.push_back(hash_value.length());
            }
            // std::cout << "]" << std::endl;
            single_path.proof.push_back(single_node);
        }
        if (single_path.proof.back().value.size() != 17){ // the last node is either a leaf node or a branch node (if leaf doesn't exist)
            single_path.proof.back().type = leaf;
        }
        paths.push_back(single_path);

/*
        bool result = test_bbf_component<field_type, mpt>(
            "mpt",                 //  Circuit name
            {} ,                   //  Public input
            paths,                 //  Assignment input (paths to prove)
            max_mpt_size           //  Maximum size of mpt circuit
        );
        BOOST_CHECK((!check_satisfiability && !generate_proof) || result == expected_result); // Max_rw, Max_mpt
*/
        bool result = test_bbf_component<field_type, mpt_dynamic>(
            "mpt_dynamic",         //  Circuit name
            {} ,                   //  Public input
            { 7,  paths },         //  Assignment input: rlc_challenge, paths to prove
            max_mpt_size           //  Maximum size of mpt circuit
        );
        BOOST_CHECK((!check_satisfiability && !generate_proof) || result == expected_result); // Max_rw, Max_mpt

    }

    template <typename field_type>
    void test_zkevm_mpt_leaf(
        std::string data_source,
        mpt_type type, // fix this
        std::size_t max_mpt_leaf_size,
        bool expected_result = true
    ) {
        using input_type = typename mpt_leaf_node<field_type, GenerationStage::ASSIGNMENT>::input_type;
        input_type input;
        input.rlc_challenge = 68;
        boost::property_tree::ptree queries_data = load_json_input(data_source);

        for(const auto &v : queries_data) {
            boost::property_tree::ptree query = v.second;
            std::size_t offset = std::stoi(query.get_child("offset").data());
            std::size_t selector = 0;
            if (query.get_child_optional( "selector" ))
                selector = std::stoi(query.get_child_optional( "selector" )->data());

            boost::property_tree::ptree node = query.get_child("node");
            leaf_node_data l = {{}};
            int i = 0;
            for(const auto &w : node) {
                std::string hash_value = w.second.data();
                std::vector<zkevm_word_type> value;
                if (hash_value.length() % 2 == 1) {
                    std::string highest_byte(1, hash_value[0]);
                    value.push_back(zkevm_word_from_string(highest_byte));

                    hash_value = hash_value.substr(1, hash_value.length()-1);
                }
                for (unsigned j = 0; j < hash_value.length(); j += 2) {
                    value.push_back(zkevm_word_from_string(hash_value.substr(j, 2)));
                }
                l.data[i++] = value;
            }
            mpt_query single_query = {offset, selector, l};
            input.queries.push_back(single_query);
        }
        bool result = test_bbf_component<field_type, mpt_leaf_node>(
            "mpt_leaf_node",   //  Circuit name
            {} ,               //  Public input
            input,             //  Assignment input (paths to prove)
            max_mpt_leaf_size, //  Maximum size of mpt circuit,
            type
        );
        BOOST_CHECK((!check_satisfiability && !generate_proof) || result == expected_result); // Max_rw, Max_mpt
    }
};

BOOST_GLOBAL_FIXTURE(zkEVMGlobalFixture);

BOOST_FIXTURE_TEST_SUITE(zkevm_bbf_mpt_leaf, zkEVMMPTTestFixture)
    using field_type = nil::crypto3::algebra::curves::alt_bn128_254::scalar_field_type;
BOOST_AUTO_TEST_CASE(one_mpt_path) {
    // test_zkevm_mpt<field_type>("mpt_path_0.json", 500);
    // test_zkevm_mpt<field_type>("mpt_path_1.json", 500); // problematic
    // test_zkevm_mpt<field_type>("mpt_path_2.json", 500);
    // test_zkevm_mpt<field_type>("mpt_path_3.json", 500);
}
BOOST_AUTO_TEST_CASE(mpt_leafs) {
  test_zkevm_mpt_leaf<field_type>("mpt_leaf_storage.json", mpt_type::storage_trie, 20);
  test_zkevm_mpt_leaf<field_type>("mpt_leaf_account.json", mpt_type::account_trie, 20);
}
BOOST_AUTO_TEST_SUITE_END()
