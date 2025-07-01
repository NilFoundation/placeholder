//---------------------------------------------------------------------------//
// Copyright (c) 2025 Alexey Yashunsky <a.yashunsky@nil.foundation>
// Copyright (c) 2025 Amirhossein Khajehpour <a.khajepour@nil.foundation>
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

#include <unordered_map>
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

    std::vector<zkevm_word_type> string_to_zkevm_word(std::string raw) {
        std::vector<zkevm_word_type> result;
        if (raw.length() % 2 == 1) {
            std::string highest_byte(1, raw[0]);
            result.push_back(zkevm_word_from_string(highest_byte));
            raw = raw.substr(1, raw.length()-1);
        }
        for (unsigned j = 0; j < raw.length(); j += 2)
            result.push_back(zkevm_word_from_string(raw.substr(j, 2)));
        return result;
    }

    mpt_node read_node_from_list(boost::property_tree::ptree raw) {
        mpt_node node;
        node.hash = zkevm_word_from_string(raw.get_child("hash").data());
        for(const auto &w : raw.get_child("inners")) {
            std::string value = w.second.data();
            node.value.push_back(zkevm_word_from_string(value));
            node.len.push_back(value.length());
        }
        return node;
    }

    template <typename field_type>
    void test_zkevm_mpt(
        std::string data_source,
        std::size_t max_mpt_size,
        bool expected_result = true
    ) {
        boost::property_tree::ptree src_data = load_json_input(data_source);

        auto root = zkevm_word_from_string(src_data.get_child("root").data());

        std::vector<mpt_node> nodes;
        

        boost::property_tree::ptree _nodes = src_data.get_child("nodes");

        for(const auto &v : _nodes) {
            boost::property_tree::ptree raw = v.second;
            mpt_node node = read_node_from_list(raw);
            if (node.value.size() == 17)
                node.type = branch;
            else {
                char control_nibble = raw.get_child("inners").begin()->second.data()[0];
                if (control_nibble == '2' || control_nibble == '3')
                    node.type = leaf;
                else if (control_nibble == '0' || control_nibble == '1')
                    node.type = extension;
                else {}
                    // throw
            }
            nodes.push_back(node);
        }


        bool result = test_bbf_component<field_type, mpt_dynamic>(
            "mpt_dynamic",         //  Circuit name
            {} ,                   //  Public input
            { 7,  nodes, root },         //  Assignment input: rlc_challenge, paths to prove
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
            auto original_key = string_to_zkevm_word(query.get_child("original_key").data());
            leaf_node_data l = {original_key, {}};
            int i = 0;
            for(const auto &w : node) {
                std::string node_value = w.second.data();
                l.data[i++] = string_to_zkevm_word(node_value);
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
    test_zkevm_mpt<field_type>("mpt_storage_path_0.json", 500);
    test_zkevm_mpt<field_type>("mpt_storage_path_1.json", 500);
    test_zkevm_mpt<field_type>("mpt_storage_path_2.json", 500);
    test_zkevm_mpt<field_type>("mpt_storage_path_3.json", 500);
    test_zkevm_mpt<field_type>("mpt_storage_two_leaves_batch_0.json", 500);
    test_zkevm_mpt<field_type>("mpt_account_no_leaf_batch_0.json", 2000);
    test_zkevm_mpt<field_type>("mpt_extension_0.json", 500);
    test_zkevm_mpt<field_type>("mpt_extension_1.json", 500);
    test_zkevm_mpt<field_type>("mpt_extension_2.json", 500);
    test_zkevm_mpt<field_type>("mpt_extension_3.json", 500);
    test_zkevm_mpt<field_type>("mpt_extension_4.json", 500);
    test_zkevm_mpt<field_type>("mpt_extension_5.json", 500);
    test_zkevm_mpt<field_type>("mpt_extension_6.json", 500);
    test_zkevm_mpt<field_type>("mpt_extension_7.json", 500);
    test_zkevm_mpt<field_type>("mpt_extension_8.json", 500);
    test_zkevm_mpt<field_type>("mpt_extension_9.json", 500);
    test_zkevm_mpt<field_type>("mpt_extension_batch.json", 2000);
    test_zkevm_mpt<field_type>("mpt_extension_long_0.json", 50); // circuit underconstrained
    // test_zkevm_mpt<field_type>("mpt_account_batch_no_leaf_22140742.json", 25000); // uncomment only if you really want to wait three hours:)
}
BOOST_AUTO_TEST_CASE(mpt_leafs) {
  test_zkevm_mpt_leaf<field_type>("mpt_leaf_storage.json", mpt_type::storage_trie, 20);
  test_zkevm_mpt_leaf<field_type>("mpt_leaf_account.json", mpt_type::account_trie, 20);
//   test_zkevm_mpt_leaf<field_type>("mpt_leaf_account_22140743.json", mpt_type::account_trie, 1200); // very slow!
//   test_zkevm_mpt_leaf<field_type>("mpt_leaf_account_22140742.json", mpt_type::account_trie, 1200); // veryyy slow!
}
BOOST_AUTO_TEST_SUITE_END()
