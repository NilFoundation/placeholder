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
#include <nil/blueprint/zkevm_bbf/mpt.hpp>

#include "./circuit_test_fixture.hpp"

using namespace nil::crypto3;
using namespace nil::blueprint;
using namespace nil::blueprint::bbf;

class zkEVMMPTTestFixture: public CircuitTestFixture {
public:
    boost::property_tree::ptree load_json_input(std::string path){
        std::ifstream ss;
        //std::cout << "Open file " << std::string(TEST_DATA_DIR) + path << std::endl;
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
        using input_type = typename mpt<field_type, GenerationStage::ASSIGNMENT>::input_type;

        input_type paths;

        boost::property_tree::ptree src_data = load_json_input(data_source);

        mpt_path single_path;

        std::string path_key = src_data.get<std::string>("storageProof..key");
        boost::property_tree::ptree proof_path = src_data.get_child("storageProof..proof");

        // std::cout << "key = " << path_key << std::endl;
        single_path.slotNumber = zkevm_word_from_string(path_key); // TODO it's not slot number always

        for(const auto &v : proof_path) {
            boost::property_tree::ptree node = v.second;

            mpt_node single_node = {extension, {}};
            if (node.size() == 17) {
                single_node.type = branch;
            }

            // std::cout << "[" << std::endl;

            for(const auto &w : node) {
                std::string hash_value = w.second.data();
                // std::cout << "    value = " << hash_value << std::endl;
                single_node.value.push_back(zkevm_word_from_string(hash_value));
            }
            // std::cout << "]" << std::endl;
            single_path.proof.push_back(single_node);
        }
        if (single_path.proof.back().value.size() != 17){ // the last node is either a leaf node or a branch node (if leaf doesn't exist)
            single_path.proof.back().type = leaf; 
        }
        paths.push_back(single_path);


        bool result = test_bbf_component<field_type, mpt>(
            "mpt",                 //  Circuit name
            {} ,                   //  Public input
            paths,                 //  Assignment input (paths to prove)
            max_mpt_size           //  Maximum size of mpt circuit
        );
        BOOST_CHECK((!check_satisfiability && !generate_proof) || result == expected_result); // Max_rw, Max_mpt
    }
};

BOOST_FIXTURE_TEST_SUITE(zkevm_bbf_mpt, zkEVMMPTTestFixture)
    using field_type = nil::crypto3::algebra::curves::alt_bn128_254::scalar_field_type;
BOOST_AUTO_TEST_CASE(one_mpt_path) {
    test_zkevm_mpt<field_type>("mpt_path_0.json", 50);
}
BOOST_AUTO_TEST_SUITE_END()
