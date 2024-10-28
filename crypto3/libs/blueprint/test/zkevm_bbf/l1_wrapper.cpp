//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_l1_wrapper_test

#include <boost/assert.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/zkevm_bbf/l1_wrapper.hpp>
#include <nil/blueprint/zkevm_bbf/zkevm.hpp>
#include <nil/blueprint/zkevm_bbf/rw.hpp>
#include <nil/blueprint/zkevm_bbf/copy.hpp>
#include <nil/blueprint/zkevm_bbf/bytecode.hpp>
#include <nil/blueprint/zkevm_bbf/keccak.hpp>

#include "./test_l1_wrapper.hpp"

using namespace nil::crypto3;
using namespace nil::blueprint;

template<typename field_type>
void complex_test(){
    using integral_type = typename field_type::integral_type;
    using value_type = typename field_type::value_type;

    nil::crypto3::random::algebraic_engine<field_type> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);

    integral_type base16 = integral_type(1) << 16;

    std::size_t max_keccak_blocks = 10;
    std::size_t max_bytecode = 3000;
    std::size_t max_mpt = 0;
    std::size_t max_rw = 500;
    std::size_t max_copy_size = 3000;
    std::size_t max_zkevm_rows = 100;

    std::string path = "../crypto3/libs/blueprint/test/zkevm/data/minimal_math/";

    std::ifstream ss;
    ss.open(path + "trace0.json");
    boost::property_tree::ptree pt;
    boost::property_tree::read_json(ss, pt);
    ss.close();

    ss.open(path + "/contract0.json");
    boost::property_tree::ptree bytecode_json;
    boost::property_tree::read_json(ss, bytecode_json);
    std::vector<uint8_t> bytecode0 = hex_string_to_bytes(std::string(bytecode_json.get_child("bytecode").data().c_str()));
    ss.close();


    typename nil::blueprint::bbf::rw<field_type,nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type rw_assignment_input(pt, max_rw);;
    typename nil::blueprint::bbf::rw<field_type,nil::blueprint::bbf::GenerationStage::CONSTRAINTS>::input_type rw_constraint_input;

    typename nil::blueprint::bbf::zkevm<field_type,nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type zkevm_assignment_input;
    typename nil::blueprint::bbf::zkevm<field_type,nil::blueprint::bbf::GenerationStage::CONSTRAINTS>::input_type zkevm_constraint_input;
    zkevm_assignment_input.b = 18 * 18;

    typename nil::blueprint::bbf::keccak<field_type,nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type keccak_assignment_input;
    typename nil::blueprint::bbf::keccak<field_type,nil::blueprint::bbf::GenerationStage::CONSTRAINTS>::input_type keccak_constraint_input;
    keccak_assignment_input.private_input = 12345;

    typename nil::blueprint::bbf::bytecode<field_type,nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type bytecode_assignment_input;
    typename nil::blueprint::bbf::bytecode<field_type,nil::blueprint::bbf::GenerationStage::CONSTRAINTS>::input_type bytecode_constraint_input;
    bytecode_assignment_input.rlc_challenge = 7;
    bytecode_assignment_input.bytecodes.new_buffer(bytecode0);
    bytecode_assignment_input.keccak_buffers.new_buffer(bytecode0);
    bytecode_assignment_input.keccak_buffers.new_buffer(hex_string_to_bytes("0x1234567890"));

    // Max_bytecode, max_bytecode
    bool result;
    result = test_l1_wrapper<field_type, nil::blueprint::bbf::bytecode>({7}, bytecode_assignment_input, bytecode_constraint_input, max_bytecode, max_keccak_blocks);
    BOOST_ASSERT(result);
    // Max_rows, max_bytecode, max_rw
    result = test_l1_wrapper<field_type, nil::blueprint::bbf::zkevm>(
        {}, zkevm_assignment_input, zkevm_constraint_input, max_zkevm_rows, max_bytecode, max_rw
    );
    BOOST_ASSERT(result);
    std::cout << std::endl;
    // Max_rw, Max_mpt
    result = test_l1_wrapper<field_type, nil::blueprint::bbf::rw>({}, rw_assignment_input, rw_constraint_input, max_rw, max_mpt);
    BOOST_ASSERT(result);
    std::cout << std::endl;
    // Max_copy, Max_rw, Max_keccak
    result = test_l1_wrapper<field_type, nil::blueprint::bbf::copy>({}, 0, 1);
    BOOST_ASSERT(result);
    std::cout << std::endl;
    // Max_keccak
    test_l1_wrapper<field_type, nil::blueprint::bbf::keccak>(
        {}, keccak_assignment_input , keccak_constraint_input
    );
    BOOST_ASSERT(result);
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_l1_wrapper_test) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    complex_test<field_type>();
}

BOOST_AUTO_TEST_SUITE_END()