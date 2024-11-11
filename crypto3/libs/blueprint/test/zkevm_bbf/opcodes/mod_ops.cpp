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

#include <nil/blueprint/zkevm_bbf/types/hashed_buffers.hpp>
#include <nil/blueprint/zkevm_bbf/types/rw_operation.hpp>
#include <nil/blueprint/zkevm_bbf/types/copy_event.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_state.hpp>
#include <nil/blueprint/zkevm_bbf/input_generators/opcode_tester.hpp>
#include <nil/blueprint/zkevm_bbf/input_generators/opcode_tester_input_generator.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/bbf/l1_wrapper.hpp>
#include <nil/blueprint/zkevm_bbf/zkevm.hpp>
#include <nil/blueprint/zkevm_bbf/rw.hpp>
#include <nil/blueprint/zkevm_bbf/copy.hpp>
#include <nil/blueprint/zkevm_bbf/bytecode.hpp>
#include <nil/blueprint/zkevm_bbf/keccak.hpp>

#include "../test_l1_wrapper.hpp"

using namespace nil::crypto3;
using namespace nil::blueprint::bbf;

template<typename field_type>
void complex_opcode_test(
    const zkevm_opcode_tester                       &opcode_tester,
    const l1_size_restrictions                      &max_sizes
){
    nil::blueprint::bbf::zkevm_opcode_tester_input_generator circuit_inputs(opcode_tester);

    using integral_type = typename field_type::integral_type;
    using value_type = typename field_type::value_type;

    integral_type base16 = integral_type(1) << 16;

    std::size_t max_keccak_blocks = max_sizes.max_keccak_blocks;
    std::size_t max_bytecode = max_sizes.max_bytecode;
    std::size_t max_mpt = max_sizes.max_mpt;
    std::size_t max_rw = max_sizes.max_rw;
    std::size_t max_copy = max_sizes.max_copy;
    std::size_t max_zkevm_rows = max_sizes.max_zkevm_rows;

    typename nil::blueprint::bbf::copy<field_type,nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type copy_assignment_input;
    typename nil::blueprint::bbf::copy<field_type,nil::blueprint::bbf::GenerationStage::CONSTRAINTS>::input_type copy_constraint_input;
    copy_assignment_input.rlc_challenge = 7;
    copy_assignment_input.bytecodes = circuit_inputs.bytecodes();
    copy_assignment_input.keccak_buffers = circuit_inputs.keccaks();
    copy_assignment_input.rw_operations = circuit_inputs.rw_operations();
    copy_assignment_input.copy_events = circuit_inputs.copy_events();

    typename nil::blueprint::bbf::zkevm<field_type,nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type zkevm_assignment_input;
    typename nil::blueprint::bbf::zkevm<field_type,nil::blueprint::bbf::GenerationStage::CONSTRAINTS>::input_type zkevm_constraint_input;
    zkevm_assignment_input.rlc_challenge = 7;
    zkevm_assignment_input.bytecodes = circuit_inputs.bytecodes();
    zkevm_assignment_input.keccak_buffers = circuit_inputs.keccaks();
    zkevm_assignment_input.rw_operations = circuit_inputs.rw_operations();
    zkevm_assignment_input.copy_events = circuit_inputs.copy_events();
    zkevm_assignment_input.zkevm_states = circuit_inputs.zkevm_states();

    typename nil::blueprint::bbf::rw<field_type,nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type rw_assignment_input = circuit_inputs.rw_operations();
    typename nil::blueprint::bbf::rw<field_type,nil::blueprint::bbf::GenerationStage::CONSTRAINTS>::input_type rw_constraint_input;

    typename nil::blueprint::bbf::keccak<field_type,nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type keccak_assignment_input;
    typename nil::blueprint::bbf::keccak<field_type,nil::blueprint::bbf::GenerationStage::CONSTRAINTS>::input_type keccak_constraint_input;
    keccak_assignment_input.private_input = 12345;

    typename nil::blueprint::bbf::bytecode<field_type,nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type bytecode_assignment_input;
    typename nil::blueprint::bbf::bytecode<field_type,nil::blueprint::bbf::GenerationStage::CONSTRAINTS>::input_type bytecode_constraint_input;
    bytecode_assignment_input.rlc_challenge = 7;
    bytecode_assignment_input.bytecodes = circuit_inputs.bytecodes();
    bytecode_assignment_input.keccak_buffers = circuit_inputs.keccaks();
    bool result;

    // Max_bytecode, max_bytecode
    std::cout << "Bytecode circuit" << std::endl;
    result = test_l1_wrapper<field_type, nil::blueprint::bbf::bytecode>({7}, bytecode_assignment_input, bytecode_constraint_input, max_bytecode, max_keccak_blocks);
    BOOST_ASSERT(result);
    std::cout << std::endl;

    // Max_rw, Max_mpt
    std::cout << "RW circuit" << std::endl;
    result = test_l1_wrapper<field_type, nil::blueprint::bbf::rw>({}, rw_assignment_input, rw_constraint_input, max_rw, max_mpt);
    BOOST_ASSERT(result);
    std::cout << std::endl;

    // Max_copy, Max_rw, Max_keccak, Max_bytecode
    result =test_l1_wrapper<field_type, nil::blueprint::bbf::copy>(
        {7}, copy_assignment_input, copy_constraint_input,
        max_copy, max_rw, max_keccak_blocks, max_bytecode
    );
    BOOST_ASSERT(result);
    std::cout << std::endl;

    // Max_rows, max_bytecode, max_rw
    result = test_l1_wrapper<field_type, nil::blueprint::bbf::zkevm>(
        {}, zkevm_assignment_input, zkevm_constraint_input,
        max_zkevm_rows,
        max_copy,
        max_rw,
        max_keccak_blocks,
        max_bytecode
    );
    BOOST_ASSERT(result);
    std::cout << std::endl;

    // Max_keccak
    result = test_l1_wrapper<field_type, nil::blueprint::bbf::keccak>(
        {}, keccak_assignment_input , keccak_constraint_input
    );
    BOOST_ASSERT(result);
    std::cout << std::endl;
}

// Remember that in production sizes should be preset.
// Here they are different for different tests just for fast and easy testing
BOOST_AUTO_TEST_SUITE(zkevm_opcode_test_suite)

BOOST_AUTO_TEST_CASE(iszero) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    zkevm_opcode_tester opcode_tester;

    l1_size_restrictions max_sizes;

    opcode_tester.push_opcode(zkevm_opcode::PUSH1, hex_string_to_bytes("0x00")); // N
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")); // b
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, hex_string_to_bytes("0x02")); // a
    opcode_tester.push_opcode(zkevm_opcode::ADDMOD);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, hex_string_to_bytes("0x00")); // N
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")); // b
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, hex_string_to_bytes("0x02")); // a
    opcode_tester.push_opcode(zkevm_opcode::MULMOD);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, hex_string_to_bytes("0x01")); // N
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")); // b
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, hex_string_to_bytes("0x02")); // a
    opcode_tester.push_opcode(zkevm_opcode::ADDMOD);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, hex_string_to_bytes("0x01")); // N
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")); // b
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, hex_string_to_bytes("0x02")); // a
    opcode_tester.push_opcode(zkevm_opcode::MULMOD);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, hex_string_to_bytes("0x03")); // N
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")); // b
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, hex_string_to_bytes("0x02")); // a
    opcode_tester.push_opcode(zkevm_opcode::ADDMOD);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, hex_string_to_bytes("0x03")); // N
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")); // b
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, hex_string_to_bytes("0x02")); // a
    opcode_tester.push_opcode(zkevm_opcode::MULMOD);
    opcode_tester.push_opcode(zkevm_opcode::PUSH5, hex_string_to_bytes("0x1234567890"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0x12b8f010425938504d73ebc8801e2e0161b70726fb8d3a24da9ff9647225a184"));
    opcode_tester.push_opcode(zkevm_opcode::ADDMOD);
    opcode_tester.push_opcode(zkevm_opcode::PUSH5, hex_string_to_bytes("0x1234567890"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0x12b8f010425938504d73ebc8801e2e0161b70726fb8d3a24da9ff9647225a184"));
    opcode_tester.push_opcode(zkevm_opcode::MULMOD);
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xFb70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xFb70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    opcode_tester.push_opcode(zkevm_opcode::ADDMOD);
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xFb70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xFb70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    opcode_tester.push_opcode(zkevm_opcode::MULMOD);
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH5, hex_string_to_bytes("0x1234567890"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH5, hex_string_to_bytes("0x6789012345"));
    opcode_tester.push_opcode(zkevm_opcode::ADDMOD);
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH5, hex_string_to_bytes("0x1234567890"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH5, hex_string_to_bytes("0x6789012345"));
    opcode_tester.push_opcode(zkevm_opcode::MULMOD);
    opcode_tester.push_opcode(zkevm_opcode::STOP);

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 500;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 300;
    complex_opcode_test<field_type>(opcode_tester, max_sizes);
}
BOOST_AUTO_TEST_SUITE_END()
