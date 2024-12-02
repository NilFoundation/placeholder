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

#define BOOST_TEST_MODULE blueprint_plonk_opcodes_test

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

BOOST_AUTO_TEST_SUITE(zkevm_pushx_test_suite)

BOOST_AUTO_TEST_CASE(pushx_strings) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    zkevm_opcode_tester opcode_tester;

    opcode_tester.push_opcode(zkevm_opcode::PUSH0);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1,  hex_string_to_bytes("0x12"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH2,  hex_string_to_bytes("0x1234"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH3,  hex_string_to_bytes("0x123456"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH4,  hex_string_to_bytes("0x12345678"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH5,  hex_string_to_bytes("0x1b70726fb8"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH6,  hex_string_to_bytes("0x1b70726fb8d3"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH7,  hex_string_to_bytes("0x1b70726fb8d3a2"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH8,  hex_string_to_bytes("0x1b70726fb8d3a24d"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH9,  hex_string_to_bytes("0x1b70726fb8d3a24da9"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH10, hex_string_to_bytes("0x1b70726fb8d3a24da9ff"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH11, hex_string_to_bytes("0x1b70726fb8d3a24da9ff96"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH12, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH13, hex_string_to_bytes("0x1b70726fb8d3a24da9ff964722"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH14, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH15, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a18"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH16, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a1841"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH17, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a18412b"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH18, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a18412b8f"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH19, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a18412b8f01"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH20, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a18412b8f0104"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH21, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a18412b8f010425"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH22, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a18412b8f01042593"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH23, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a18412b8f0104259385"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH24, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH25, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d7"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH26, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73e"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH27, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH28, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc88"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH29, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH30, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH31, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e0"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016"));
    opcode_tester.push_opcode(zkevm_opcode::STOP);

    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 500;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 100;

    complex_opcode_test<field_type>(opcode_tester, max_sizes);
}

BOOST_AUTO_TEST_CASE(pushx) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    zkevm_opcode_tester opcode_tester;

    opcode_tester.push_opcode(zkevm_opcode::PUSH0);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1,  zwordc(0x12_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH2,  zwordc(0x1234_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH3,  zwordc(0x123456_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH4,  zwordc(0x12345678_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH5,  zwordc(0x1b70726fb8_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH6,  zwordc(0x1b70726fb8d3_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH7,  zwordc(0x1b70726fb8d3a2_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH8,  zwordc(0x1b70726fb8d3a24d_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH9,  zwordc(0x1b70726fb8d3a24da9_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH10, zwordc(0x1b70726fb8d3a24da9ff_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH11, zwordc(0x1b70726fb8d3a24da9ff96_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH12, zwordc(0x1b70726fb8d3a24da9ff9647_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH13, zwordc(0x1b70726fb8d3a24da9ff964722_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH14, zwordc(0x1b70726fb8d3a24da9ff9647225a_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH15, zwordc(0x1b70726fb8d3a24da9ff9647225a18_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH16, zwordc(0x1b70726fb8d3a24da9ff9647225a1841_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH17, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH18, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH19, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f01_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH20, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f0104_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH21, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH22, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f01042593_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH23, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f0104259385_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH24, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH25, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d7_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH26, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73e_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH27, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH28, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc88_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH29, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH30, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH31, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e0_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257));
    opcode_tester.push_opcode(zkevm_opcode::STOP);

    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 500;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 100;

    complex_opcode_test<field_type>(opcode_tester, max_sizes);
}
BOOST_AUTO_TEST_SUITE_END()
