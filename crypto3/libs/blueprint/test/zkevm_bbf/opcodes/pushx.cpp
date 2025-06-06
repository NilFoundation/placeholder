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

#define BOOST_TEST_MODULE blueprint_plonk_opcodes_test_pushx

#include <boost/assert.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/babybear.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include "./opcode_test_fixture.hpp"

using namespace nil::crypto3;
using namespace nil::blueprint::bbf;

BOOST_GLOBAL_FIXTURE(zkEVMGlobalFixture);
BOOST_FIXTURE_TEST_SUITE(zkevm_opcode_bbf_test_suite, zkEVMOpcodeTestFixture)
    using big_field_type = typename nil::crypto3::algebra::curves::alt_bn128_254::scalar_field_type;
    using small_field_type = typename algebra::fields::babybear;

BOOST_AUTO_TEST_CASE(pushx_strings) {
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

    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 20;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 500;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 100;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 100;

    complex_opcode_test<big_field_type, small_field_type>(opcode_tester, max_sizes);
}

BOOST_AUTO_TEST_CASE(pushx) {
    zkevm_opcode_tester opcode_tester;

    opcode_tester.push_opcode(zkevm_opcode::PUSH0);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0x12_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH2, 0x1234_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH3, 0x123456_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH4, 0x12345678_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH5, 0x1b70726fb8_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH6, 0x1b70726fb8d3_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH7, 0x1b70726fb8d3a2_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH8, 0x1b70726fb8d3a24d_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH9, 0x1b70726fb8d3a24da9_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH10, 0x1b70726fb8d3a24da9ff_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH11, 0x1b70726fb8d3a24da9ff96_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH12, 0x1b70726fb8d3a24da9ff9647_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH13, 0x1b70726fb8d3a24da9ff964722_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH14, 0x1b70726fb8d3a24da9ff9647225a_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH15, 0x1b70726fb8d3a24da9ff9647225a18_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH16, 0x1b70726fb8d3a24da9ff9647225a1841_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH17,
                              0x1b70726fb8d3a24da9ff9647225a18412b_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH18,
                              0x1b70726fb8d3a24da9ff9647225a18412b8f_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH19,
                              0x1b70726fb8d3a24da9ff9647225a18412b8f01_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH20,
                              0x1b70726fb8d3a24da9ff9647225a18412b8f0104_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH21,
                              0x1b70726fb8d3a24da9ff9647225a18412b8f010425_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH22,
                              0x1b70726fb8d3a24da9ff9647225a18412b8f01042593_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH23,
                              0x1b70726fb8d3a24da9ff9647225a18412b8f0104259385_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH24,
                              0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH25,
                              0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d7_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH26,
                              0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73e_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH27,
                              0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc_big_uint256);
    opcode_tester.push_opcode(
        zkevm_opcode::PUSH28,
        0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc88_big_uint256);
    opcode_tester.push_opcode(
        zkevm_opcode::PUSH29,
        0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801_big_uint256);
    opcode_tester.push_opcode(
        zkevm_opcode::PUSH30,
        0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2_big_uint256);
    opcode_tester.push_opcode(
        zkevm_opcode::PUSH31,
        0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e0_big_uint256);
    opcode_tester.push_opcode(
        zkevm_opcode::PUSH32,
        0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_big_uint256);

    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 20;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 500;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 100;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 100;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("zkevm-s");
        circuits_to_run.insert("copy-s");
    }
    complex_opcode_test<big_field_type, small_field_type>(opcode_tester, max_sizes);
}
BOOST_AUTO_TEST_SUITE_END()
