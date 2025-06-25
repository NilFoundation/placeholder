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

#define BOOST_TEST_MODULE blueprint_plonk_opcodes_test_codecopy

#include <boost/assert.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/babybear.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include "./opcode_test_fixture.hpp"

using namespace nil::crypto3;
using namespace nil::blueprint::bbf;

// Remember that in production sizes should be preset.
// Here they are different for different tests just for fast and easy testing
BOOST_GLOBAL_FIXTURE(zkEVMGlobalFixture);
BOOST_FIXTURE_TEST_SUITE(zkevm_opcode_test_suite, zkEVMOpcodeTestFixture)
using big_field_type =
    typename nil::crypto3::algebra::curves::alt_bn128_254::scalar_field_type;
using small_field_type = typename algebra::fields::babybear;

BOOST_AUTO_TEST_CASE(codecopy) {
    zkevm_opcode_tester opcode_tester;

    l1_size_restrictions max_sizes;

    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0x10_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0x0_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0x0_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::CODECOPY);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0x8_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0x1F_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0x0_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::CODECOPY);
    //length bigger than bytecode size
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0x90_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0x0_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0x0_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::CODECOPY);
    //length bigger than code limit
    opcode_tester.push_opcode(zkevm_opcode::PUSH4, hex_string_to_bytes("0x10001"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0x0_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0x0_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::CODECOPY);
    //offset bigger than code limit
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0x0_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH4, hex_string_to_bytes("0x10001"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0x0_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::CODECOPY);
    //dest offset is bigger than max memory
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0x0_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0x0_big_uint256);
    opcode_tester.push_opcode(zkevm_opcode::PUSH5, hex_string_to_bytes("0x20000000"));
    opcode_tester.push_opcode(zkevm_opcode::CODECOPY);
    // // huge length
    // opcode_tester.push_opcode(zkevm_opcode::PUSH32, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256);
    // opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0x0_big_uint256);
    // opcode_tester.push_opcode(zkevm_opcode::PUSH5, hex_string_to_bytes("0x20000000"));
    // opcode_tester.push_opcode(zkevm_opcode::CODECOPY);
    // // huge offset
    // opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0x5_big_uint256);
    // opcode_tester.push_opcode(zkevm_opcode::PUSH32, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256);
    // opcode_tester.push_opcode(zkevm_opcode::PUSH5, 0x0);
    // opcode_tester.push_opcode(zkevm_opcode::CODECOPY);
    // // huge dest offset
    // opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0x5_big_uint256);
    // opcode_tester.push_opcode(zkevm_opcode::PUSH5, 0x0);
    // opcode_tester.push_opcode(zkevm_opcode::PUSH32, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256);
    // opcode_tester.push_opcode(zkevm_opcode::CODECOPY);
    opcode_tester.push_opcode(zkevm_opcode::STOP);
    // test with metadata
    std::vector<std::uint8_t> metadata = {
    0xa1, 0x65, 0x62, 0x7a, 0x7a, 0x72, 0x30, 0x58, 0x20,
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x64, 0x73, 0x6f, 0x6c, 0x63, 0x43, 0x00, 0x08,
    0x11, 0x00, 0x33
    };
    opcode_tester.push_metadata(metadata);

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 500;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 700;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 300;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_exponentiations = 50;

    if (circuits_to_run.empty()) {
        // circuits_to_run.insert("zkevm");
        // circuits_to_run.insert("zkevm-wide");
        // circuits_to_run.insert("rw");
        // circuits_to_run.insert("bytecode");
        // circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("zkevm-s");
        circuits_to_run.insert("rw-s");
        // circuits_to_run.insert("copy-s");
    }
    complex_opcode_test<big_field_type, small_field_type>(opcode_tester, max_sizes);
}
BOOST_AUTO_TEST_SUITE_END()
