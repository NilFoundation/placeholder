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

#define BOOST_TEST_MODULE blueprint_zkevm_bbf_opcodes_mod_ops

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

// Remember that in production sizes should be preset.
// Here they are different for different tests just for fast and easy testing
BOOST_GLOBAL_FIXTURE(zkEVMGlobalFixture);
BOOST_FIXTURE_TEST_SUITE(zkevm_opcode_test_suite, zkEVMOpcodeTestFixture)
    using big_field_type = typename nil::crypto3::algebra::curves::alt_bn128_254::scalar_field_type;
    using small_field_type = typename algebra::fields::babybear;

BOOST_AUTO_TEST_CASE(mod_ops) {
    zkevm_opcode_tester opcode_tester;

    l1_size_restrictions max_sizes;

    opcode_tester.push_opcode(zkevm_opcode::PUSH1, hex_string_to_bytes("0x00")); // N
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")); // b
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, hex_string_to_bytes("0x02")); // a
    opcode_tester.push_opcode(zkevm_opcode::ADDMOD);
    // opcode_tester.push_opcode(zkevm_opcode::PUSH1, hex_string_to_bytes("0x00")); // N
    // opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")); // b
    // opcode_tester.push_opcode(zkevm_opcode::PUSH1, hex_string_to_bytes("0x02")); // a
    // opcode_tester.push_opcode(zkevm_opcode::MULMOD);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, hex_string_to_bytes("0x01")); // N
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")); // b
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, hex_string_to_bytes("0x02")); // a
    opcode_tester.push_opcode(zkevm_opcode::ADDMOD);
    // opcode_tester.push_opcode(zkevm_opcode::PUSH1, hex_string_to_bytes("0x01")); // N
    // opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")); // b
    // opcode_tester.push_opcode(zkevm_opcode::PUSH1, hex_string_to_bytes("0x02")); // a
    // opcode_tester.push_opcode(zkevm_opcode::MULMOD);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, hex_string_to_bytes("0x03")); // N
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")); // b
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, hex_string_to_bytes("0x02")); // a
    opcode_tester.push_opcode(zkevm_opcode::ADDMOD);
    // opcode_tester.push_opcode(zkevm_opcode::PUSH1, hex_string_to_bytes("0x03")); // N
    // opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")); // b
    // opcode_tester.push_opcode(zkevm_opcode::PUSH1, hex_string_to_bytes("0x02")); // a
    // opcode_tester.push_opcode(zkevm_opcode::MULMOD);
    opcode_tester.push_opcode(zkevm_opcode::PUSH5, hex_string_to_bytes("0x1234567890"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0x12b8f010425938504d73ebc8801e2e0161b70726fb8d3a24da9ff9647225a184"));
    opcode_tester.push_opcode(zkevm_opcode::ADDMOD);
    // opcode_tester.push_opcode(zkevm_opcode::PUSH5, hex_string_to_bytes("0x1234567890"));
    // opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016"));
    // opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0x12b8f010425938504d73ebc8801e2e0161b70726fb8d3a24da9ff9647225a184"));
    // opcode_tester.push_opcode(zkevm_opcode::MULMOD);
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xFb70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xFb70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    opcode_tester.push_opcode(zkevm_opcode::ADDMOD);    
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    opcode_tester.push_opcode(zkevm_opcode::ADDMOD);
    // opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xFb70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016"));
    // opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xFb70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016"));
    // opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    // opcode_tester.push_opcode(zkevm_opcode::MULMOD);
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH5, hex_string_to_bytes("0x1234567890"));
    opcode_tester.push_opcode(zkevm_opcode::PUSH5, hex_string_to_bytes("0x6789012345"));
    opcode_tester.push_opcode(zkevm_opcode::ADDMOD);
    // opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016"));
    // opcode_tester.push_opcode(zkevm_opcode::PUSH5, hex_string_to_bytes("0x1234567890"));
    // opcode_tester.push_opcode(zkevm_opcode::PUSH5, hex_string_to_bytes("0x6789012345"));
    // opcode_tester.push_opcode(zkevm_opcode::MULMOD);
    // opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016"));
    // opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xfffffffffffffffffffffffffffffffffffffff"));
    // opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0x200000000000000000000000000000123456788e"));
    // opcode_tester.push_opcode(zkevm_opcode::MULMOD);
    // opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016"));
    // opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xfffffffffffffffffffffffffffffffffffffff"));
    // opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0x200000000000000000000000000000123456788e"));
    // opcode_tester.push_opcode(zkevm_opcode::MULMOD);
    opcode_tester.push_opcode(zkevm_opcode::PUSH16, hex_string_to_bytes("0xffffffffffffffffffffffffffffffff")); // N
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xfffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffff")); // b
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0xffffffffffffffffffffffffffffffff00000000000000000000000000000000")); // a
    opcode_tester.push_opcode(zkevm_opcode::ADDMOD);    
    opcode_tester.push_opcode(zkevm_opcode::PUSH16, hex_string_to_bytes("0x2")); // N
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0x5")); // b
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0x5")); // a
    opcode_tester.push_opcode(zkevm_opcode::ADDMOD);
    opcode_tester.push_opcode(zkevm_opcode::PUSH16, hex_string_to_bytes("0x3")); // N
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0x10000")); // b
    opcode_tester.push_opcode(zkevm_opcode::PUSH32, hex_string_to_bytes("0x0")); // a
    opcode_tester.push_opcode(zkevm_opcode::ADDMOD);
    opcode_tester.push_opcode(zkevm_opcode::STOP);

    max_sizes.max_exp_rows = 500;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 500;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 300;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("zkevm-s");
    }
    complex_opcode_test<big_field_type, small_field_type>(opcode_tester, max_sizes);
}
BOOST_AUTO_TEST_SUITE_END()
