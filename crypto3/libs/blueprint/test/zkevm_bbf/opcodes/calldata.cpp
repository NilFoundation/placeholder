//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
// Copyright (c) 2025 Antoine Cyr <antoinecyr@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_opcodes_test_calldata

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

BOOST_AUTO_TEST_CASE(calldata) {
    zkevm_opcode_tester opcode_tester;
    l1_size_restrictions max_sizes;

    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 32);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0);
    opcode_tester.push_opcode(zkevm_opcode::CALLDATACOPY);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 8);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 31);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 32);
    opcode_tester.push_opcode(zkevm_opcode::CALLDATACOPY);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 64);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0);
    opcode_tester.push_opcode(zkevm_opcode::CALLDATACOPY);
    opcode_tester.push_opcode(zkevm_opcode::PUSH2, 800);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0);
    opcode_tester.push_opcode(zkevm_opcode::CALLDATACOPY);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0);
    opcode_tester.push_opcode(zkevm_opcode::PUSH1, 0);
    opcode_tester.push_opcode(zkevm_opcode::CALLDATACOPY);
    opcode_tester.push_opcode(zkevm_opcode::STOP);

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 5000;
    max_sizes.max_copy = 5000;
    max_sizes.max_zkevm_rows = 100;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_exponentiations = 50;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
    }
    complex_opcode_test<big_field_type, small_field_type>(opcode_tester, max_sizes);
}
BOOST_AUTO_TEST_SUITE_END()
