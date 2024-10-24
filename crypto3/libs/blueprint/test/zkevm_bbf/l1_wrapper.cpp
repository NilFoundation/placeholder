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

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_l1_wrapper_test) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    using integral_type = typename field_type::integral_type;
    using value_type = typename field_type::value_type;

    nil::crypto3::random::algebraic_engine<field_type> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);

    integral_type base16 = integral_type(1) << 16;

    nil::blueprint::bbf::zkevm<field_type,nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type zkevm_assignment_input;
    nil::blueprint::bbf::zkevm<field_type,nil::blueprint::bbf::GenerationStage::CONSTRAINTS>::input_type zkevm_constraint_input;
    zkevm_assignment_input.b = 18 * 18;

    nil::blueprint::bbf::keccak<field_type,nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type keccak_assignment_input;
    nil::blueprint::bbf::keccak<field_type,nil::blueprint::bbf::GenerationStage::CONSTRAINTS>::input_type keccak_constraint_input;
    keccak_assignment_input.private_input = 12345;

    std::size_t max_keccak_blocks = 10;
    std::size_t max_bytecode = 3000;
    std::size_t max_mpt = 100;
    std::size_t max_rw = 3000;
    std::size_t max_copy_size = 3000;
    std::size_t max_zkevm_rows = 100;

    test_l1_wrapper<field_type, nil::blueprint::bbf::zkevm>(
        {}, zkevm_assignment_input, zkevm_constraint_input, max_zkevm_rows, max_bytecode, max_rw
    );  // Max_rows, max_bytecode, max_rw
    test_l1_wrapper<field_type, nil::blueprint::bbf::rw>({}, 0, 1, max_rw, max_mpt);                 // Max_rw, Max_mpt
    test_l1_wrapper<field_type, nil::blueprint::bbf::bytecode>({}, 0, 1, max_bytecode, max_mpt);     // Max_bytecode, max_bytecode
    test_l1_wrapper<field_type, nil::blueprint::bbf::copy>({}, 0, 1);                                // Max_copy, Max_rw, Max_keccak
    test_l1_wrapper<field_type, nil::blueprint::bbf::keccak>(
        {}, keccak_assignment_input , keccak_constraint_input
    );  // Max_keccak
}

BOOST_AUTO_TEST_SUITE_END()