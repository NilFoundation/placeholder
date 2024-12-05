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

#define BOOST_TEST_MODULE blueprint_plonk_copy_test

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
#include <nil/blueprint/bbf/l1_wrapper.hpp>
#include <nil/blueprint/zkevm_bbf/copy.hpp>
#include <nil/blueprint/zkevm_bbf/zkevm.hpp>
#include <nil/blueprint/zkevm_bbf/bytecode.hpp>
#include <nil/blueprint/zkevm_bbf/keccak.hpp>
#include <nil/blueprint/zkevm_bbf/rw.hpp>
#include <nil/blueprint/zkevm_bbf/input_generators/hardhat_input_generator.hpp>

#include "./test_l1_wrapper.hpp"

using namespace nil::crypto3;
using namespace nil::blueprint;

template <typename field_type>
void test_zkevm_copy(
    const std::vector<std::vector<std::uint8_t>>    &bytecodes,
    const std::vector<boost::property_tree::ptree>  &traces,
    const l1_size_restrictions                      &max_sizes
){
    const auto &pt = traces[0];
    const auto &bytecode0 = bytecodes[0];

    nil::blueprint::bbf::zkevm_hardhat_input_generator circuit_inputs(bytecodes, traces);

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


    // Max_copy, Max_rw, Max_keccak, Max_bytecode
    bool result = test_l1_wrapper<field_type, nil::blueprint::bbf::copy>(
        {7}, copy_assignment_input, copy_constraint_input,
        max_copy, max_rw, max_keccak_blocks, max_bytecode
    );
    BOOST_ASSERT(result);
    std::cout << std::endl;
}


BOOST_AUTO_TEST_SUITE(blueprint_bbf_copy)
    using field_type = typename algebra::curves::pallas::base_field_type;
    using integral_type = typename field_type::integral_type;
    using value_type = typename field_type::value_type;
BOOST_AUTO_TEST_CASE(small_storage_contract){
    using field_type = typename algebra::curves::pallas::base_field_type;
    std::cout << "../crypto3/libs/blueprint/test/zkevm/data/small_stack_storage/" << std::endl;
    auto [bytecodes, pts] = load_hardhat_input("small_stack_storage/");

    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 500;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 500;

    test_zkevm_copy<field_type>(bytecodes, pts, max_sizes);
}

BOOST_AUTO_TEST_CASE(mstore8_contract){
    using field_type = typename algebra::curves::pallas::base_field_type;
    std::cout << "../crypto3/libs/blueprint/test/zkevm/data/mstore8/" << std::endl;
    auto [bytecodes, pts] = load_hardhat_input("mstore8/");
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 5000;
    max_sizes.max_copy = 3000;
    max_sizes.max_zkevm_rows = 4500;

    test_zkevm_copy<field_type>(bytecodes, pts, max_sizes);
}

BOOST_AUTO_TEST_CASE(meminit_contract){
    using field_type = typename algebra::curves::pallas::base_field_type;
    std::cout << "../crypto3/libs/blueprint/test/zkevm/data/meminit/" << std::endl;
    auto [bytecodes, pts] = load_hardhat_input("mem_init/");
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 10000;
    max_sizes.max_copy = 3000;
    max_sizes.max_zkevm_rows = 4500;

    test_zkevm_copy<field_type>(bytecodes, pts, max_sizes);
}

BOOST_AUTO_TEST_CASE(calldatacopy_contract){
    using field_type = typename algebra::curves::pallas::base_field_type;
    std::cout << "../crypto3/libs/blueprint/test/zkevm/data/calldatacopy/" << std::endl;
    auto [bytecodes, pts] = load_hardhat_input("calldatacopy/");
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 10000;
    max_sizes.max_copy = 3000;
    max_sizes.max_zkevm_rows = 4500;

    test_zkevm_copy<field_type>(bytecodes, pts, max_sizes);
}

BOOST_AUTO_TEST_CASE(keccak_contract){
    using field_type = typename algebra::curves::pallas::base_field_type;
    std::cout << "../crypto3/libs/blueprint/test/zkevm/data/keccak/" << std::endl;
    auto [bytecodes, pts] = load_hardhat_input("keccak/");
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 10000;
    max_sizes.max_copy = 3000;
    max_sizes.max_zkevm_rows = 4500;

    test_zkevm_copy<field_type>(bytecodes, pts, max_sizes);
}
BOOST_AUTO_TEST_SUITE_END()
