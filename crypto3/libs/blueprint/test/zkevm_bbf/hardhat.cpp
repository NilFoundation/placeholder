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

#include <nil/blueprint/zkevm_bbf/types/hashed_buffers.hpp>
#include <nil/blueprint/zkevm_bbf/types/rw_operation.hpp>
#include <nil/blueprint/zkevm_bbf/types/copy_event.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_state.hpp>
#include <nil/blueprint/zkevm_bbf/input_generators/hardhat_input_generator.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/zkevm_bbf/zkevm.hpp>
#include <nil/blueprint/zkevm_bbf/rw.hpp>
#include <nil/blueprint/zkevm_bbf/copy.hpp>
#include <nil/blueprint/zkevm_bbf/bytecode.hpp>
#include <nil/blueprint/zkevm_bbf/keccak.hpp>
#include <nil/blueprint/zkevm_bbf/exp.hpp>

#include "./test_l1_wrapper.hpp"

using namespace nil::crypto3;
using namespace nil::blueprint;

class zkEVMHardhatTestFixture: public BBFTestFixture {
public:
    zkEVMHardhatTestFixture():BBFTestFixture(){}

    template <typename field_type>
    void complex_test(
        const boost::property_tree::ptree  &trace,
        const l1_size_restrictions         &max_sizes
    ){
        nil::blueprint::bbf::zkevm_hardhat_input_generator circuit_inputs(trace);

        using integral_type = typename field_type::integral_type;
        using value_type = typename field_type::value_type;

        integral_type base16 = integral_type(1) << 16;

        std::size_t max_keccak_blocks = max_sizes.max_keccak_blocks;
        std::size_t max_bytecode = max_sizes.max_bytecode;
        std::size_t max_mpt = max_sizes.max_mpt;
        std::size_t max_rw = max_sizes.max_rw;
        std::size_t max_copy = max_sizes.max_copy;
        std::size_t max_zkevm_rows = max_sizes.max_zkevm_rows;
        std::size_t max_exponentiations = max_sizes.max_exponentiations;
        std::size_t max_exp_rows = max_sizes.max_exp_rows;

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
        zkevm_assignment_input.exponentiations = circuit_inputs.exponentiations();

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

        typename nil::blueprint::bbf::exponentiation<field_type,nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type exp_assignment_input;
        typename nil::blueprint::bbf::exponentiation<field_type,nil::blueprint::bbf::GenerationStage::CONSTRAINTS>::input_type exp_constraint_input;
        exp_assignment_input = circuit_inputs.exponentiations();

        // Max_rows, max_bytecode, max_rw
        result = test_bbf_component<field_type, nil::blueprint::bbf::zkevm>(
            "zkevm",
            {}, zkevm_assignment_input, zkevm_constraint_input,
            max_zkevm_rows,
            max_copy,
            max_rw,

            max_exponentiations,
            max_bytecode
        );
        BOOST_ASSERT(result);
        std::cout << std::endl;

        // Max_rw, Max_mpt
        std::cout << "RW circuit" << std::endl;
        result = test_bbf_component<field_type, nil::blueprint::bbf::rw>(
            "rw",
            {}, rw_assignment_input, rw_constraint_input, max_rw, max_mpt
        );
        BOOST_ASSERT(result);
        std::cout << std::endl;

        // Max_copy, Max_rw, Max_keccak, Max_bytecode
        result =test_bbf_component<field_type, nil::blueprint::bbf::exponentiation>(
            "exp",
            {}, exp_assignment_input, exp_constraint_input,
            max_exp_rows,
            max_exponentiations
        );
        BOOST_ASSERT(result);
        std::cout << std::endl;

        // Max_copy, Max_rw, Max_keccak, Max_bytecode
        result =test_bbf_component<field_type, nil::blueprint::bbf::copy>(
            "copy",
            {7}, copy_assignment_input, copy_constraint_input,
            max_copy, max_rw, max_keccak_blocks, max_bytecode
        );
        BOOST_ASSERT(result);
        std::cout << std::endl;

        // Max_keccak
        result = test_bbf_component<field_type, nil::blueprint::bbf::keccak>(
            "keccak",
            {}, keccak_assignment_input , keccak_constraint_input
        );
        BOOST_ASSERT(result);
        std::cout << std::endl;

        // Max_bytecode, max_bytecode
        std::cout << "Bytecode circuit" << std::endl;
        result = test_bbf_component<field_type, nil::blueprint::bbf::bytecode>(
            "bytecode",
            {7}, bytecode_assignment_input, bytecode_constraint_input, max_bytecode, max_keccak_blocks
        );
        BOOST_ASSERT(result);
        std::cout << std::endl;
    }
};

// Remember that in production sizes should be preset.
// Here they are different for different tests just for fast and easy testing
BOOST_FIXTURE_TEST_SUITE(zkevm_bbf_hardhat, zkEVMHardhatTestFixture)

BOOST_AUTO_TEST_CASE(minimal_math) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    auto pts = load_hardhat_input("minimal_math.json");
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 500;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 500;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;

    complex_test<field_type>(pts, max_sizes);
}
/*
BOOST_AUTO_TEST_CASE(small_log) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    auto [bytecodes, pts] = load_hardhat_input("small_log/");
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 500;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 500;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;

    complex_test<field_type>(bytecodes, pts, max_sizes);
}
*/
BOOST_AUTO_TEST_CASE(call_counter) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    auto pt = load_hardhat_input("call_counter.json");
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;

    complex_test<field_type>(pt, max_sizes);
}

BOOST_AUTO_TEST_CASE(delegatecall_counter) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    auto pt = load_hardhat_input("delegatecall.json");
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1500;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;

    complex_test<field_type>(pt, max_sizes);
}

BOOST_AUTO_TEST_CASE(counter) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    auto pt = load_hardhat_input("counter.json");
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;

    complex_test<field_type>(pt, max_sizes);
}

BOOST_AUTO_TEST_CASE(indexed_log) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    auto pt = load_hardhat_input("indexed_log.json");
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;

    complex_test<field_type>(pt, max_sizes);
}

BOOST_AUTO_TEST_CASE(cold_sstore) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    auto pt = load_hardhat_input("cold_sstore.json");
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;

    complex_test<field_type>(pt, max_sizes);
}
/*
BOOST_AUTO_TEST_CASE(deploy) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    auto [bytecodes, pts] = load_hardhat_input("deploy/");
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 1000;
    max_sizes.max_copy = 1000;
    max_sizes.max_zkevm_rows = 500;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;

    complex_test<field_type>(bytecodes, pts, max_sizes);
}

BOOST_AUTO_TEST_CASE(modular_operations) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    auto [bytecodes, pts] = load_hardhat_input("modular_operations/");
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 500;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 500;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;

    complex_test<field_type>(bytecodes, pts, max_sizes);
}

BOOST_AUTO_TEST_CASE(exp) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    auto [bytecodes, pts] = load_hardhat_input("exp/");
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 1000;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 2000;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_exponentiations = 50;

    complex_test<field_type>(bytecodes, pts, max_sizes);
}

BOOST_AUTO_TEST_CASE(keccak) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    auto [bytecodes, pts] = load_hardhat_input("keccak/");
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 1000;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 500;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;

    complex_test<field_type>(bytecodes, pts, max_sizes);
}

BOOST_AUTO_TEST_CASE(mstore8) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    auto [bytecodes, pts] = load_hardhat_input("mstore8/");
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 5000;
    max_sizes.max_copy = 3000;
    max_sizes.max_zkevm_rows = 4500;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;

    complex_test<field_type>(bytecodes, pts, max_sizes);
}

BOOST_AUTO_TEST_CASE(meminit) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    auto [bytecodes, pts] = load_hardhat_input("mem_init/");
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 10000;
    max_sizes.max_copy = 3000;
    max_sizes.max_zkevm_rows = 10000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;

    complex_test<field_type>(bytecodes, pts, max_sizes);
}

BOOST_AUTO_TEST_CASE(calldatacopy) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    auto [bytecodes, pts] = load_hardhat_input("calldatacopy/");
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 5000;
    max_sizes.max_copy = 3000;
    max_sizes.max_zkevm_rows = 4500;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;

    complex_test<field_type>(bytecodes, pts, max_sizes);
}

BOOST_AUTO_TEST_CASE(try_catch) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    auto [bytecodes, pts] = load_hardhat_input("try_catch/");
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 15000;
    max_sizes.max_copy = 3000;
    max_sizes.max_zkevm_rows = 10000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;

    complex_test<field_type>(bytecodes, pts, max_sizes);
}
*/
BOOST_AUTO_TEST_SUITE_END()