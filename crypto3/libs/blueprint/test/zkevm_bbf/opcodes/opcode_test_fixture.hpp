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

#pragma once

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/babybear.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/babybear.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/zkevm_bbf/loaders/opcode_tester.hpp>
#include <nil/blueprint/zkevm_bbf/input_generators/basic_input_generator.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>

#include <nil/blueprint/zkevm_bbf/big_field/circuits/bytecode.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/circuits/copy.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/circuits/exp.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/circuits/keccak.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/circuits/rw.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/circuits/state.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/circuits/zkevm.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/circuits/zkevm_wide.hpp>

#include <nil/blueprint/zkevm_bbf/small_field/circuits/rw.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/circuits/bytecode.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/circuits/zkevm.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/circuits/copy.hpp>

#include "../circuit_test_fixture.hpp"

using namespace nil::crypto3;
using namespace nil::blueprint;
using namespace nil::blueprint::bbf;

class zkEVMOpcodeTestFixture: public CircuitTestFixture {
public:
    template<typename BigFieldType, typename SmallFieldType>
    void complex_opcode_test(
        const zkevm_opcode_tester                       &opcode_tester,
        const l1_size_restrictions                      &max_sizes
    ){
        nil::blueprint::bbf::opcode_tester_block_loader loader(opcode_tester);
        nil::blueprint::bbf::zkevm_basic_input_generator circuit_inputs((abstract_block_loader*)(&loader));
        BOOST_LOG_TRIVIAL(info) << circuit_inputs.print_statistics();
        BOOST_ASSERT(circuit_inputs.get_execution_status());

        using integral_type = typename BigFieldType::integral_type;
        using value_type = typename BigFieldType::value_type;

        integral_type base16 = integral_type(1) << 16;

        std::size_t max_keccak_blocks = max_sizes.max_keccak_blocks;
        std::size_t max_bytecode = max_sizes.max_bytecode;
        std::size_t max_mpt = max_sizes.max_mpt;
        std::size_t max_rw = max_sizes.max_rw;
        std::size_t max_copy = max_sizes.max_copy;
        std::size_t max_copy_events = max_sizes.max_copy_events;
        std::size_t max_zkevm_rows = max_sizes.max_zkevm_rows;
        std::size_t max_zkevm_small_field_rows = max_sizes.max_zkevm_small_field_rows;
        std::size_t max_exponentiations = max_sizes.max_exponentiations;
        std::size_t max_exp_rows = max_sizes.max_exp_rows;
        std::size_t max_state = max_sizes.max_state;
        std::size_t max_bytecodes_amount = max_sizes.max_bytecodes_amount;

        std::size_t instances_rw_8 = max_sizes.instances_rw_8;
        std::size_t instances_rw_256 = max_sizes.instances_rw_256;
        std::size_t instances_copy = max_sizes.instances_copy;

        typename zkevm_big_field::zkevm_keccak<BigFieldType,nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type keccak_assignment_input;
        keccak_assignment_input.rlc_challenge = 7;
        keccak_assignment_input.private_input = circuit_inputs.keccaks();

        bool result;

        const std::string exp_circuit = "exp";
        if (should_run_circuit(exp_circuit)) {
            auto exp_assignment_input = circuit_inputs.exponentiations();
            result = test_bbf_component<BigFieldType, zkevm_big_field::exponentiation>(
                "exp",
                {}, exp_assignment_input,
                max_exp_rows,
                max_exponentiations
            );
            BOOST_CHECK(result);
        }

        // Max_bytecode, max_bytecode
        const std::string bytecode_circuit = "bytecode";
        if (should_run_circuit(bytecode_circuit)) {
            BOOST_LOG_TRIVIAL(info) << "circuit '" << bytecode_circuit << "'";
            typename zkevm_big_field::bytecode<BigFieldType, GenerationStage::ASSIGNMENT>::input_type bytecode_assignment_input;
            bytecode_assignment_input.rlc_challenge = 7;
            bytecode_assignment_input.bytecodes = circuit_inputs.bytecodes();
            bytecode_assignment_input.keccak_buffers = circuit_inputs.keccaks();

            result = test_bbf_component<BigFieldType, zkevm_big_field::bytecode>(
                "bytecode",
                {7}, bytecode_assignment_input, max_bytecode, max_keccak_blocks
            );
            BOOST_CHECK(result);
        }

        // Max_rw, Max_mpt
        const std::string rw_circuit = "rw";
        if (should_run_circuit(rw_circuit)) {
            BOOST_LOG_TRIVIAL(info) << "circuit '" << rw_circuit << "'";
            typename zkevm_big_field::rw<BigFieldType, GenerationStage::ASSIGNMENT>::input_type rw_assignment_input;
            rw_assignment_input.rw_trace = circuit_inputs.short_rw_operations();
            rw_assignment_input.timeline = circuit_inputs.timeline();
            rw_assignment_input.state_trace = circuit_inputs.state_operations();

            result = test_bbf_component<BigFieldType, zkevm_big_field::rw>(
                "rw", {}, rw_assignment_input, max_rw, max_state
            );
            BOOST_CHECK(result);
        }

        // Max_state
        const std::string state_circuit = "state";
        if (should_run_circuit(state_circuit)) {
            BOOST_LOG_TRIVIAL(info) << std::endl << "circuit '" << state_circuit << "'";
            typename zkevm_big_field::state_transition<BigFieldType, GenerationStage::ASSIGNMENT>::input_type state_assignment_input;
            state_assignment_input.state_trace = circuit_inputs.state_operations();
            state_assignment_input.call_state_data = circuit_inputs.call_state_data();

            result = test_bbf_component<BigFieldType, zkevm_big_field::state_transition>(
                "state", {}, state_assignment_input, max_state
            );
            BOOST_CHECK(result);
        }

        // Max_rw, Max_mpt
        const std::string copy_circuit = "copy";
        if (should_run_circuit(copy_circuit)) {
            BOOST_LOG_TRIVIAL(info) << "circuit '" << copy_circuit << "'";
            typename zkevm_big_field::copy<BigFieldType, GenerationStage::ASSIGNMENT>::input_type copy_assignment_input;
            copy_assignment_input.rlc_challenge = 7;
            copy_assignment_input.bytecodes = circuit_inputs.bytecodes();
            copy_assignment_input.keccak_buffers = circuit_inputs.keccaks();
            copy_assignment_input.rw_operations = circuit_inputs.short_rw_operations();
            copy_assignment_input.copy_events = circuit_inputs.copy_events();

            result = test_bbf_component<BigFieldType, zkevm_big_field::copy>(
                "copy", {7}, copy_assignment_input,
                max_copy, max_rw, max_keccak_blocks, max_bytecode
            );
            BOOST_CHECK(result);
        }

        const std::string zkevm_circuit = "zkevm";
        if (should_run_circuit(zkevm_circuit)) {
            BOOST_LOG_TRIVIAL(info) << "circuit '" << zkevm_circuit << "'";
            typename zkevm_big_field::zkevm<BigFieldType, GenerationStage::ASSIGNMENT>::input_type zkevm_assignment_input;
            zkevm_assignment_input.rlc_challenge = 7;
            zkevm_assignment_input.bytecodes = circuit_inputs.bytecodes();
            zkevm_assignment_input.keccak_buffers = circuit_inputs.keccaks();
            zkevm_assignment_input.rw_operations = circuit_inputs.short_rw_operations();
            zkevm_assignment_input.copy_events = circuit_inputs.copy_events();
            zkevm_assignment_input.zkevm_states = circuit_inputs.zkevm_states();
            zkevm_assignment_input.exponentiations = circuit_inputs.exponentiations();
            zkevm_assignment_input.state_operations = circuit_inputs.state_operations();

            result = test_bbf_component<BigFieldType, zkevm_big_field::zkevm>(
                "zkevm", {}, zkevm_assignment_input,
                max_zkevm_rows, max_copy, max_rw, max_exponentiations, max_bytecode, max_state
            );
            BOOST_CHECK(result);
        }

        const std::string zkevm_wide_circuit = "zkevm-wide";
        if (should_run_circuit(zkevm_wide_circuit)) {
            BOOST_LOG_TRIVIAL(info) << "circuit '" << zkevm_wide_circuit << "'";
            typename zkevm_big_field::zkevm_wide<BigFieldType, GenerationStage::ASSIGNMENT>::input_type zkevm_wide_assignment_input;
            zkevm_wide_assignment_input.rlc_challenge = 7;
            zkevm_wide_assignment_input.bytecodes = circuit_inputs.bytecodes();
            zkevm_wide_assignment_input.keccak_buffers = circuit_inputs.keccaks();
            zkevm_wide_assignment_input.rw_operations = circuit_inputs.short_rw_operations();
            zkevm_wide_assignment_input.copy_events = circuit_inputs.copy_events();
            zkevm_wide_assignment_input.zkevm_states = circuit_inputs.zkevm_states();
            zkevm_wide_assignment_input.exponentiations = circuit_inputs.exponentiations();
            zkevm_wide_assignment_input.state_operations = circuit_inputs.state_operations();

            result = test_bbf_component<BigFieldType, zkevm_big_field::zkevm_wide>(
                "zkevm_wide", {}, zkevm_wide_assignment_input,
                max_zkevm_rows, max_copy, max_rw, max_exponentiations, max_bytecode, max_state
            );
            BOOST_CHECK(result);
        }

        // Small_field

        // Max_rw, max_state
        const std::string small_rw_circuit = "rw-s";
        if (should_run_circuit(small_rw_circuit)) {
            BOOST_LOG_TRIVIAL(info) << std::endl << "circuit '" << small_rw_circuit << "'";
            typename zkevm_small_field::rw<SmallFieldType, GenerationStage::ASSIGNMENT>::input_type rw_assignment_input;
            rw_assignment_input.rw_trace = circuit_inputs.short_rw_operations();
            rw_assignment_input.timeline = circuit_inputs.timeline();
            rw_assignment_input.state_trace = circuit_inputs.state_operations();

            result = test_bbf_component<SmallFieldType, nil::blueprint::bbf::zkevm_small_field::rw>(
                "rw-s", {}, rw_assignment_input, max_rw, instances_rw_8, instances_rw_256, max_state
            );
            BOOST_CHECK(result);
        }

        const std::string small_bytecode_circuit = "bytecode-s";
        if (should_run_circuit(small_bytecode_circuit)) {
            BOOST_LOG_TRIVIAL(info) << std::endl << "circuit '" << small_bytecode_circuit << "'";
            typename zkevm_small_field::bytecode<SmallFieldType, GenerationStage::ASSIGNMENT>::input_type bytecode_assignment_input;
            bytecode_assignment_input.rlc_challenge = 7;
            bytecode_assignment_input.bytecodes = circuit_inputs.bytecodes();
            bytecode_assignment_input.keccak_buffers = circuit_inputs.keccaks();

            result = test_bbf_component<SmallFieldType, nil::blueprint::bbf::zkevm_small_field::bytecode>(
                "bytecode-s",
                {7}, bytecode_assignment_input, max_bytecode, max_keccak_blocks, max_bytecodes_amount
            );
            BOOST_CHECK(result);
        }

        const std::string zkevm_s_circuit = "zkevm-s";
        if (should_run_circuit(zkevm_s_circuit)) {
            BOOST_LOG_TRIVIAL(info) << "circuit '" << zkevm_s_circuit << "'";
            typename zkevm_small_field::zkevm<SmallFieldType, GenerationStage::ASSIGNMENT>::input_type zkevm_assignment_input;
            zkevm_assignment_input.rlc_challenge = 7;
            zkevm_assignment_input.bytecodes = circuit_inputs.bytecodes();
            // zkevm_assignment_input.keccak_buffers = circuit_inputs.keccaks();
            zkevm_assignment_input.rw_operations = circuit_inputs.short_rw_operations();
            zkevm_assignment_input.copy_events = circuit_inputs.copy_events();
            zkevm_assignment_input.zkevm_states = circuit_inputs.zkevm_states();
            // zkevm_assignment_input.exponentiations = circuit_inputs.exponentiations();
            // zkevm_assignment_input.state_operations = circuit_inputs.state_operations();

            result = test_bbf_component<SmallFieldType, nil::blueprint::bbf::zkevm_small_field::zkevm>(
                "zkevm-s", {},
                zkevm_assignment_input,
                max_zkevm_rows,
                max_copy_events,
                instances_rw_8,
                instances_rw_256,
                max_exponentiations,
                max_bytecode,
                max_state
            );
            BOOST_CHECK(result);
        }

        const std::string copy_s_circuit = "copy-s";
        if (should_run_circuit(copy_s_circuit)) {
            BOOST_LOG_TRIVIAL(info) << "circuit '" << copy_s_circuit << "'";
            typename zkevm_small_field::copy<SmallFieldType, GenerationStage::ASSIGNMENT>::input_type copy_assignment_input;
            copy_assignment_input.rlc_challenge = 7;
            copy_assignment_input.bytecodes = circuit_inputs.bytecodes();
            copy_assignment_input.keccak_buffers = circuit_inputs.keccaks();
            copy_assignment_input.rw_operations = circuit_inputs.short_rw_operations();
            copy_assignment_input.copy_events = circuit_inputs.copy_events();

            result = test_bbf_component<SmallFieldType, nil::blueprint::bbf::zkevm_small_field::copy>(
                "copy-s", {7}, copy_assignment_input,
                max_copy_events,
                max_copy,
                instances_copy,
                max_rw,
                instances_rw_8,
                max_keccak_blocks,
                max_bytecode
            );
            BOOST_CHECK(result);
        }
    }
};
