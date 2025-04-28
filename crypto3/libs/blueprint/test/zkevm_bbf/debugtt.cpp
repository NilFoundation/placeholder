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

#include <cstdlib>
#include <string_view>
#include <unordered_map>
#define BOOST_TEST_MODULE blueprint_plonk_l1_wrapper_test

#include <boost/assert.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/babybear.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/fields/babybear.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/zkevm_bbf/types/hashed_buffers.hpp>
#include <nil/blueprint/zkevm_bbf/types/short_rw_operation.hpp>
#include <nil/blueprint/zkevm_bbf/types/copy_event.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_state.hpp>
#include <nil/blueprint/zkevm_bbf/loaders/debugtt.hpp>
#include <nil/blueprint/zkevm_bbf/input_generators/basic_input_generator.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/zkevm_bbf/zkevm.hpp>
#include <nil/blueprint/zkevm_bbf/zkevm_wide.hpp>
#include <nil/blueprint/zkevm_bbf/rw.hpp>
#include <nil/blueprint/zkevm_bbf/state.hpp>
#include <nil/blueprint/zkevm_bbf/copy.hpp>
#include <nil/blueprint/zkevm_bbf/bytecode.hpp>
#include <nil/blueprint/zkevm_bbf/keccak.hpp>
#include <nil/blueprint/zkevm_bbf/exp.hpp>

#include "./circuit_test_fixture.hpp"

using namespace nil::crypto3;
using namespace nil::blueprint;
using namespace nil::blueprint::bbf;

class zkEVMDebugTTTestFixture: public CircuitTestFixture {
protected:
    bool empty_machine_run = false;
    bool check_trace = false;
    bool assign = true;
public:
    zkEVMDebugTTTestFixture():CircuitTestFixture(){
        std::size_t argc = boost::unit_test::framework::master_test_suite().argc;
        auto &argv = boost::unit_test::framework::master_test_suite().argv;

        for( std::size_t i = 0; i < argc; i++ ){
            std::string arg(argv[i]);
            if(arg == "--empty-machine-run" ) {
                empty_machine_run = true;
                check_trace = false;
                assign = false;
            }
            if(arg == "--check-trace" ) {
                check_trace = true;
            }
            if(arg == "--no-assign"){
                assign = false;
            }
        }
    }

    template <typename BlueprintFieldType>
    void complex_test(
        std::string                        path,
        const l1_size_restrictions         &max_sizes
    ){
        if( empty_machine_run ){
            debugtt_block_loader loader(path);
            nil::blueprint::bbf::zkevm_basic_evm evm((abstract_block_loader*)(&loader));
            evm.execute_blocks();
            BOOST_ASSERT(evm.get_execution_status());
        }

        if( check_trace ){
            debugtt_block_loader loader(path);
            debugtt_trace_checker trace_checker(&loader);
            BOOST_ASSERT(trace_checker.get_execution_status());
        }

        if( !assign ) return;

        debugtt_block_loader loader(path);
        nil::blueprint::bbf::zkevm_basic_input_generator circuit_inputs((abstract_block_loader*)(&loader));
        BOOST_LOG_TRIVIAL(trace) << circuit_inputs.print_statistics();
        BOOST_ASSERT(circuit_inputs.get_execution_status());


        using integral_type = typename BlueprintFieldType::integral_type;
        using value_type = typename BlueprintFieldType::value_type;

        integral_type base16 = integral_type(1) << 16;

        std::size_t max_keccak_blocks = max_sizes.max_keccak_blocks;
        std::size_t max_bytecode = max_sizes.max_bytecode;
        std::size_t max_mpt = max_sizes.max_mpt;
        std::size_t max_rw = max_sizes.max_rw;
        std::size_t max_copy = max_sizes.max_copy;
        std::size_t max_zkevm_rows = max_sizes.max_zkevm_rows;
        std::size_t max_exponentiations = max_sizes.max_exponentiations;
        std::size_t max_exp_rows = max_sizes.max_exp_rows;
        std::size_t max_state = max_sizes.max_state;

        typename copy<BlueprintFieldType, GenerationStage::ASSIGNMENT>::input_type copy_assignment_input;
        copy_assignment_input.rlc_challenge = 7;
        copy_assignment_input.bytecodes = circuit_inputs.bytecodes();
        copy_assignment_input.keccak_buffers = circuit_inputs.keccaks();
        copy_assignment_input.rw_operations = circuit_inputs.short_rw_operations();
        copy_assignment_input.copy_events = circuit_inputs.copy_events();

        typename zkevm<BlueprintFieldType, GenerationStage::ASSIGNMENT>::input_type zkevm_assignment_input;
        zkevm_assignment_input.rlc_challenge = 7;
        zkevm_assignment_input.bytecodes = circuit_inputs.bytecodes();
        zkevm_assignment_input.keccak_buffers = circuit_inputs.keccaks();
        zkevm_assignment_input.rw_operations = circuit_inputs.short_rw_operations();
        zkevm_assignment_input.copy_events = circuit_inputs.copy_events();
        zkevm_assignment_input.zkevm_states = circuit_inputs.zkevm_states();
        zkevm_assignment_input.exponentiations = circuit_inputs.exponentiations();
        zkevm_assignment_input.state_operations = circuit_inputs.state_operations();

        typename zkevm_wide<BlueprintFieldType, GenerationStage::ASSIGNMENT>::input_type zkevm_wide_assignment_input;
        zkevm_wide_assignment_input.rlc_challenge = 7;
        zkevm_wide_assignment_input.bytecodes = circuit_inputs.bytecodes();
        zkevm_wide_assignment_input.keccak_buffers = circuit_inputs.keccaks();
        zkevm_wide_assignment_input.rw_operations = circuit_inputs.short_rw_operations();
        zkevm_wide_assignment_input.copy_events = circuit_inputs.copy_events();
        zkevm_wide_assignment_input.zkevm_states = circuit_inputs.zkevm_states();
        zkevm_wide_assignment_input.exponentiations = circuit_inputs.exponentiations();
        zkevm_wide_assignment_input.state_operations = circuit_inputs.state_operations();

        typename rw<BlueprintFieldType, GenerationStage::ASSIGNMENT>::input_type rw_assignment_input;
        rw_assignment_input = circuit_inputs.short_rw_operations();

        typename nil::blueprint::bbf::state_transition<BlueprintFieldType, GenerationStage::ASSIGNMENT>::input_type state_assignment_input;
        state_assignment_input.state_trace = circuit_inputs.state_operations();
        state_assignment_input.call_state_data = circuit_inputs.call_state_data();

        typename nil::blueprint::bbf::zkevm_keccak<BlueprintFieldType,nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type keccak_assignment_input;
        keccak_assignment_input.rlc_challenge = 7;
        keccak_assignment_input.private_input = circuit_inputs.keccaks();

        typename bytecode<BlueprintFieldType, GenerationStage::ASSIGNMENT>::input_type bytecode_assignment_input;
        bytecode_assignment_input.rlc_challenge = 7;
        bytecode_assignment_input.bytecodes = circuit_inputs.bytecodes();
        bytecode_assignment_input.keccak_buffers = circuit_inputs.keccaks();

        auto exp_assignment_input = circuit_inputs.exponentiations();

        bool result;

        const std::string exp_circuit = "exp";
        if (should_run_circuit(exp_circuit)) {
            BOOST_LOG_TRIVIAL(info) << std::endl << "circuit '" << exp_circuit << "'";
            result = test_bbf_component<BlueprintFieldType, nil::blueprint::bbf::exponentiation>(
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
            BOOST_LOG_TRIVIAL(info) << std::endl << "circuit '" << bytecode_circuit << "'";
            result = test_bbf_component<BlueprintFieldType, nil::blueprint::bbf::bytecode>(
                "bytecode",
                {7}, bytecode_assignment_input, max_bytecode, max_keccak_blocks
            );
            BOOST_CHECK(result);
        }

        // Max_rw
        const std::string rw_circuit = "rw";
        if (should_run_circuit(rw_circuit)) {
            BOOST_LOG_TRIVIAL(info) << std::endl << "circuit '" << rw_circuit << "'";
            result = test_bbf_component<BlueprintFieldType, nil::blueprint::bbf::rw>(
                "rw", {}, rw_assignment_input, max_rw
            );
            BOOST_CHECK(result);
        }

        // Max_state
        const std::string state_circuit = "state";
        if (should_run_circuit(state_circuit)) {
            BOOST_LOG_TRIVIAL(info) << std::endl << "circuit '" << state_circuit << "'";
            result = test_bbf_component<BlueprintFieldType, nil::blueprint::bbf::state_transition>(
                "state", {}, state_assignment_input, max_state
            );
            BOOST_CHECK(result);
        }

        // Max_rw, Max_mpt
        const std::string copy_circuit = "copy";
        if (should_run_circuit(copy_circuit)) {
            BOOST_LOG_TRIVIAL(info) << "circuit '" << copy_circuit << "'";
            result = test_bbf_component<BlueprintFieldType, nil::blueprint::bbf::copy>(
                "copy", {7}, copy_assignment_input,
                max_copy, max_rw, max_keccak_blocks, max_bytecode
            );
            BOOST_CHECK(result);
        }

        const std::string zkevm_circuit = "zkevm";
        if (should_run_circuit(zkevm_circuit)) {
            BOOST_LOG_TRIVIAL(info) << "circuit '" << zkevm_circuit << "'";
            result = test_bbf_component<BlueprintFieldType, nil::blueprint::bbf::zkevm>(
                "zkevm", {}, zkevm_assignment_input,
                max_zkevm_rows, max_copy, max_rw, max_exponentiations, max_bytecode, max_state
            );
            BOOST_CHECK(result);
        }

        const std::string zkevm_wide_circuit = "zkevm-wide";
        if (should_run_circuit(zkevm_wide_circuit)) {
            BOOST_LOG_TRIVIAL(info) << "circuit '" << zkevm_wide_circuit << "'";
            result = test_bbf_component<BlueprintFieldType, nil::blueprint::bbf::zkevm_wide>(
                "zkevm_wide", {}, zkevm_wide_assignment_input,
                max_zkevm_rows, max_copy, max_rw, max_exponentiations, max_bytecode, max_state
            );
            BOOST_CHECK(result);
        }
    }
};

// Remember that in production sizes should be preset.
// Here they are different for different tests just for fast and easy testing
BOOST_GLOBAL_FIXTURE(zkEVMGlobalFixture);
BOOST_FIXTURE_TEST_SUITE(zkevm_bbf_debugtt, zkEVMDebugTTTestFixture)

BOOST_AUTO_TEST_CASE(minimal_math) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 3;
    max_sizes.max_bytecode = 300;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 1000;
    max_sizes.max_copy = 70;
    max_sizes.max_zkevm_rows = 500;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    complex_test<field_type>("minimal_math.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(call_counter) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    complex_test<field_type>("call_counter.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(delegatecall_counter) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 4000;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1500;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    complex_test<field_type>("delegatecall.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(staticcall) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 4000;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1500;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    complex_test<field_type>("staticcall.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(counter) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    complex_test<field_type>("counter.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(keccak) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 5000;
    max_sizes.max_copy = 1000;
    max_sizes.max_zkevm_rows = 2000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    complex_test<field_type>("keccak.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(call_keccak) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 5000;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 2000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    complex_test<field_type>("call_keccak.json", max_sizes);
}


BOOST_AUTO_TEST_CASE(indexed_log) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    complex_test<field_type>("indexed_log.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(cold_sstore) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    complex_test<field_type>("cold_sstore.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(try_catch) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 5000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 8000;
    max_sizes.max_copy = 1500;
    max_sizes.max_zkevm_rows = 5000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    complex_test<field_type>("try_catch.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(try_catch2) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 5000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 8000;
    max_sizes.max_copy = 1500;
    max_sizes.max_zkevm_rows = 3000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    complex_test<field_type>("try_catch2.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(try_catch_cold) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 20;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 6000;
    max_sizes.max_copy = 1500;
    max_sizes.max_zkevm_rows = 3000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    complex_test<field_type>("try_catch_cold.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(sar) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    complex_test<field_type>("sar.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(scmp) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 2000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    complex_test<field_type>("scmp.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(exp) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 2000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 3000;
    max_sizes.max_state = 500;

    complex_test<field_type>("exp.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(modular) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 100;
    max_sizes.max_bytecode = 1000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 2000;
    max_sizes.max_copy = 70;
    max_sizes.max_zkevm_rows = 1000;
    max_sizes.max_exponentiations = 10;
    max_sizes.max_exp_rows = 100;

    complex_test<field_type>("modular.json", max_sizes);
}

// May be tested when block loader will be updated
BOOST_AUTO_TEST_CASE(precompiles, *boost::unit_test::disabled()) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 4;
    max_sizes.max_bytecode = 300;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 500;
    max_sizes.max_copy = 70;
    max_sizes.max_zkevm_rows = 500;
    max_sizes.max_exponentiations = 10;
    max_sizes.max_exp_rows = 100;

    complex_test<field_type>("precompiles.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(mem) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 25;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy = 3000;
    max_sizes.max_zkevm_rows = 4500;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;

    complex_test<field_type>("mem.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(codecopy) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 300;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 2000;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 500;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;


    complex_test<field_type>("codecopy.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(transient_storage) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 2000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 2000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;

    complex_test<field_type>("transient_storage.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(transient_storage_revert) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 2000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 2000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;

    complex_test<field_type>("transient_storage_revert.json", max_sizes);
}

BOOST_AUTO_TEST_SUITE_END()
