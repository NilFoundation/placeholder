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
#define BOOST_TEST_MODULE blueprint_plonk_debugtt_test

#include <cstdlib>
#include <string_view>
#include <unordered_map>

#include <boost/algorithm/string.hpp>
#include <boost/assert.hpp>
#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/babybear.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/goldilocks.hpp>
#include <nil/crypto3/algebra/fields/babybear.hpp>
#include <nil/crypto3/algebra/fields/goldilocks.hpp>
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

#include <nil/blueprint/zkevm_bbf/big_field/circuits/zkevm.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/circuits/zkevm_wide.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/circuits/rw.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/circuits/state.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/circuits/copy.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/circuits/bytecode.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/circuits/keccak.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/circuits/exp.hpp>

#include <nil/blueprint/zkevm_bbf/small_field/circuits/rw.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/circuits/bytecode.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/circuits/copy.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/circuits/zkevm.hpp>

#include "./circuit_test_fixture.hpp"

using namespace nil::crypto3;
using namespace nil::blueprint;
using namespace nil::blueprint::bbf;

class zkEVMDebugTTTestFixture: public CircuitTestFixture {
  protected:
    bool empty_machine_run = false;
    bool check_trace = true;
    bool assign = true;
    bool force_incompatibe_circuits_for_field = false;

  public:
    zkEVMDebugTTTestFixture() {
        std::size_t argc = boost::unit_test::framework::master_test_suite().argc;
        auto &argv = boost::unit_test::framework::master_test_suite().argv;

        for (std::size_t i = 0; i < argc; i++) {
            std::string arg(argv[i]);
            if (arg == "--empty-machine-run") {
                empty_machine_run = true;
                check_trace = false;
                assign = false;
            }
            if (arg == "--no-check-trace") {
                check_trace = false;
            }
            if (arg == "--no-assign") {
                assign = false;
            }
            if (arg == "--force-incompatible-circuits-for-field") {
                force_incompatibe_circuits_for_field = true;
            }
        }
    }

    template<typename FieldType>
    void complex_test(std::string path, const l1_size_restrictions &max_sizes) {
        using SmallFieldType = typename FieldType::small_subfield;
        constexpr bool BIG_FIELD = SmallFieldType::modulus_bits >= 250;

        if (empty_machine_run) {
            debugtt_block_loader loader(path);
            nil::blueprint::bbf::zkevm_basic_evm evm((abstract_block_loader *)(&loader));
            evm.execute_blocks();
            BOOST_ASSERT(evm.get_execution_status());
        }

        if (check_trace) {
            debugtt_block_loader loader(path);
            debugtt_trace_checker trace_checker(&loader);
            BOOST_ASSERT(trace_checker.get_execution_status());
        }

        if (!assign) return;

        debugtt_block_loader loader(path);
        nil::blueprint::bbf::zkevm_basic_input_generator circuit_inputs(
            (abstract_block_loader *)(&loader));
        BOOST_LOG_TRIVIAL(trace) << circuit_inputs.print_statistics();
        BOOST_ASSERT(circuit_inputs.get_execution_status());

        using integral_type = typename FieldType::integral_type;
        using value_type = typename FieldType::value_type;

        integral_type base16 = integral_type(1) << 16;

        std::size_t max_keccak_blocks = max_sizes.max_keccak_blocks;
        std::size_t max_bytecode = max_sizes.max_bytecode;
        std::size_t max_mpt = max_sizes.max_mpt;
        std::size_t max_rw = max_sizes.max_rw;
        std::size_t max_copy = max_sizes.max_copy;
        std::size_t max_copy_events = max_sizes.max_copy_events;
        std::size_t max_zkevm_rows = max_sizes.max_zkevm_rows;
        std::size_t max_exponentiations = max_sizes.max_exponentiations;
        std::size_t max_exp_rows = max_sizes.max_exp_rows;
        std::size_t max_state = max_sizes.max_state;
        std::size_t max_bytecodes_amount = max_sizes.max_bytecodes_amount;

        std::size_t instances_rw_8 = max_sizes.instances_rw_8;
        std::size_t instances_rw_256 = max_sizes.instances_rw_256;

        typename nil::blueprint::bbf::zkevm_big_field::zkevm_keccak<
            SmallFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type
            keccak_assignment_input;
        keccak_assignment_input.rlc_challenge = 7;
        keccak_assignment_input.private_input = circuit_inputs.keccaks();

        bool result;

        if (BIG_FIELD || force_incompatibe_circuits_for_field) {
            const std::string exp_circuit = "exp";
            if (should_run_circuit(exp_circuit)) {
                BOOST_LOG_TRIVIAL(info) << std::endl << "circuit '" << exp_circuit << "'";
                auto exp_assignment_input = circuit_inputs.exponentiations();
                result = test_bbf_component<
                    FieldType, nil::blueprint::bbf::zkevm_big_field::exponentiation>(
                    "exp", {}, exp_assignment_input, max_exp_rows, max_exponentiations);
                BOOST_CHECK(result);
            }

            // Max_bytecode, max_bytecode
            const std::string bytecode_circuit = "bytecode";
            if (should_run_circuit(bytecode_circuit)) {
                BOOST_LOG_TRIVIAL(info) << std::endl
                                        << "circuit '" << bytecode_circuit << "'";
                typename zkevm_big_field::bytecode<
                    SmallFieldType, GenerationStage::ASSIGNMENT>::input_type
                    bytecode_assignment_input;
                bytecode_assignment_input.rlc_challenge = 7;
                bytecode_assignment_input.bytecodes = circuit_inputs.bytecodes();
                bytecode_assignment_input.keccak_buffers = circuit_inputs.keccaks();

                result =
                    test_bbf_component<FieldType,
                                       nil::blueprint::bbf::zkevm_big_field::bytecode>(
                        "bytecode", {7}, bytecode_assignment_input, max_bytecode,
                        max_keccak_blocks);
                BOOST_CHECK(result);
            }

            // Max_rw, max_state
            const std::string rw_circuit = "rw";
            if (should_run_circuit(rw_circuit)) {
                BOOST_LOG_TRIVIAL(info) << std::endl << "circuit '" << rw_circuit << "'";
                typename zkevm_big_field::rw<SmallFieldType,
                                             GenerationStage::ASSIGNMENT>::input_type
                    rw_assignment_input;
                rw_assignment_input.rw_trace = circuit_inputs.short_rw_operations();
                rw_assignment_input.timeline = circuit_inputs.timeline();
                rw_assignment_input.state_trace = circuit_inputs.state_operations();

                result = test_bbf_component<FieldType,
                                            nil::blueprint::bbf::zkevm_big_field::rw>(
                    "rw", {}, rw_assignment_input, max_rw, max_state);
                BOOST_CHECK(result);
            }

            // Max_state
            const std::string state_circuit = "state";
            if (should_run_circuit(state_circuit)) {
                BOOST_LOG_TRIVIAL(info) << std::endl
                                        << "circuit '" << state_circuit << "'";
                typename zkevm_big_field::state_transition<
                    SmallFieldType, GenerationStage::ASSIGNMENT>::input_type
                    state_assignment_input;
                state_assignment_input.state_trace = circuit_inputs.state_operations();
                state_assignment_input.call_state_data = circuit_inputs.call_state_data();

                result = test_bbf_component<
                    FieldType, nil::blueprint::bbf::zkevm_big_field::state_transition>(
                    "state", {}, state_assignment_input, max_state);
                BOOST_CHECK(result);
            }

            // Max_rw, Max_mpt
            const std::string copy_circuit = "copy";
            if (should_run_circuit(copy_circuit)) {
                BOOST_LOG_TRIVIAL(info) << "circuit '" << copy_circuit << "'";
                typename zkevm_big_field::copy<SmallFieldType,
                                               GenerationStage::ASSIGNMENT>::input_type
                    copy_assignment_input;
                copy_assignment_input.rlc_challenge = 7;
                copy_assignment_input.bytecodes = circuit_inputs.bytecodes();
                copy_assignment_input.keccak_buffers = circuit_inputs.keccaks();
                copy_assignment_input.rw_operations =
                    circuit_inputs.short_rw_operations();
                copy_assignment_input.copy_events = circuit_inputs.copy_events();

                result = test_bbf_component<FieldType,
                                            nil::blueprint::bbf::zkevm_big_field::copy>(
                    "copy", {7}, copy_assignment_input, max_copy, max_rw,
                    max_keccak_blocks, max_bytecode);
                BOOST_CHECK(result);
            }

            const std::string zkevm_circuit = "zkevm";
            if (should_run_circuit(zkevm_circuit)) {
                BOOST_LOG_TRIVIAL(info) << "circuit '" << zkevm_circuit << "'";
                typename zkevm_big_field::zkevm<SmallFieldType,
                                                GenerationStage::ASSIGNMENT>::input_type
                    zkevm_assignment_input;
                zkevm_assignment_input.rlc_challenge = 7;
                zkevm_assignment_input.bytecodes = circuit_inputs.bytecodes();
                zkevm_assignment_input.keccak_buffers = circuit_inputs.keccaks();
                zkevm_assignment_input.rw_operations =
                    circuit_inputs.short_rw_operations();
                zkevm_assignment_input.copy_events = circuit_inputs.copy_events();
                zkevm_assignment_input.zkevm_states = circuit_inputs.zkevm_states();
                zkevm_assignment_input.exponentiations = circuit_inputs.exponentiations();
                zkevm_assignment_input.state_operations =
                    circuit_inputs.state_operations();

                result = test_bbf_component<FieldType,
                                            nil::blueprint::bbf::zkevm_big_field::zkevm>(
                    "zkevm", {}, zkevm_assignment_input, max_zkevm_rows, max_copy, max_rw,
                    max_exponentiations, max_bytecode, max_state);
                BOOST_CHECK(result);
            }

            const std::string zkevm_wide_circuit = "zkevm-wide";
            if (should_run_circuit(zkevm_wide_circuit)) {
                BOOST_LOG_TRIVIAL(info) << "circuit '" << zkevm_wide_circuit << "'";
                typename zkevm_big_field::zkevm_wide<
                    SmallFieldType, GenerationStage::ASSIGNMENT>::input_type
                    zkevm_wide_assignment_input;
                zkevm_wide_assignment_input.rlc_challenge = 7;
                zkevm_wide_assignment_input.bytecodes = circuit_inputs.bytecodes();
                zkevm_wide_assignment_input.keccak_buffers = circuit_inputs.keccaks();
                zkevm_wide_assignment_input.rw_operations =
                    circuit_inputs.short_rw_operations();
                zkevm_wide_assignment_input.copy_events = circuit_inputs.copy_events();
                zkevm_wide_assignment_input.zkevm_states = circuit_inputs.zkevm_states();
                zkevm_wide_assignment_input.exponentiations =
                    circuit_inputs.exponentiations();
                zkevm_wide_assignment_input.state_operations =
                    circuit_inputs.state_operations();

                result =
                    test_bbf_component<FieldType,
                                       nil::blueprint::bbf::zkevm_big_field::zkevm_wide>(
                        "zkevm_wide", {}, zkevm_wide_assignment_input, max_zkevm_rows,
                        max_copy, max_rw, max_exponentiations, max_bytecode, max_state);
                BOOST_CHECK(result);
            }
        }

        // Circuits adapted to small fields (31-bit)

        // Max_rw, max_state
        const std::string small_rw_circuit = "rw-s";
        if (should_run_circuit(small_rw_circuit)) {
            BOOST_LOG_TRIVIAL(info) << std::endl << "circuit '" << small_rw_circuit << "'";
            typename zkevm_small_field::rw<SmallFieldType,
                                           GenerationStage::ASSIGNMENT>::input_type
                rw_assignment_input;
            rw_assignment_input.rw_trace = circuit_inputs.short_rw_operations();
            rw_assignment_input.timeline = circuit_inputs.timeline();
            rw_assignment_input.state_trace = circuit_inputs.state_operations();

            result =
                test_bbf_component<FieldType, nil::blueprint::bbf::zkevm_small_field::rw>(
                    "rw-s", {}, rw_assignment_input, max_rw, instances_rw_8,
                    instances_rw_256, max_state);
            BOOST_CHECK(result);
        }

        const std::string small_bytecode_circuit = "bytecode-s";
        if (should_run_circuit(small_bytecode_circuit)) {
            BOOST_LOG_TRIVIAL(info) << std::endl
                                    << "circuit '" << small_bytecode_circuit << "'";
            typename zkevm_small_field::bytecode<SmallFieldType,
                                                 GenerationStage::ASSIGNMENT>::input_type
                bytecode_assignment_input;
            bytecode_assignment_input.rlc_challenge = 7;
            bytecode_assignment_input.bytecodes = circuit_inputs.bytecodes();
            bytecode_assignment_input.keccak_buffers = circuit_inputs.keccaks();

            result = test_bbf_component<FieldType,
                                        nil::blueprint::bbf::zkevm_small_field::bytecode>(
                "bytecode-s", {7}, bytecode_assignment_input, max_bytecode,
                max_keccak_blocks, max_bytecodes_amount);
            BOOST_CHECK(result);
        }

        const std::string zkevm_s_circuit = "zkevm-s";
        if (should_run_circuit(zkevm_s_circuit)) {
            BOOST_LOG_TRIVIAL(info) << "circuit '" << zkevm_s_circuit << "'";
            typename zkevm_small_field::zkevm<SmallFieldType,
                                              GenerationStage::ASSIGNMENT>::input_type
                zkevm_assignment_input;
            zkevm_assignment_input.rlc_challenge = 7;
            zkevm_assignment_input.bytecodes = circuit_inputs.bytecodes();
            // zkevm_assignment_input.keccak_buffers = circuit_inputs.keccaks();
            zkevm_assignment_input.rw_operations = circuit_inputs.short_rw_operations();
            zkevm_assignment_input.copy_events = circuit_inputs.copy_events();
            zkevm_assignment_input.zkevm_states = circuit_inputs.zkevm_states();
            // zkevm_assignment_input.exponentiations = circuit_inputs.exponentiations();
            // zkevm_assignment_input.state_operations = circuit_inputs.state_operations();

            result = test_bbf_component<FieldType,
                                        nil::blueprint::bbf::zkevm_small_field::zkevm>(
                "zkevm-s", {}, zkevm_assignment_input, max_zkevm_rows, max_copy_events,
                max_rw, max_exponentiations, max_bytecode, max_state);
            BOOST_CHECK(result);
        }

        const std::string copy_s_circuit = "copy-s";
        if (should_run_circuit(copy_s_circuit)) {
            BOOST_LOG_TRIVIAL(info) << "circuit '" << copy_s_circuit << "'";
            typename zkevm_small_field::copy<SmallFieldType,
                                             GenerationStage::ASSIGNMENT>::input_type
                copy_assignment_input;
            copy_assignment_input.rlc_challenge = 7;
            copy_assignment_input.bytecodes = circuit_inputs.bytecodes();
            copy_assignment_input.keccak_buffers = circuit_inputs.keccaks();
            copy_assignment_input.rw_operations = circuit_inputs.short_rw_operations();
            copy_assignment_input.copy_events = circuit_inputs.copy_events();

            result = test_bbf_component<FieldType,
                                        nil::blueprint::bbf::zkevm_small_field::copy>(
                "copy-s", {7}, copy_assignment_input, max_copy_events, max_copy, max_rw,
                max_keccak_blocks, max_bytecode);
            BOOST_CHECK(result);
        }
    }
};

// Remember that in production sizes should be preset.
// Here they are different for different tests just for fast and easy testing
BOOST_GLOBAL_FIXTURE(zkEVMGlobalFixture);

BOOST_FIXTURE_TEST_SUITE(zkevm_bbf_debugtt, zkEVMDebugTTTestFixture)

using big_field_type =
    typename nil::crypto3::algebra::curves::alt_bn128_254::scalar_field_type;
using small_field_extension_type = typename algebra::fields::babybear_fp4;

using fields = std::tuple<big_field_type, small_field_extension_type>;

BOOST_AUTO_TEST_CASE_TEMPLATE(minimal_math, Field, fields) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 3;
    max_sizes.max_bytecode = 300;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 1000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 70;
    max_sizes.max_zkevm_rows = 500;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    if (circuits_to_run.empty()) {
        circuits_to_run.insert("zkevm");
        // circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
    }
    complex_test<Field>("minimal_math.json", max_sizes);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(call_counter, Field, fields) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
    }
    complex_test<Field>("call_counter.json", max_sizes);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(delegatecall_counter, Field, fields) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 4000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1500;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
    }
    complex_test<Field>("delegatecall.json", max_sizes);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(staticcall, Field, fields) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 4000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1500;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
    }
    complex_test<Field>("staticcall.json", max_sizes);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(counter, Field, fields) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
    }
    complex_test<Field>("counter.json", max_sizes);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(keccak, Field, fields) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 5000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 1000;
    max_sizes.max_zkevm_rows = 2000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("keccak");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
    }
    complex_test<Field>("keccak.json", max_sizes);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(call_keccak, Field, fields) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 5000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 2000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    if (circuits_to_run.empty()) {
        circuits_to_run.insert("zkevm");
        // circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("keccak");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
    }
    complex_test<Field>("call_keccak.json", max_sizes);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(indexed_log, Field, fields) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
    }
    complex_test<Field>("indexed_log.json", max_sizes);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(cold_sstore, Field, fields) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
    }
    complex_test<Field>("cold_sstore.json", max_sizes);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(try_catch, Field, fields) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 5000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 8000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 1500;
    max_sizes.max_zkevm_rows = 5000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
    }
    complex_test<Field>("try_catch.json", max_sizes);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(try_catch2, Field, fields) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 5000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 8000;
    max_sizes.max_copy = 1500;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 6000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
    }
    complex_test<Field>("try_catch2.json", max_sizes);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(try_catch_cold, Field, fields) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 6000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 8000;
    max_sizes.max_copy = 1500;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 5000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
    }
    complex_test<Field>("try_catch_cold.json", max_sizes);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(sar, Field, fields) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy = 500;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 1000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
    }
    complex_test<Field>("sar.json", max_sizes);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(scmp, Field, fields) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy = 500;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 2000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
    }
    complex_test<Field>("scmp.json", max_sizes);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(exp, Field, fields) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 10;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy = 500;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 2000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 3000;
    max_sizes.max_state = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("exp");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
    }
    complex_test<Field>("exp.json", max_sizes);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(modular, Field, fields) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 100;
    max_sizes.max_bytecode = 1000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 2000;
    max_sizes.max_copy = 70;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 1000;
    max_sizes.max_exponentiations = 10;
    max_sizes.max_exp_rows = 100;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
    }
    complex_test<Field>("modular.json", max_sizes);
}

BOOST_AUTO_TEST_SUITE(disabled_zkevm, *boost::unit_test::disabled())

// May be tested when block loader will be updated
BOOST_AUTO_TEST_CASE_TEMPLATE(precompiles, Field, fields) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 4;
    max_sizes.max_bytecode = 300;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 500;
    max_sizes.max_copy = 70;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 500;
    max_sizes.max_exponentiations = 10;
    max_sizes.max_exp_rows = 100;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
    }
    complex_test<Field>("precompiles.json", max_sizes);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_CASE_TEMPLATE(mem, Field, fields) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 25;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy = 3000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 4500;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
    }
    complex_test<Field>("mem.json", max_sizes);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(codecopy, Field, fields) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 300;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 2000;
    max_sizes.max_copy = 500;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 500;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
    }
    complex_test<Field>("codecopy.json", max_sizes);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(transient_storage, Field, fields) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 2000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy = 500;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 5000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
    }
    complex_test<Field>("transient_storage.json", max_sizes);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(transient_storage_revert, Field, fields) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 2000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 4000;
    max_sizes.max_copy = 500;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 4000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
    }
    complex_test<Field>("transient_storage_revert.json", max_sizes);
}

BOOST_AUTO_TEST_SUITE_END()


// TODO(ioxid): these tests work in multithread mode.
// In single thread mode they can fail to compile.
// Also compiling in multithread mode takes too long time in CI with GCC.

BOOST_FIXTURE_TEST_SUITE(benchmarking_fixed_sizes, zkEVMDebugTTTestFixture,
                         *boost::unit_test::disabled())

constexpr l1_size_restrictions gen_max_sizes(std::size_t max_bits) {
    std::size_t max_rows = (1 << max_bits) - 2;
    l1_size_restrictions max_sizes;
    max_sizes.max_exponentiations = max_rows;
    max_sizes.max_keccak_blocks = max_rows;
    max_sizes.max_bytecode = max_rows;
    max_sizes.max_mpt = max_rows;
    max_sizes.max_rw = max_rows;
    max_sizes.max_copy = max_rows;
    max_sizes.max_zkevm_rows = max_rows;
    max_sizes.max_exponentiations = max_rows;
    max_sizes.max_exp_rows = max_rows;
    max_sizes.max_state = max_rows;
    max_sizes.max_mpt = max_rows;
    return max_sizes;
}

BOOST_DATA_TEST_CASE(minimal_math_pallas_fixed_size, boost::unit_test::data::xrange(30)) {
    using FieldType = typename algebra::curves::pallas::scalar_field_type;
    complex_test<FieldType>("minimal_math.json", gen_max_sizes(sample));
}

BOOST_DATA_TEST_CASE(minimal_math_bn254_fixed_size, boost::unit_test::data::xrange(30)) {
    using FieldType = typename algebra::curves::alt_bn128_254::scalar_field_type;
    complex_test<FieldType>("minimal_math.json", gen_max_sizes(sample));
}

BOOST_DATA_TEST_CASE(minimal_math_goldilocks_fixed_size,
                     boost::unit_test::data::xrange(30)) {
    using FieldType = typename algebra::fields::goldilocks;
    complex_test<FieldType>("minimal_math.json", gen_max_sizes(sample));
}

BOOST_DATA_TEST_CASE(minimal_math_goldilocks_fp2_fixed_size,
                     boost::unit_test::data::xrange(30)) {
    using FieldType = typename algebra::fields::goldilocks_fp2;
    complex_test<FieldType>("minimal_math.json", gen_max_sizes(sample));
}

BOOST_DATA_TEST_CASE(minimal_math_babybear_fixed_size,
                     boost::unit_test::data::xrange(30)) {
    using FieldType = typename algebra::fields::babybear;
    complex_test<FieldType>("minimal_math.json", gen_max_sizes(sample));
}

BOOST_DATA_TEST_CASE(minimal_math_babybear_fp4_fixed_size,
                     boost::unit_test::data::xrange(30)) {
    using FieldType = typename algebra::fields::babybear_fp4;
    complex_test<FieldType>("minimal_math.json", gen_max_sizes(sample));
}

BOOST_DATA_TEST_CASE(minimal_math_babybear_fp5_fixed_size,
                     boost::unit_test::data::xrange(30)) {
    using FieldType = typename algebra::fields::babybear_fp5;
    complex_test<FieldType>("minimal_math.json", gen_max_sizes(sample));
}

BOOST_AUTO_TEST_SUITE_END()
