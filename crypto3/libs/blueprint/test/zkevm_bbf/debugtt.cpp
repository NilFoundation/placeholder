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
#include <nil/blueprint/zkevm_bbf/big_field/circuits/logs.hpp>

#include <nil/blueprint/zkevm_bbf/small_field/circuits/rw.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/circuits/bytecode.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/circuits/copy.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/circuits/zkevm.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/circuits/logs.hpp>

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

    void setup(std::string path) {
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
    }

    nil::blueprint::bbf::zkevm_basic_input_generator load_circuit_inputs(std::string path) {
        debugtt_block_loader loader(path);
        auto circuit_inputs = nil::blueprint::bbf::zkevm_basic_input_generator(
            (abstract_block_loader *)(&loader));
        BOOST_LOG_TRIVIAL(trace) << circuit_inputs.print_statistics();
        BOOST_ASSERT(circuit_inputs.get_execution_status());
        return circuit_inputs;
    }

    template<typename FieldType>
    void test_big_keccak_circuit(const nil::blueprint::bbf::zkevm_basic_input_generator &circuit_inputs, const l1_size_restrictions &s){
        using SmallFieldType = typename FieldType::small_subfield;
        const std::string keccak_circuit = "keccak";
        if(should_run_circuit(keccak_circuit)){
            typename nil::blueprint::bbf::zkevm_big_field::zkevm_keccak<
            FieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type
            keccak_assignment_input;
            keccak_assignment_input.rlc_challenge = 7;
            keccak_assignment_input.private_input = circuit_inputs.keccaks();
            bool result = test_bbf_component<
                FieldType, nil::blueprint::bbf::zkevm_big_field::zkevm_keccak>(
                "keccak", {7},
                keccak_assignment_input,
                s.max_keccak_blocks
            );
            BOOST_CHECK(result);
        }
    }

    template<typename FieldType>
    void test_big_exp_circuit(const nil::blueprint::bbf::zkevm_basic_input_generator &circuit_inputs, const l1_size_restrictions &s){
        using SmallFieldType = typename FieldType::small_subfield;
        const std::string exp_circuit = "exp";
        if (should_run_circuit(exp_circuit)) {
            BOOST_LOG_TRIVIAL(info) << std::endl << "circuit '" << exp_circuit << "'";
            typename zkevm_big_field::exponentiation<SmallFieldType, GenerationStage::ASSIGNMENT>::input_type
            exp_assignment_input = circuit_inputs.exponentiations();
            bool result = test_bbf_component<
                FieldType, nil::blueprint::bbf::zkevm_big_field::exponentiation>(
                "exp", {},
                exp_assignment_input,
                s.max_exp_rows, s.max_exponentiations
            );
            BOOST_CHECK(result);
        }
    }

    template<typename FieldType>
    void test_big_bytecode_circuit(const nil::blueprint::bbf::zkevm_basic_input_generator &circuit_inputs, const l1_size_restrictions &s){
        using SmallFieldType = typename FieldType::small_subfield;
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

            bool result = test_bbf_component<FieldType, nil::blueprint::bbf::zkevm_big_field::bytecode>(
                "bytecode", {7},
                bytecode_assignment_input,
                s.max_bytecode,
                s.max_keccak_blocks
            );
            BOOST_CHECK(result);
        }
    }

    template<typename FieldType>
    void test_big_rw_circuit(const nil::blueprint::bbf::zkevm_basic_input_generator &circuit_inputs, const l1_size_restrictions &s) {
        using SmallFieldType = typename FieldType::small_subfield;
        const std::string rw_circuit = "rw";
        if (should_run_circuit(rw_circuit)) {
            BOOST_LOG_TRIVIAL(info) << std::endl << "circuit '" << rw_circuit << "'";
            typename zkevm_big_field::rw<SmallFieldType, GenerationStage::ASSIGNMENT>::input_type rw_assignment_input;
            rw_assignment_input.rw_trace = circuit_inputs.short_rw_operations();
            rw_assignment_input.timeline = circuit_inputs.timeline();
            rw_assignment_input.state_trace = circuit_inputs.state_operations();
            rw_assignment_input.filter_indices = circuit_inputs.filter_indices();

            bool result = test_bbf_component<FieldType, nil::blueprint::bbf::zkevm_big_field::rw>(
                "rw", {}, rw_assignment_input,
                s.max_rw, s.max_state, s.max_filter_indices
            );
            BOOST_CHECK(result);
        }
    }

    template<typename FieldType>
    void test_big_state_circuit(const nil::blueprint::bbf::zkevm_basic_input_generator &circuit_inputs, const l1_size_restrictions &s) {
        using SmallFieldType = typename FieldType::small_subfield;
        const std::string state_circuit = "state";
        if (should_run_circuit(state_circuit)) {
            BOOST_LOG_TRIVIAL(info) << std::endl
                << "circuit '" << state_circuit << "'";
            typename zkevm_big_field::state_transition<
                SmallFieldType, GenerationStage::ASSIGNMENT>::input_type
                state_assignment_input;
            state_assignment_input.state_trace = circuit_inputs.state_operations();
            state_assignment_input.call_state_data = circuit_inputs.call_state_data();

            bool result = test_bbf_component<FieldType, nil::blueprint::bbf::zkevm_big_field::state_transition>(
                "state", {}, state_assignment_input, s.max_state
            );
            BOOST_CHECK(result);
        }
    }

    template<typename FieldType>
    void test_big_copy_circuit(const nil::blueprint::bbf::zkevm_basic_input_generator &circuit_inputs, const l1_size_restrictions &s) {
        using SmallFieldType = typename FieldType::small_subfield;
        const std::string copy_circuit = "copy";
        if (should_run_circuit(copy_circuit)) {
            BOOST_LOG_TRIVIAL(info) << "circuit '" << copy_circuit << "'";
            typename zkevm_big_field::copy<
                SmallFieldType,
                GenerationStage::ASSIGNMENT>::input_type
                copy_assignment_input;
            copy_assignment_input.rlc_challenge = 7;
            copy_assignment_input.bytecodes = circuit_inputs.bytecodes();
            copy_assignment_input.keccak_buffers = circuit_inputs.keccaks();
            copy_assignment_input.rw_operations =
                circuit_inputs.short_rw_operations();
            copy_assignment_input.copy_events = circuit_inputs.copy_events();

            bool result = test_bbf_component<FieldType, nil::blueprint::bbf::zkevm_big_field::copy>(
                "copy", {7}, copy_assignment_input,
                s.max_copy, s.max_rw,
                s.max_keccak_blocks, s.max_bytecode
            );
            BOOST_CHECK(result);
        }
    }

    template<typename FieldType>
    void test_big_zkevm_circuit(const nil::blueprint::bbf::zkevm_basic_input_generator &circuit_inputs, const l1_size_restrictions &s) {
        using SmallFieldType = typename FieldType::small_subfield;
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
            zkevm_assignment_input.filter_indices = circuit_inputs.filter_indices();

            bool result = test_bbf_component<FieldType,
                                        nil::blueprint::bbf::zkevm_big_field::zkevm>(
                "zkevm", {}, zkevm_assignment_input,
                s.max_zkevm_rows, s.max_copy,
                s.max_rw, s.max_exponentiations,
                s.max_bytecode, s.max_state, s.max_filter_indices
            );
            BOOST_CHECK(result);
        }
    }

    template<typename FieldType>
    void test_big_zkevm_wide_circuit(const nil::blueprint::bbf::zkevm_basic_input_generator &circuit_inputs, const l1_size_restrictions &s) {
        using SmallFieldType = typename FieldType::small_subfield;
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
            zkevm_wide_assignment_input.filter_indices = circuit_inputs.filter_indices();

            bool result =
                test_bbf_component<FieldType,
                                    nil::blueprint::bbf::zkevm_big_field::zkevm_wide>(
                    "zkevm_wide", {}, zkevm_wide_assignment_input, s.max_zkevm_rows,
                    s.max_copy, s.max_rw, s.max_exponentiations, s.max_bytecode, s.max_state, s.max_filter_indices);
            BOOST_CHECK(result);
        }
    }

    template<typename FieldType>
    void test_big_logs_circuit(const nil::blueprint::bbf::zkevm_basic_input_generator &circuit_inputs, const l1_size_restrictions &s) {
        using SmallFieldType = typename FieldType::small_subfield;
                    const std::string log_circuit = "logs";
        if (should_run_circuit(log_circuit)) {
            BOOST_LOG_TRIVIAL(info) << "circuit '" << log_circuit << "'";
            typename zkevm_big_field::logs<
                SmallFieldType, GenerationStage::ASSIGNMENT>::input_type
                log_assignment_input;
            log_assignment_input.rlc_challenge = 7;
            log_assignment_input.filter_indices = circuit_inputs.filter_indices();
            log_assignment_input.keccak_buffers = circuit_inputs.logs_buffers();
            log_assignment_input.rw_trace = circuit_inputs.short_rw_operations();

            bool result = test_bbf_component<FieldType, nil::blueprint::bbf::zkevm_big_field::logs>(
                log_circuit, {}, log_assignment_input,
               s.max_keccak_blocks, s.max_filter_indices, s.max_rw
            );
            BOOST_CHECK(result);
        }
    }



    template<typename FieldType>
    void test_small_rw_circuit(const nil::blueprint::bbf::zkevm_basic_input_generator &circuit_inputs, const l1_size_restrictions &s){
        using SmallFieldType = typename FieldType::small_subfield;
        const std::string small_rw_circuit = "rw-s";
        if (should_run_circuit(small_rw_circuit)) {
            BOOST_LOG_TRIVIAL(info) << std::endl << "circuit '" << small_rw_circuit << "'";
            typename zkevm_small_field::rw<SmallFieldType,
                                           GenerationStage::ASSIGNMENT>::input_type
                rw_assignment_input;
            rw_assignment_input.rw_trace = circuit_inputs.short_rw_operations();
            rw_assignment_input.timeline = circuit_inputs.timeline();
            rw_assignment_input.state_trace = circuit_inputs.state_operations();
            rw_assignment_input.filter_indices = circuit_inputs.filter_indices();

            bool result = test_bbf_component<SmallFieldType, nil::blueprint::bbf::zkevm_small_field::rw>(
                "rw-s", {},
                rw_assignment_input,
                s.max_zkevm_small_field_rows,
                s.instances_rw_8,
                s.instances_rw_256,
                s.max_state,
                s.max_filter_indices
            );
            BOOST_CHECK(result);
        }
    }

    template<typename FieldType>
    void test_small_bytecode_circuit(const nil::blueprint::bbf::zkevm_basic_input_generator &circuit_inputs, const l1_size_restrictions &s) {
        using SmallFieldType = typename FieldType::small_subfield;
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

            bool result = test_bbf_component<FieldType, nil::blueprint::bbf::zkevm_small_field::bytecode>(
                "bytecode-s", {7},
                bytecode_assignment_input,
                s.max_bytecode,
                s.max_keccak_blocks,
                s.max_bytecodes_amount
            );
            BOOST_CHECK(result);
        }
    }

    template<typename FieldType>
    void test_small_zkevm_circuit(const nil::blueprint::bbf::zkevm_basic_input_generator &circuit_inputs, const l1_size_restrictions &s) {
        using SmallFieldType = typename FieldType::small_subfield;
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

            bool result = test_bbf_component<SmallFieldType, nil::blueprint::bbf::zkevm_small_field::zkevm>(
                "zkevm-s", {}, zkevm_assignment_input,
                s.max_zkevm_small_field_rows,
                s.max_copy_events,
                s.instances_rw_8,
                s.instances_rw_256,
                s.max_exponentiations,
                s.max_bytecode,
                s.max_state
            );
            BOOST_CHECK(result);
        }
    }

    template<typename FieldType>
    void test_small_copy_circuit(const nil::blueprint::bbf::zkevm_basic_input_generator &circuit_inputs, const l1_size_restrictions &s) {
        using SmallFieldType = typename FieldType::small_subfield;

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

            bool result = test_bbf_component<SmallFieldType, nil::blueprint::bbf::zkevm_small_field::copy>(
                "copy-s", {7}, copy_assignment_input,
                s.max_copy_events,
                s.max_copy_small_field_rows,
                s.instances_copy,
                s.max_rw,
                s.instances_rw_8,
                s.max_keccak_blocks,
                s.max_bytecode
            );
            BOOST_CHECK(result);
        }

    }
    template<typename FieldType>
    void test_small_logs_circuit(const nil::blueprint::bbf::zkevm_basic_input_generator &circuit_inputs, const l1_size_restrictions &s) {
        using SmallFieldType = typename FieldType::small_subfield;

        const std::string logs_s_circuit = "logs-s";
        if (should_run_circuit(logs_s_circuit)) {
            BOOST_LOG_TRIVIAL(info) << "circuit '" << logs_s_circuit << "'";
            typename zkevm_small_field::logs<SmallFieldType, GenerationStage::ASSIGNMENT>::input_type log_assignment_input;
            log_assignment_input.rlc_challenge = 7;
            log_assignment_input.filter_indices = circuit_inputs.filter_indices();
            log_assignment_input.keccak_buffers = circuit_inputs.logs_buffers();
            log_assignment_input.rw_trace = circuit_inputs.short_rw_operations();

            bool result = test_bbf_component<FieldType, nil::blueprint::bbf::zkevm_small_field::logs>(
                logs_s_circuit, {7}, log_assignment_input,
               s.max_keccak_blocks, s.max_filter_indices, s.max_rw, s.instances_rw_256);
            BOOST_CHECK(result);
        }
    }

    template<typename BigFieldType, typename SmallFieldType>
    void complex_test(std::string path, const l1_size_restrictions &max_sizes) {
        setup(path);
        if( !assign ) return;
        auto circuit_inputs = std::move(load_circuit_inputs(path));

        l1_size_restrictions s = max_sizes;
        s.max_copy_small_field_rows = max_sizes.max_copy_small_field_rows == 0? max_sizes.max_copy : max_sizes.max_copy_small_field_rows;
        s.max_zkevm_small_field_rows = max_sizes.max_zkevm_small_field_rows == 0? max_sizes.max_zkevm_rows : max_sizes.max_zkevm_small_field_rows;

        test_big_keccak_circuit<BigFieldType>(circuit_inputs, s);
        test_big_exp_circuit<BigFieldType>(circuit_inputs, s);

        test_big_bytecode_circuit<BigFieldType>(circuit_inputs, s);
        test_big_rw_circuit<BigFieldType>(circuit_inputs, s);
        test_big_state_circuit<BigFieldType>(circuit_inputs, s);
        test_big_copy_circuit<BigFieldType>(circuit_inputs, s);
        test_big_zkevm_circuit<BigFieldType>(circuit_inputs, s);
        test_big_zkevm_wide_circuit<BigFieldType>(circuit_inputs, s);
        test_big_logs_circuit<BigFieldType>(circuit_inputs, s);
        test_small_rw_circuit<SmallFieldType>(circuit_inputs, s);
        test_small_bytecode_circuit<SmallFieldType>(circuit_inputs, s);
        test_small_zkevm_circuit<SmallFieldType>(circuit_inputs, s);
        test_small_copy_circuit<SmallFieldType>(circuit_inputs, s);
        test_small_logs_circuit<SmallFieldType>(circuit_inputs, s);
    }

    template<typename FieldType>
    void complex_test(std::string path, const l1_size_restrictions &max_sizes) {
        using SmallFieldType = typename FieldType::small_subfield;
        constexpr bool BIG_FIELD = SmallFieldType::modulus_bits >= 250;

        setup(path);
        if (!assign) return;
        auto circuit_inputs = std::move(load_circuit_inputs(path));

        l1_size_restrictions s = max_sizes;
        s.max_copy_small_field_rows = max_sizes.max_copy_small_field_rows == 0? max_sizes.max_copy : max_sizes.max_copy_small_field_rows;
        s.max_zkevm_small_field_rows = max_sizes.max_zkevm_small_field_rows == 0? max_sizes.max_zkevm_rows : max_sizes.max_zkevm_small_field_rows;

        if constexpr (BIG_FIELD){
            // This circuit uses big constants, so it cannot be built with small fields
            test_big_keccak_circuit<FieldType>(circuit_inputs, s);
        }
        if (BIG_FIELD || force_incompatibe_circuits_for_field) {
            test_big_exp_circuit<FieldType>(circuit_inputs, s);
            test_big_bytecode_circuit<FieldType>(circuit_inputs, s);
            test_big_rw_circuit<FieldType>(circuit_inputs, s);
            test_big_state_circuit<FieldType>(circuit_inputs, s);
            test_big_copy_circuit<FieldType>(circuit_inputs, s);
            test_big_zkevm_circuit<FieldType>(circuit_inputs, s);
            test_big_zkevm_wide_circuit<FieldType>(circuit_inputs, s);
            test_big_logs_circuit<FieldType>(circuit_inputs, s);
        }

        test_small_rw_circuit<FieldType>(circuit_inputs, s);
        test_small_bytecode_circuit<FieldType>(circuit_inputs, s);
        test_small_zkevm_circuit<FieldType>(circuit_inputs, s);
        test_small_copy_circuit<FieldType>(circuit_inputs, s);
        test_small_logs_circuit<FieldType>(circuit_inputs, s);
    }
};

// Remember that in production sizes should be preset.
// Here they are different for different tests just for fast and easy testing
BOOST_GLOBAL_FIXTURE(zkEVMGlobalFixture);

BOOST_FIXTURE_TEST_SUITE(zkevm_bbf_debugtt, zkEVMDebugTTTestFixture)
using big_field_type = typename nil::crypto3::algebra::curves::alt_bn128_254::scalar_field_type;
using small_field_extension_type = typename algebra::fields::babybear_fp4;

BOOST_AUTO_TEST_CASE(minimal_math) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 30;
    max_sizes.max_bytecode = 300;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 1000;    // Doesn't matter for small fields

    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 70;
    max_sizes.max_zkevm_rows = 400;
    max_sizes.max_zkevm_small_field_rows = 250;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;
    max_sizes.max_filter_indices = 100;

    if (circuits_to_run.empty()) {
        circuits_to_run.insert("zkevm");
        // circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("logs");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("zkevm-s");
    }
    complex_test<big_field_type, small_field_extension_type>("minimal_math.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(call_counter) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 100;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;
    max_sizes.max_filter_indices = 100;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        // circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("logs");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("logs-s");
    }
    complex_test<big_field_type, small_field_extension_type>("call_counter.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(delegatecall_counter) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 100;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 4000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1500;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;
    max_sizes.max_filter_indices = 100;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("logs");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("logs-s");
    }
    complex_test<big_field_type, small_field_extension_type>("delegatecall.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(staticcall) {
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
    max_sizes.max_filter_indices = 100;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("logs");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("logs-s");
    }
    complex_test<big_field_type, small_field_extension_type>("staticcall.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(counter) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 100;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;
    max_sizes.max_filter_indices = 100;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("logs");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("logs-s");
    }
    complex_test<big_field_type, small_field_extension_type>("counter.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(keccak) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 100;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 5000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 1000;
    max_sizes.max_copy_small_field_rows = 500; // For multicolumn copy testing
    max_sizes.max_zkevm_rows = 2000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;
    max_sizes.max_filter_indices = 100;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("keccak");
        circuits_to_run.insert("logs");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("logs-s");
    }
    complex_test<big_field_type, small_field_extension_type>("keccak.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(call_keccak) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 100;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 5000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 2000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;
    max_sizes.max_filter_indices = 100;

    if (circuits_to_run.empty()) {
        circuits_to_run.insert("zkevm");
        // circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("keccak");
        circuits_to_run.insert("logs");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("logs-s");
    }
    complex_test<big_field_type, small_field_extension_type>("call_keccak.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(indexed_log) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 100;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;
    max_sizes.max_filter_indices = 100;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("logs");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("logs-s");
    }
    complex_test<big_field_type, small_field_extension_type>("indexed_log.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(simple_log) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 100;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;
    max_sizes.max_filter_indices = 100;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("logs");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("logs-s");
    }
    complex_test<big_field_type, small_field_extension_type>("simple_log.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(cold_sstore) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 100;
    max_sizes.max_bytecode = 3000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 3000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 500;
    max_sizes.max_zkevm_rows = 1000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;
    max_sizes.max_filter_indices = 100;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("logs");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("logs-s");
    }
    complex_test<big_field_type, small_field_extension_type>("cold_sstore.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(try_catch) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 100;
    max_sizes.max_bytecode = 5000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 8000;
    max_sizes.max_copy_events = 70;
    max_sizes.max_copy = 1500;
    max_sizes.max_zkevm_rows = 5000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;
    max_sizes.max_filter_indices = 100;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("logs");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("logs-s");
    }
    complex_test<big_field_type, small_field_extension_type>("try_catch.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(try_catch2) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 100;
    max_sizes.max_bytecode = 5000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 8000;
    max_sizes.max_copy = 1500;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 6000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;
    max_sizes.max_filter_indices = 100;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("logs");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("logs-s");
    }
    complex_test<big_field_type, small_field_extension_type>("try_catch2.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(try_catch_cold) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 100;
    max_sizes.max_bytecode = 6000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 8000;
    max_sizes.max_copy = 1500;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 5000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_state = 500;
     max_sizes.max_filter_indices = 100;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("logs");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("logs-s");
    }
    complex_test<big_field_type, small_field_extension_type>("try_catch_cold.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(sar) {
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
     max_sizes.max_filter_indices = 100;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("logs");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("logs-s");
    }
    complex_test<big_field_type, small_field_extension_type>("sar.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(scmp) {
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
     max_sizes.max_filter_indices = 100;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("logs");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("logs-s");
    }
    complex_test<big_field_type, small_field_extension_type>("scmp.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(exp) {
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
     max_sizes.max_filter_indices = 100;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("exp");
        circuits_to_run.insert("logs");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("logs-s");
    }
    complex_test<big_field_type, small_field_extension_type>("exp.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(modular) {
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
     max_sizes.max_filter_indices = 100;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("logs");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("logs-s");
    }
    complex_test<big_field_type, small_field_extension_type>("modular.json", max_sizes);
}

// May be tested when block loader will be updated
BOOST_AUTO_TEST_CASE(precompiles, *boost::unit_test::disabled()) {
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
     max_sizes.max_filter_indices = 100;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("logs");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("logs-s");
    }
    complex_test<big_field_type, small_field_extension_type>("precompiles.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(mem) {
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
     max_sizes.max_filter_indices = 100;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("logs");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("logs-s");
    }
    complex_test<big_field_type, small_field_extension_type>("mem.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(codecopy) {
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
     max_sizes.max_filter_indices = 100;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("logs");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("logs-s");
    }
    complex_test<big_field_type, small_field_extension_type>("codecopy.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(transient_storage) {
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
     max_sizes.max_filter_indices = 100;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        //circuits_to_run.insert("zkevm-wide");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("logs");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("logs-s");
    }
    complex_test<big_field_type, small_field_extension_type>("transient_storage.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(transient_storage_revert) {
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
    max_sizes.max_filter_indices = 100;

    if( circuits_to_run.empty() ) {
        circuits_to_run.insert("zkevm");
        circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        circuits_to_run.insert("copy");
        circuits_to_run.insert("logs");
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
        circuits_to_run.insert("logs-s");
    }
    complex_test<big_field_type, small_field_extension_type>("transient_storage_revert.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(large_calldata_key) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 1000;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 4000;
    max_sizes.max_copy = 500;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 4000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_zkevm_small_field_rows = 1000;
    max_sizes.max_filter_indices = 100;

    if( circuits_to_run.empty() ) {
        // circuits_to_run.insert("zkevm"); //Previous version doesn't support large calldata keys
        // circuits_to_run.insert("rw");
        circuits_to_run.insert("bytecode");
        // circuits_to_run.insert("copy"); //Previous version doesn't support large calldata keys
        circuits_to_run.insert("bytecode-s");
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
    }
    complex_test<big_field_type, small_field_extension_type>("large_calldata_key.json", max_sizes);
}

BOOST_AUTO_TEST_CASE(call_large_memory_key) {
    l1_size_restrictions max_sizes;

    max_sizes.max_keccak_blocks = 50;
    max_sizes.max_bytecode = 4500;
    max_sizes.max_mpt = 0;
    max_sizes.max_rw = 10000;
    max_sizes.max_copy = 500;
    max_sizes.max_copy_events = 70;
    max_sizes.max_zkevm_rows = 4000;
    max_sizes.max_exponentiations = 50;
    max_sizes.max_exp_rows = 500;
    max_sizes.max_zkevm_small_field_rows = 8000;
    max_sizes.max_filter_indices = 100;

    if( circuits_to_run.empty() ) {
        // circuits_to_run.insert("zkevm");       // Previous version doesn't support large memory keys
        // circuits_to_run.insert("rw");
        // circuits_to_run.insert("bytecode");    // Doesn't work for now
        // circuits_to_run.insert("copy");        // Previous version doesn't support large memory keys
        // circuits_to_run.insert("bytecode-s");  // Doesn't work for now
        circuits_to_run.insert("rw-s");
        circuits_to_run.insert("copy-s");
    }
    complex_test<big_field_type, small_field_extension_type>("call_large_memory_key.json", max_sizes);
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