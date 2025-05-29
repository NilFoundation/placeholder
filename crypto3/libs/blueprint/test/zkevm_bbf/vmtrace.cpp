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
#define BOOST_TEST_MODULE blueprint_zkevm_vmtrace_test

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
#include <nil/blueprint/zkevm_bbf/types/state_operation.hpp>
#include <nil/blueprint/zkevm_bbf/types/copy_event.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_state.hpp>

#include <nil/blueprint/zkevm_bbf/loaders/vmtrace.hpp>
#include <nil/blueprint/zkevm_bbf/input_generators/basic_input_generator.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

// #include <nil/blueprint/zkevm_bbf/zkevm.hpp>
// #include <nil/blueprint/zkevm_bbf/rw.hpp>
// //#include <nil/blueprint/zkevm_bbf/rw_small_field.hpp>
// #include <nil/blueprint/zkevm_bbf/copy.hpp>
// #include <nil/blueprint/zkevm_bbf/bytecode.hpp>
// #include <nil/blueprint/zkevm_bbf/keccak.hpp>
// #include <nil/blueprint/zkevm_bbf/exp.hpp>
// #include <nil/blueprint/zkevm_bbf/call_commit.hpp>

#include "./circuit_test_fixture.hpp"

using namespace nil::crypto3;
using namespace nil::blueprint;
using namespace nil::blueprint::bbf;

// This circuit does something only if some parameters are set.
// It's because of this test works long and shouldn't be executed as is in CI

class zkEVMVmTraceTestFixture: public CircuitTestFixture {
protected:
    bool check_trace = false;
    bool empty_machine_run = false;
    bool assign = false;
    bool do_something = false;
public:
    zkEVMVmTraceTestFixture():CircuitTestFixture(){
        std::size_t argc = boost::unit_test::framework::master_test_suite().argc;
        auto &argv = boost::unit_test::framework::master_test_suite().argv;

        for( std::size_t i = 0; i < argc; i++ ){
            std::string arg(argv[i]);
            if(arg == "--empty-machine-run" ) {
                empty_machine_run = true;
            }
            if(arg == "--check-trace" ) {
                check_trace = true;
            }
            if(arg == "--assign"){
                assign = true;
            }
            do_something = empty_machine_run || check_trace || assign;
        }
    }

    template <typename field_type>
    void complex_test(
        std::string                        path,
        const l1_size_restrictions         &max_sizes
    ){
        {
            if( empty_machine_run ){
                nil::blueprint::bbf::vmtrace_block_loader loader(path);
                nil::blueprint::bbf::zkevm_basic_evm evm((abstract_block_loader*)(&loader));
                evm.execute_blocks();
                BOOST_ASSERT(evm.get_execution_status());
            }
            if( check_trace){
                nil::blueprint::bbf::vmtrace_block_loader loader(path);
                nil::blueprint::bbf::zkevm_vmtrace_trace_checker trace_checker(&loader);
                BOOST_ASSERT(trace_checker.get_execution_status());
            }
            if( !assign ) return;

            nil::blueprint::bbf::vmtrace_block_loader loader(path);
            nil::blueprint::bbf::zkevm_basic_input_generator circuit_inputs((abstract_block_loader*)(&loader));
            BOOST_ASSERT(circuit_inputs.get_execution_status());
            BOOST_LOG_TRIVIAL(info) << circuit_inputs.print_statistics();
        }
        std::cout << "Done" << std::endl;
        return;

        // using integral_type = typename field_type::integral_type;
        // using value_type = typename field_type::value_type;

        // integral_type base16 = integral_type(1) << 16;

        // std::size_t max_keccak_blocks = max_sizes.max_keccak_blocks;
        // std::size_t max_bytecode = max_sizes.max_bytecode;
        // std::size_t max_mpt = max_sizes.max_mpt;
        // std::size_t max_rw = max_sizes.max_rw;
        // std::size_t max_copy = max_sizes.max_copy;
        // std::size_t max_zkevm_rows = max_sizes.max_zkevm_rows;
        // std::size_t max_exponentiations = max_sizes.max_exponentiations;
        // std::size_t max_exp_rows = max_sizes.max_exp_rows;
        // std::size_t max_state = max_sizes.max_state;

        // typename copy<field_type, GenerationStage::ASSIGNMENT>::input_type copy_assignment_input;
        // copy_assignment_input.rlc_challenge = 7;
        // copy_assignment_input.bytecodes = circuit_inputs.bytecodes();
        // copy_assignment_input.keccak_buffers = circuit_inputs.keccaks();
        // copy_assignment_input.rw_operations = circuit_inputs.rw_operations();
        // copy_assignment_input.copy_events = circuit_inputs.copy_events();
        // copy_assignment_input.call_commits = circuit_inputs.call_commits();

        // typename zkevm<field_type, GenerationStage::ASSIGNMENT>::input_type zkevm_assignment_input;
        // zkevm_assignment_input.rlc_challenge = 7;
        // zkevm_assignment_input.bytecodes = circuit_inputs.bytecodes();
        // zkevm_assignment_input.keccak_buffers = circuit_inputs.keccaks();
        // zkevm_assignment_input.rw_operations = circuit_inputs.rw_operations();
        // zkevm_assignment_input.copy_events = circuit_inputs.copy_events();
        // zkevm_assignment_input.zkevm_states = circuit_inputs.zkevm_states();
        // zkevm_assignment_input.exponentiations = circuit_inputs.exponentiations();

        // typename nil::blueprint::bbf::rw<field_type,nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type rw_assignment_input;
        // rw_assignment_input.rw_operations = circuit_inputs.rw_operations();
        // rw_assignment_input.call_commits = circuit_inputs.call_commits();

        // typename nil::blueprint::bbf::call_commit<field_type,nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type call_commit_assignment_input;
        // call_commit_assignment_input.rw_operations = circuit_inputs.rw_operations();
        // call_commit_assignment_input.call_commits = circuit_inputs.call_commits();

        // typename zkevm_keccak<field_type,GenerationStage::ASSIGNMENT>::input_type keccak_assignment_input;
        // keccak_assignment_input.rlc_challenge = 7;
        // keccak_assignment_input.private_input = circuit_inputs.keccaks();

        // typename bytecode<field_type, GenerationStage::ASSIGNMENT>::input_type bytecode_assignment_input;
        // bytecode_assignment_input.rlc_challenge = 7;
        // bytecode_assignment_input.bytecodes = circuit_inputs.bytecodes();
        // bytecode_assignment_input.keccak_buffers = circuit_inputs.keccaks();

        // auto exp_assignment_input = circuit_inputs.exponentiations();

        // bool result{false};
        // const std::string zkevm_circuit = "zkevm";
        // if (should_run_circuit(zkevm_circuit)) {
        //     std::cout << "circuit '" << zkevm_circuit << "'" << std::endl;

        //     // Max_rows, max_bytecode, max_rw
        //     result = test_bbf_component<field_type, nil::blueprint::bbf::zkevm>(
        //         zkevm_circuit,
        //         {}, zkevm_assignment_input,
        //         max_zkevm_rows,
        //         max_copy,
        //         max_rw,
        //         max_exponentiations,
        //         max_bytecode
        //     );
        //     BOOST_ASSERT(result);
        // }
        // return;

        // const std::string exp_circuit = "exp";
        // if (should_run_circuit(exp_circuit)) {
        //     // Max_copy, Max_rw, Max_keccak, Max_bytecode
        //     result =test_bbf_component<field_type, nil::blueprint::bbf::exponentiation>(
        //         exp_circuit,
        //         {}, exp_assignment_input,
        //         max_exp_rows,
        //         max_exponentiations
        //     );
        //     BOOST_ASSERT(result);
        //     std::cout << std::endl;
        // }

        // const std::string copy_circuit = "copy";
        // if (should_run_circuit(copy_circuit)) {
        //     std::cout << "circuit '" << copy_circuit << "'" << std::endl;

        //     // Max_copy, Max_rw, Max_keccak, Max_bytecode
        //     result =test_bbf_component<field_type, nil::blueprint::bbf::copy>(
        //         copy_circuit,
        //         {7}, copy_assignment_input,
        //         max_copy, max_rw, max_keccak_blocks, max_bytecode, max_state
        //     );
        //     BOOST_ASSERT(result);
        //     std::cout << std::endl;
        // }

        // const std::string keccak_circuit = "keccak";
        // if (should_run_circuit(keccak_circuit)) {
        //     std::cout << "circuit '" << keccak_circuit << "'" << std::endl;

        //     // Max_keccak
        //     result = test_bbf_component<field_type, nil::blueprint::bbf::zkevm_keccak>(
        //         keccak_circuit,
        //         {}, keccak_assignment_input,max_keccak_blocks
        //     );
        //     BOOST_ASSERT(result);
        //     std::cout << std::endl;
        // }

        // const std::string bytecode_circuit = "bytecode";
        // if (should_run_circuit(bytecode_circuit)) {
        //     std::cout << "circuit '" << bytecode_circuit << "'" << std::endl;

        //     // Max_bytecode, max_bytecode
        //     result = test_bbf_component<field_type, nil::blueprint::bbf::bytecode>(
        //         bytecode_circuit,
        //         {7}, bytecode_assignment_input, max_bytecode, max_keccak_blocks
        //     );
        //     BOOST_ASSERT(result);

        //     std::cout << std::endl;
        // }

        // const std::string rw_circuit = "rw";
        // if (should_run_circuit(rw_circuit)) {
        //     std::cout << "circuit '" << rw_circuit << "'" << std::endl;

        //     // Max_rw, Max_mpt
        //     result = test_bbf_component<field_type, nil::blueprint::bbf::rw>(
        //         rw_circuit,
        //         {}, rw_assignment_input, max_rw, max_mpt, max_state
        //     );
        //     BOOST_ASSERT(result);

        //     // using small_field_type = typename algebra::fields::babybear;
        //     // // Max_rw, Max_mpt
        //     // result = test_bbf_component<small_field_type, nil::blueprint::bbf::rw_small_field>(
        //     //     rw_circuit,
        //     //     {}, rw_assignment_input, max_rw, max_mpt
        //     // );
        //     // BOOST_ASSERT(result);
        //     std::cout << std::endl;
        // }

        // const std::string call_commit_circuit = "call_commit";
        // if (should_run_circuit(call_commit_circuit)) {
        //     std::cout << "circuit '" << call_commit_circuit << "'" << std::endl;

        //     // Max_rw, Max_mpt
        //     result = test_bbf_component<field_type, nil::blueprint::bbf::call_commit>(
        //         call_commit_circuit,
        //         {}, call_commit_assignment_input, max_rw, max_state
        //     );
        //     BOOST_ASSERT(result);
        //     std::cout << std::endl;
        // }
    }
};

// Remember that in production sizes should be preset.
// Here they are different for different tests just for fast and easy testing
BOOST_GLOBAL_FIXTURE(zkEVMGlobalFixture);
BOOST_FIXTURE_TEST_SUITE(zkevm_bbf_hardhat, zkEVMVmTraceTestFixture)

BOOST_AUTO_TEST_CASE(sp1_block_18884864) {
    if(!do_something) return;
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

    complex_test<field_type>("vmtrace/sp1_block_18884864/", max_sizes);
}

BOOST_AUTO_TEST_CASE(sp1_block_18884865) {
    if(!do_something) return;
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

    complex_test<field_type>("vmtrace/sp1_block_18884865/", max_sizes);
}

BOOST_AUTO_TEST_CASE(sp1_block_18884866) {
    if(!do_something) return;
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

    complex_test<field_type>("vmtrace/sp1_block_18884866/", max_sizes);
}

BOOST_AUTO_TEST_CASE(sp1_block_18884867) {
    if(!do_something) return;
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

    complex_test<field_type>("vmtrace/sp1_block_18884867/", max_sizes);
}

BOOST_AUTO_TEST_CASE(sp1_block_18884868) {
    if(!do_something) return;
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

    complex_test<field_type>("vmtrace/sp1_block_18884868/", max_sizes);
}

BOOST_AUTO_TEST_CASE(sp1_block_18884869) {
    if(!do_something) return;
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

    complex_test<field_type>("vmtrace/sp1_block_18884869/", max_sizes);
}

BOOST_AUTO_TEST_CASE(sp1_block_20526624) {
    if(!do_something) return;
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

    complex_test<field_type>("vmtrace/sp1_block_20526624/", max_sizes);
}

BOOST_AUTO_TEST_CASE(sp1_block_20526626) {
    if(!do_something) return;
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

    complex_test<field_type>("vmtrace/sp1_block_20526626/", max_sizes);
}

BOOST_AUTO_TEST_CASE(sp1_block_20526627) {
    if(!do_something) return;
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

    complex_test<field_type>("vmtrace/sp1_block_20526627/", max_sizes);
}

BOOST_AUTO_TEST_CASE(sp1_block_20526628) {
    if(!do_something) return;
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

    complex_test<field_type>("vmtrace/sp1_block_20526628/", max_sizes);
}

BOOST_AUTO_TEST_CASE(sp1_block_20526629) {
    if(!do_something) return;
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

    complex_test<field_type>("vmtrace/sp1_block_20526629/", max_sizes);
}

BOOST_AUTO_TEST_CASE(sp1_block_20526630) {
    if(!do_something) return;
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

    complex_test<field_type>("vmtrace/sp1_block_20526630/", max_sizes);
}

BOOST_AUTO_TEST_CASE(sp1_block_20526631) {
    if(!do_something) return;
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

    complex_test<field_type>("vmtrace/sp1_block_20526631/", max_sizes);
}

BOOST_AUTO_TEST_CASE(sp1_block_20528708) {
    if(!do_something) return;
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

    complex_test<field_type>("vmtrace/sp1_block_20528708/", max_sizes);
}

BOOST_AUTO_TEST_CASE(sp1_block_20528709) {
    if(!do_something) return;
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

    complex_test<field_type>("vmtrace/sp1_block_20528709/", max_sizes);
}


BOOST_AUTO_TEST_CASE(sp1_block_22140743) {
    if(!do_something) return;
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

    complex_test<field_type>("vmtrace/sp1_block_22140743/", max_sizes);
}

BOOST_AUTO_TEST_SUITE_END()
