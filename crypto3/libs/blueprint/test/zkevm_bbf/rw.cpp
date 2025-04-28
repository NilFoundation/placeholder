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

#define BOOST_TEST_MODULE blueprint_plonk_rw_test
#define PROFILING_ENABLED

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

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/circuits/rw.hpp>
//#include <nil/blueprint/zkevm_bbf/rw_small_field.hpp>
#include <nil/blueprint/zkevm_bbf/input_generators/debugtt_input_generator.hpp>

#include "./circuit_test_fixture.hpp"

using namespace nil::crypto3;
using namespace nil::blueprint;
using namespace nil::blueprint::bbf;

class zkEVMRWTestFixture: public CircuitTestFixture {
public:
    template <typename field_type>
    void test_zkevm_rw(
        std::string path,
        std::size_t max_rw_size,
        std::size_t max_call_commits
    ){
        auto trace = load_debugtt_input(path);
        nil::blueprint::bbf::zkevm_debugtt_input_generator circuit_inputs(trace);

        typename nil::blueprint::bbf::rw<field_type, GenerationStage::ASSIGNMENT>::input_type rw_assignment_input;
        rw_assignment_input.rw_operations = circuit_inputs.rw_operations();
        rw_assignment_input.call_commits = circuit_inputs.call_commits();

        std::cout << "rw_trace size = " <<  rw_assignment_input.rw_operations.size() << std::endl;
        bool result = test_bbf_component<field_type, nil::blueprint::bbf::rw>(
            "rw", {}, rw_assignment_input, max_rw_size, 0, max_call_commits
        );
        BOOST_ASSERT(result); // Max_rw, Max_mpt
    }
};

BOOST_FIXTURE_TEST_SUITE(zkevm_bbf_rw, zkEVMRWTestFixture)
    using field_type = typename algebra::curves::pallas::base_field_type;
    using integral_type = typename field_type::integral_type;
    using value_type = typename field_type::value_type;
BOOST_AUTO_TEST_CASE(minimal_math){
    test_zkevm_rw<field_type>({"minimal_math.json"}, 1000, 500);
}
BOOST_AUTO_TEST_CASE(counter){
    test_zkevm_rw<field_type>({"counter.json"}, 3000, 500);
}
BOOST_AUTO_TEST_CASE(call_counter){
    test_zkevm_rw<field_type>({"call_counter.json"}, 3000, 500);
}
BOOST_AUTO_TEST_CASE(keccak){
    test_zkevm_rw<field_type>({"keccak.json"}, 5000, 500);
}
BOOST_AUTO_TEST_CASE(call_keccak){
    test_zkevm_rw<field_type>({"call_keccak.json"}, 3000, 500);
}
BOOST_AUTO_TEST_CASE(delegatecall_counter){
    test_zkevm_rw<field_type>({"delegatecall.json"}, 4000, 500);
}
BOOST_AUTO_TEST_CASE(cold_sstore){
    test_zkevm_rw<field_type>({"cold_sstore.json"}, 3000, 500);
}
BOOST_AUTO_TEST_CASE(try_catch){
    test_zkevm_rw<field_type>({"try_catch.json"}, 7000, 500);
}
BOOST_AUTO_TEST_CASE(try_catch2){
    test_zkevm_rw<field_type>({"try_catch2.json"}, 7000, 500);
}
BOOST_AUTO_TEST_CASE(try_catch_cold){
    test_zkevm_rw<field_type>({"try_catch_cold.json"}, 6000, 500);
}
/*
BOOST_AUTO_TEST_CASE(small_storage){
    test_zkevm_rw<field_type>({"small_stack_storage/"}, 500);
}

BOOST_AUTO_TEST_CASE(mstore8){
    test_zkevm_rw<field_type>({"mstore8/"}, 5000);
}

BOOST_AUTO_TEST_CASE(meminit){
    test_zkevm_rw<field_type>({"mem_init/"}, 10000);
}

BOOST_AUTO_TEST_CASE(calldatacopy){
    test_zkevm_rw<field_type>({"calldatacopy/"}, 10000);
}

BOOST_AUTO_TEST_CASE(multiple_traces){
    test_zkevm_rw<field_type>({"minimal_math/", "keccak/", "exp/"} , 3000);
}*/
BOOST_AUTO_TEST_SUITE_END()
