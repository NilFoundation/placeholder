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
#include <nil/blueprint/zkevm_bbf/rw.hpp>
#include <nil/blueprint/zkevm_bbf/copy.hpp>
#include <nil/blueprint/zkevm_bbf/zkevm.hpp>
#include <nil/blueprint/zkevm_bbf/bytecode.hpp>
#include <nil/blueprint/zkevm_bbf/keccak.hpp>
#include <nil/blueprint/zkevm_bbf/input_generators/hardhat_input_generator.hpp>

#include "./test_l1_wrapper.hpp"

using namespace nil::crypto3;
using namespace nil::blueprint;

class zkEVMRWTestFixture: public BBFTestFixture {
public:
    zkEVMRWTestFixture():BBFTestFixture(){}

    template <typename field_type>
    void test_zkevm_rw(
        std::vector<std::string> paths,
        std::size_t max_rw_size
    ){
        auto [bytecodes, traces] = load_hardhat_input(paths[0]);
        for( std::size_t i = 1; i < paths.size(); i++ ){
            auto [bytecodes_next, traces_next] = load_hardhat_input(paths[i]);
            bytecodes.insert(bytecodes.end(), bytecodes_next.begin(), bytecodes_next.end());
            traces.insert(traces.end(), traces_next.begin(), traces_next.end());
        }

        nil::blueprint::bbf::zkevm_hardhat_input_generator circuit_inputs(bytecodes, traces);

        typename nil::blueprint::bbf::rw<field_type, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type rw_trace = circuit_inputs.rw_operations();
        typename nil::blueprint::bbf::rw<field_type, nil::blueprint::bbf::GenerationStage::CONSTRAINTS>::input_type null_input;

        std::cout << "rw_trace size = " <<  rw_trace.size() << std::endl;
        bool result = test_bbf_component<field_type, nil::blueprint::bbf::rw>(
            "rw", {}, rw_trace, null_input, max_rw_size, 0
        );
        BOOST_ASSERT(result); // Max_rw, Max_mpt
    }
};

BOOST_FIXTURE_TEST_SUITE(blueprint_bbf_rw, zkEVMRWTestFixture)
    using field_type = typename algebra::curves::pallas::base_field_type;
    using integral_type = typename field_type::integral_type;
    using value_type = typename field_type::value_type;
BOOST_AUTO_TEST_CASE(minimal_math){
    test_zkevm_rw<field_type>({"minimal_math/"}, 500);
}

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
}
BOOST_AUTO_TEST_SUITE_END()
