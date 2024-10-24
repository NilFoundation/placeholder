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
#include <nil/blueprint/zkevm_bbf/rw.hpp>

#include "./test_l1_wrapper.hpp"

using namespace nil::crypto3;
using namespace nil::blueprint;

template <typename field_type>
void test_zkevm_rw(
    std::string path,
    std::size_t max_rw_size
){
    std::cout << "path = " << path << std::endl;

    std::ifstream ss;
    ss.open(path);
    boost::property_tree::ptree pt;
    boost::property_tree::read_json(ss, pt);
    ss.close();

    typename nil::blueprint::bbf::rw<field_type, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type rw_trace(pt, max_rw_size);
    typename nil::blueprint::bbf::rw<field_type, nil::blueprint::bbf::GenerationStage::CONSTRAINTS>::input_type null_input;

    std::cout << "rw_trace size = " <<  rw_trace.get_rw_ops().size() << std::endl;
    test_l1_wrapper<field_type, nil::blueprint::bbf::rw>({}, rw_trace, null_input, max_rw_size, 0); // Max_rw, Max_mpt
}


BOOST_AUTO_TEST_SUITE(blueprint_bbf_rw)
    using field_type = typename algebra::curves::pallas::base_field_type;
    using integral_type = typename field_type::integral_type;
    using value_type = typename field_type::value_type;
BOOST_AUTO_TEST_CASE(small_storage_contract){
    test_zkevm_rw<field_type>("../crypto3/libs/blueprint/test/zkevm/data/small_stack_storage.json", 500);
}

BOOST_AUTO_TEST_CASE(mstore8_contract){
    test_zkevm_rw<field_type>("../crypto3/libs/blueprint/test/zkevm/data/mstore8.json", 5000);
}

BOOST_AUTO_TEST_CASE(meminit_contract){
    test_zkevm_rw<field_type>("../crypto3/libs/blueprint/test/zkevm/data/mem_init.json", 10000);
}

BOOST_AUTO_TEST_CASE(calldatacopy_contract){
    test_zkevm_rw<field_type>("../crypto3/libs/blueprint/test/zkevm/data/calldatacopy.json", 10000);
}
BOOST_AUTO_TEST_SUITE_END()