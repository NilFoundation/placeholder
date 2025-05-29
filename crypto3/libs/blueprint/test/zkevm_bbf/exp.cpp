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

#define BOOST_TEST_MODULE blueprint_plonk_exp_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/circuits/exp.hpp>

#include "./circuit_test_fixture.hpp"

using namespace nil::crypto3;
using namespace nil::blueprint;
using namespace nil::blueprint::bbf;

class zkEVMExpTestFixture: public CircuitTestFixture {
public:
    template <typename field_type>
    void test_zkevm_exp(
        const std::vector<std::pair<zkevm_word_type, zkevm_word_type>> &exps,
        std::size_t max_exponentiations,
        std::size_t max_exp_rows,
        bool expected_result = true
    ){
        bool result = test_bbf_component<field_type, exponentiation>(
            "exp",
            {} ,                   //  Public input
            exps,                  //  Assignment input
            max_exp_rows,          //  Maximum size of exp circuit
            max_exponentiations    //  Maximum rows in exponentiation dynamic lookup table
        );
        BOOST_CHECK((!check_satisfiability && !generate_proof) || result == expected_result); // Max_rw, Max_mpt
    }
};

BOOST_FIXTURE_TEST_SUITE(zkevm_bbf_exp, zkEVMExpTestFixture)
    using field_type = nil::crypto3::algebra::curves::alt_bn128_254::scalar_field_type;
BOOST_AUTO_TEST_CASE(one_exponent){
    std::vector<std::pair<zkevm_word_type, zkevm_word_type>> exp_input;
    exp_input.push_back({2, 2566798231683721});
    exp_input.push_back({3, 3});
    test_zkevm_exp<field_type>(exp_input, 50, 3000);
}
BOOST_AUTO_TEST_SUITE_END()
