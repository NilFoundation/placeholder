//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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
                            
#define BOOST_TEST_MODULE blueprint_plonk_bbf_mpt_nonce_changed_test

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
#include <nil/blueprint/zkevm_bbf/copy.hpp>
#include <nil/blueprint/zkevm_bbf/zkevm.hpp>
#include <nil/blueprint/zkevm_bbf/bytecode.hpp>
#include <nil/blueprint/zkevm_bbf/keccak.hpp>
#include <nil/blueprint/zkevm_bbf/rw.hpp>
#include <nil/blueprint/zkevm_bbf/input_generators/hardhat_input_generator.hpp>
#include <nil/blueprint/zkevm_bbf/mpt/mpt_verifier.hpp>

#include "../test_l1_wrapper.hpp"

using namespace nil::crypto3;
using namespace nil::blueprint;

class MPTTestFixture: public BBFTestFixture {
public:
    MPTTestFixture():BBFTestFixture(){}

    template <typename field_type>
    void test_mpt_nonce_changed(std::vector<typename field_type::value_type> public_input, std::size_t max_mpt)
    {
    typename nil::blueprint::bbf::mpt_verifier<field_type, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type mpt_nonce_changed_assignment_input;
    typename nil::blueprint::bbf::mpt_verifier<field_type, nil::blueprint::bbf::GenerationStage::CONSTRAINTS>::input_type mpt_nonce_changed_constraint_input;

    mpt_nonce_changed_assignment_input.rlc_challenge = 18;
    mpt_nonce_changed_assignment_input.public_input = public_input;

        bool result = test_bbf_component<field_type, nil::blueprint::bbf::mpt_verifier>(
            "MPT",
            {18},                        //  Public input
            mpt_nonce_changed_assignment_input,  //  Assignment input
            mpt_nonce_changed_constraint_input,  //  Circuit input
            max_mpt          //  Sizes
        );
        BOOST_CHECK(result); // Max_rw, Max_mpt
    }
};

// template <typename field_type>
// void test_mpt_nonce_changed(std::vector<typename field_type::value_type> public_input, std::size_t max_mpt) {
//     typename nil::blueprint::bbf::mpt_verifier<field_type, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type mpt_nonce_changed_assignment_input;
//     typename nil::blueprint::bbf::mpt_verifier<field_type, nil::blueprint::bbf::GenerationStage::CONSTRAINTS>::input_type mpt_nonce_changed_constraint_input;

//     mpt_nonce_changed_assignment_input.rlc_challenge = 18;
//     mpt_nonce_changed_assignment_input.public_input = public_input;

//     bool result = test_l1_wrapper<field_type, nil::blueprint::bbf::mpt_verifier>(
//         {7},                                 //  Public input
//         mpt_nonce_changed_assignment_input,  //  Assignment input
//         mpt_nonce_changed_constraint_input,  //  Circuit input
//         max_mpt                         //  Sizes
//         // max_keccak_blocks           //  Keccak blocks amount
//     );
// }

static const std::size_t random_tests_amount = 10;

BOOST_FIXTURE_TEST_SUITE(blueprint_plonk_test_suite, MPTTestFixture)

BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_mpt_nonce_changed_test) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    using integral_type = typename field_type::integral_type;
    using value_type = typename field_type::value_type;

    nil::crypto3::random::algebraic_engine<field_type> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);

    integral_type base16 = integral_type(1) << 16;
    auto random_input = value_type(integral_type(generate_random().data) % base16);

    std::vector<typename field_type::value_type> public_input = {};

    for (std::size_t i = 0; i < random_tests_amount; i++) {
        std::cout << "random_input = " << random_input << std::endl;
        for (std::size_t j = 0; j < 20; j++) {
            public_input.push_back(random_input);
        }
        test_mpt_nonce_changed<field_type>(public_input, 100);
    }
}

BOOST_AUTO_TEST_SUITE_END()