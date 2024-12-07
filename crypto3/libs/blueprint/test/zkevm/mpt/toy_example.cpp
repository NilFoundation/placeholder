//---------------------------------------------------------------------------//
// Copyright (c) 2024 Georgios Fotiadis <gfotiadis@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_detail_mpt_nonce_changed_test

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>
#include <typeinfo>

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/alt_bn128/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/fields/goldilocks64/base_field.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_permutation.hpp>
#include <nil/crypto3/hash/poseidon.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/zkevm/mpt/toy_verifier.hpp>

#include "../../test_plonk_component.hpp"

#include <iostream>  
#include <sstream> // use stringstream class  

using namespace nil;
using namespace nil::crypto3::hashes::detail;

template <typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t account_trie_length, std::size_t WitnessColumns>
void test_mpt_nonce_changed(const std::vector<typename BlueprintFieldType::value_type> &public_input){
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 2;
    constexpr std::size_t SelectorColumns = 5;

    zk::snark::plonk_table_description<BlueprintFieldType> desc(WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);

    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;
 
    using component_type = blueprint::components::mpt_nonce_changed<ArithmetizationType, BlueprintFieldType, num_chunks, bit_size_chunk, account_trie_length>;

    size_t public_input_index = 0;

    typename component_type::input_type instance_input;
    instance_input.eth_address = var(0, public_input_index, false, var::column_type::public_input);
    public_input_index += 1; 

    integral_type B = integral_type(1) << bit_size_chunk; // the representation base
    value_type expected_res[num_chunks], carry[num_chunks];

    auto result_check = [&expected_res, &carry, &public_input](AssignmentType &assignment, typename component_type::result_type &real_res) {
        for(std::size_t i = 0; i < num_chunks; i++) {
            // BOOST_ASSERT(var_value(assignment, real_res.z[i]) == expected_res[i]);
        }
        // BOOST_ASSERT(var_value(assignment, real_res.ck) == carry[num_chunks-1]);
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }

    component_type component_instance(witnesses, // witnesses
                                      std::array<std::uint32_t, 0>{}, // constants
                                      std::array<std::uint32_t, 0>{}  // public inputs
                                     );

    nil::crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>
        (component_instance, desc, public_input, result_check, instance_input, nil::blueprint::connectedness_check_type::type::NONE);
}



template <typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t account_trie_length, std::size_t WitnessColumns, std::size_t RandomTestsAmount>
void mpt_nonce_changed_case_1_tests() {
    using integral_type = typename BlueprintFieldType::integral_type;
    using value_type = typename BlueprintFieldType::value_type;
    integral_type chunk_size = (integral_type(1) << bit_size_chunk);

    using policy = poseidon_policy<BlueprintFieldType, 128, /*Rate=*/ 4>;
    using hash_t = hashes::poseidon<policy>;   

    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random(seed_seq);
    std::random_device rd;
    std::mt19937_64 gen(rd());

    //random 160-bit integer for ethereum address
    using namespace boost::random;
    typedef independent_bits_engine<mt19937, 160, uint256_t> generator_type;
    generator_type gen_160;

    for (std::size_t test_count = 0; test_count < RandomTestsAmount; test_count++) {
        std::cout << "==================" << std::endl;  
        std::cout << "Example Number: " << test_count << std::endl;  
        std::cout << "==================" << std::endl;  

        std::cout << "account_trie_length = " << account_trie_length << std::endl;
        // ethereumAddress: first 160-bits of user's public key
        uint256_t ethAddress = gen_160();
        std::string address_string = boost::multiprecision::to_string(ethAddress);

        // convert strings to value_type
        nil::marshalling::status_type status;
        typedef typename boost::multiprecision::cpp_int_modular_backend<255> modular_backend_of_required_size;
        value_type eth_address = nil::marshalling::pack(ethAddress, status);
        std::cout << "eth_address = " << eth_address << std::endl;

        // fill in public_input
        std::vector<typename BlueprintFieldType::value_type> public_input = {};
        public_input.push_back(eth_address);
        std::cout << "#public_input = " << public_input.size() << std::endl;

        test_mpt_nonce_changed<BlueprintFieldType,num_chunks,bit_size_chunk,account_trie_length,WitnessColumns>(public_input);
        std::cout << "\n" << std::endl;
    }
}

constexpr static const std::size_t random_tests_amount = 40;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_equality_flag_test) {
    // using bls12_381_field_type = typename crypto3::algebra::curves::bls12<381>::scalar_field_type;
    using bn_254_field_type = nil::crypto3::algebra::fields::alt_bn128_scalar_field<254>;

    // std::cout << "*** Case 1: BLS12-381 scalar field\n";
    // mpt_nonce_changed_case_1_tests<bls12_381_field_type, 4, 16, 17, 24, random_tests_amount>();

    std::cout << "*** Case 2: BN-254 scalar field\n";
    mpt_nonce_changed_case_1_tests<bn_254_field_type, 4, 16, 12, 24, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()