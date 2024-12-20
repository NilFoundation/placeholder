//---------------------------------------------------------------------------//
// Copyright (c) 2024 Georgios Fotiadis <gfotiadis@nil.foundation>
// Copyright (c) 2024 Antoine Cyr <gfotiadis@nil.foundation>
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

#define BOOST_TEST_MODULE carry_on_addition_test

#include <boost/test/unit_test.hpp>
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/bbf/components/detail/carry_on_addition.hpp>

#include <nil/blueprint/bbf/circuit_builder.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>

using namespace nil;
using namespace nil::blueprint;

template <typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk>
void test_carry_on_addition(const std::vector<typename BlueprintFieldType::value_type> &public_input){
    using FieldType = BlueprintFieldType;
    using integral_type = typename FieldType::integral_type;
    using TYPE = typename FieldType::value_type;

    typename bbf::components::carry_on_addition<FieldType,bbf::GenerationStage::ASSIGNMENT>::raw_input_type raw_input;
    raw_input.x = std::vector<TYPE>(public_input.begin(), public_input.begin() + num_chunks);
    raw_input.y = std::vector<TYPE>(public_input.begin() + num_chunks, public_input.end());
    auto B = bbf::circuit_builder<FieldType,bbf::components::carry_on_addition, std::size_t, std::size_t>(num_chunks,bit_size_chunk);
    auto [at, A, desc] = B.assign(raw_input);
    bool pass = B.is_satisfied(at);
    std::cout << "Is_satisfied = " << pass << std::endl;

    assert(B.is_satisfied(at) == true);
    bool proof = B.check_proof(at, desc);
    std::cout << "Is_proved = " << proof << std::endl;
    assert(proof == true);

    integral_type BASE = integral_type(1) << bit_size_chunk; // the representation base
    TYPE expected_res[num_chunks], carry[num_chunks];
    for(std::size_t i = 0; i < num_chunks; i++) {
        expected_res[i] = public_input[i] + public_input[num_chunks + i];
        if (i > 0) {
            expected_res[i] += carry[i-1];
        }
        carry[i] = (expected_res[i] >= BASE);
        expected_res[i] -= carry[i]*BASE;
    }

    std::cout << "Carry on addition test" << std::endl;
    for(std::size_t i = 0; i < num_chunks; i++) {
        #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "Expected res: " << std::dec << expected_res[i] << std::endl;
        std::cout << "Real res:     " << std::dec << A.res[i].data  << std::endl;
        #endif
        assert(A.res_z[i].data == expected_res[i].data);
    }
    assert(carry[num_chunks-1] == A.res_c.data);
}

template <typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t RandomTestsAmount>
void carry_on_addition_tests() {
    using integral_type = typename BlueprintFieldType::integral_type;
    using value_type = typename BlueprintFieldType::value_type;
    integral_type chunk_size = (integral_type(1) << bit_size_chunk);

    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random(seed_seq);

    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        std::vector<typename BlueprintFieldType::value_type> public_input = {};
        for(std::size_t j = 0; j < 2*num_chunks; j++) {
            public_input.push_back(value_type(integral_type(generate_random().data) % chunk_size));
        }
        test_carry_on_addition<BlueprintFieldType,num_chunks,bit_size_chunk>(public_input);
    }
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_equality_flag_test_vesta) {
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;

    carry_on_addition_tests<field_type, 2, 16, random_tests_amount>();
    carry_on_addition_tests<field_type, 2, 32, random_tests_amount>();
    carry_on_addition_tests<field_type, 2, 64, random_tests_amount>();

    carry_on_addition_tests<field_type, 4, 64, random_tests_amount>();
    carry_on_addition_tests<field_type, 4, 128, random_tests_amount>();
    carry_on_addition_tests<field_type, 4, 16, random_tests_amount>();

    carry_on_addition_tests<field_type, 2, 32, random_tests_amount>();
    carry_on_addition_tests<field_type, 5, 64, random_tests_amount>();
    carry_on_addition_tests<field_type, 7, 128, random_tests_amount>();
    carry_on_addition_tests<field_type, 9, 16, random_tests_amount>();

    carry_on_addition_tests<field_type, 2, 32, random_tests_amount>();
    carry_on_addition_tests<field_type, 5, 64, random_tests_amount>();
    carry_on_addition_tests<field_type, 7, 128, random_tests_amount>();
    carry_on_addition_tests<field_type, 9, 16, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_field_operations_test_pallas) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;

    carry_on_addition_tests<field_type, 2, 16, random_tests_amount>();
    carry_on_addition_tests<field_type, 2, 32, random_tests_amount>();
    carry_on_addition_tests<field_type, 2, 64, random_tests_amount>();

    carry_on_addition_tests<field_type, 4, 64, random_tests_amount>();
    carry_on_addition_tests<field_type, 4, 128, random_tests_amount>();
    carry_on_addition_tests<field_type, 4, 16, random_tests_amount>();

    carry_on_addition_tests<field_type, 2, 32, random_tests_amount>();
    carry_on_addition_tests<field_type, 5, 64, random_tests_amount>();
    carry_on_addition_tests<field_type, 7, 128, random_tests_amount>();
    carry_on_addition_tests<field_type, 9, 16, random_tests_amount>();

    carry_on_addition_tests<field_type, 2, 32, random_tests_amount>();
    carry_on_addition_tests<field_type, 5, 64, random_tests_amount>();
    carry_on_addition_tests<field_type, 7, 128, random_tests_amount>();
    carry_on_addition_tests<field_type, 9, 16, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()