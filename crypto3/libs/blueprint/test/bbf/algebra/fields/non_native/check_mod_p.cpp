//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
// Copyright (c) 2024 Antoine Cyr <antoine.cyr@nil.foundation>
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

#define BOOST_TEST_MODULE bbf_check_mod_p_test

#include <boost/test/unit_test.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/bbf/components/algebra/fields/non_native/check_mod_p.hpp>

#include <nil/blueprint/bbf/circuit_builder.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>

using namespace nil;
using namespace nil::blueprint;


template <typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, bool to_pass = true, bool is_overflow = false>
void test_mod_p_check(const std::vector<typename BlueprintFieldType::value_type> &public_input){

    using FieldType = BlueprintFieldType;
    using TYPE = typename FieldType::value_type;
    typename bbf::components::check_mod_p<FieldType,bbf::GenerationStage::ASSIGNMENT>::raw_input_type raw_input;
    raw_input.x = std::vector<TYPE>(public_input.begin(), public_input.begin() + num_chunks);
    raw_input.pp = std::vector<TYPE>(public_input.begin() + num_chunks, public_input.begin() + 2 * num_chunks);
    auto B = bbf::circuit_builder<FieldType,bbf::components::check_mod_p, std::size_t, std::size_t, bool>(num_chunks,bit_size_chunk,is_overflow);
    auto [at, A, desc] = B.assign(raw_input);
    bool pass = B.is_satisfied(at);
    std::cout << "Is_satisfied = " << pass << std::endl;

    if (to_pass) {
        assert(B.is_satisfied(at) == true);
        bool proof = B.check_proof(at, desc);
        std::cout << "Is_proved = " << proof << std::endl;
         assert(proof == true);
    } else {
        assert(B.is_satisfied(at) == false);
    }
}


template <typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t RandomTestsAmount, bool is_overflow>
void mod_p_check_tests() {
    using integral_type = typename BlueprintFieldType::integral_type;
    using value_type = typename BlueprintFieldType::value_type;

    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random(seed_seq);
    boost::random::uniform_int_distribution<> t_dist(0, 1);
    const integral_type B = integral_type(1) << bit_size_chunk;

    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        std::vector<typename BlueprintFieldType::value_type> public_input;
        integral_type p = integral_type(generate_random().data);
        p = (p == 0) ? 1 : p; // avoid p == 0

        integral_type x = is_overflow ? p + 1:(integral_type(generate_random().data) % p);

        for(std::size_t j = 0; j < num_chunks; j++) { // the x's
            public_input.push_back(value_type(x % B));
            x /= B;
        }
        for(std::size_t j = 0; j < num_chunks; j++) { // the pp's
            public_input.push_back(value_type(B - (j > 0) - (p % B))); // these are B-base digits of (2^{kb} - p)
            p /= B;
        }


        //Test pass, gives the expected overflow
        test_mod_p_check<BlueprintFieldType,num_chunks,bit_size_chunk,true,is_overflow>(public_input);
        //Test fails, gives the opposite overflow
        test_mod_p_check<BlueprintFieldType,num_chunks,bit_size_chunk,false,!is_overflow>(public_input);
    }
}

//constexpr static const std::size_t random_tests_amount = 10;
constexpr static const std::size_t random_tests_amount = 1;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_equality_flag_test) {
    using pallas_field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using vesta_field_type = typename crypto3::algebra::curves::vesta::base_field_type;

    mod_p_check_tests<pallas_field_type, 8, 32, random_tests_amount,false>();
    mod_p_check_tests<pallas_field_type, 4, 65, random_tests_amount,false>();
    mod_p_check_tests<pallas_field_type, 5, 63, random_tests_amount,false>();

    mod_p_check_tests<vesta_field_type, 2, 252, random_tests_amount,false>();
    mod_p_check_tests<vesta_field_type, 12, 22, random_tests_amount,false>();
    mod_p_check_tests<vesta_field_type, 2, 129, random_tests_amount,false>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_field_operations_test_with_overflow) {
    using pallas_field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using vesta_field_type = typename crypto3::algebra::curves::vesta::base_field_type;

    mod_p_check_tests<pallas_field_type, 9, 30, random_tests_amount,true>();
    mod_p_check_tests<pallas_field_type, 12, 22, random_tests_amount,true>();
    mod_p_check_tests<pallas_field_type, 2, 128, random_tests_amount,true>();

    mod_p_check_tests<vesta_field_type, 2, 252, random_tests_amount,true>();
    mod_p_check_tests<vesta_field_type, 2, 220, random_tests_amount,true>();
    mod_p_check_tests<vesta_field_type, 4, 65, random_tests_amount,true>();
}

BOOST_AUTO_TEST_SUITE_END()