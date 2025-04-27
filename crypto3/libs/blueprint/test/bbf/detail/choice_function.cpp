//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
// Copyright (c) 2024 Antoine Cyr <antoinecyr@nil.foundation>
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

#define BOOST_TEST_MODULE choice_function_test

#include <boost/test/unit_test.hpp>
#include <nil/blueprint/bbf/circuit_builder.hpp>
#include <nil/blueprint/bbf/components/detail/choice_function.hpp>
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

using namespace nil;
using namespace nil::blueprint;

template<typename BlueprintFieldType, std::size_t num_chunks>
void test_choice_function(
    const std::vector<typename BlueprintFieldType::value_type> &public_input) {
    using FieldType = BlueprintFieldType;
    using integral_type = typename FieldType::integral_type;
    using TYPE = typename FieldType::value_type;

    typename bbf::components::choice_function<
        FieldType, bbf::GenerationStage::ASSIGNMENT>::input_type input;
    input.q = public_input[0];
    input.x = std::vector<TYPE>(public_input.begin() + 1,
                                    public_input.begin() + num_chunks + 1);
    input.y =
        std::vector<TYPE>(public_input.begin() + num_chunks + 1, public_input.end());
    auto B =
        bbf::circuit_builder<FieldType, bbf::components::choice_function, std::size_t>(
            num_chunks);

    auto [at, A, desc] = B.assign(input);
    bool pass = B.is_satisfied(at);
    std::cout << "Is_satisfied = " << pass << std::endl;

    assert(pass == true);

    TYPE expected_res[num_chunks];
    for (std::size_t i = 0; i < num_chunks; i++) {
        expected_res[i] =
            (1 - input.q) * input.x[i] + input.q * input.y[i];
    }

    for (std::size_t i = 0; i < num_chunks; i++) {
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "Expected res: " << std::dec << expected_res[i] << std::endl;
        std::cout << "Real res:     " << std::dec << A.r[i] << std::endl;
#endif
        assert(A.r[i] == expected_res[i]);
    }
}

template<typename BlueprintFieldType, std::size_t num_chunks,
         std::size_t RandomTestsAmount>
void choice_function_tests() {
    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random(
        seed_seq);
    boost::random::uniform_int_distribution<> t_dist(0, 1);

    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        std::vector<typename BlueprintFieldType::value_type> public_input = {
            t_dist(seed_seq)};  // q is the first arg (0 or 1)
        for (std::size_t j = 0; j < 2 * num_chunks; j++) {
            public_input.push_back(generate_random());
        }
        test_choice_function<BlueprintFieldType, num_chunks>(public_input);
    }
}

constexpr static const std::size_t random_tests_amount = 3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_choice_function_vesta_test) {
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;

    choice_function_tests<field_type, 2, random_tests_amount>();

    choice_function_tests<field_type, 2, random_tests_amount>();
    choice_function_tests<field_type, 5, random_tests_amount>();
    choice_function_tests<field_type, 7, random_tests_amount>();
    choice_function_tests<field_type, 9, random_tests_amount>();

    choice_function_tests<field_type, 2, random_tests_amount>();
    choice_function_tests<field_type, 5, random_tests_amount>();
    choice_function_tests<field_type, 7, random_tests_amount>();
    choice_function_tests<field_type, 9, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_choice_function_pallas_test) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;

    choice_function_tests<field_type, 2, random_tests_amount>();

    choice_function_tests<field_type, 2, random_tests_amount>();
    choice_function_tests<field_type, 5, random_tests_amount>();
    choice_function_tests<field_type, 7, random_tests_amount>();
    choice_function_tests<field_type, 9, random_tests_amount>();

    choice_function_tests<field_type, 2, random_tests_amount>();
    choice_function_tests<field_type, 5, random_tests_amount>();
    choice_function_tests<field_type, 7, random_tests_amount>();
    choice_function_tests<field_type, 9, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()
