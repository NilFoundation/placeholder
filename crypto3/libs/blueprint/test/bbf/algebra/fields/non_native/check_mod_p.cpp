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

#define BOOST_TEST_MODULE bbf_check_mod_p_test

#include <boost/test/unit_test.hpp>
#include <nil/blueprint/bbf/circuit_builder.hpp>
#include <nil/blueprint/bbf/components/algebra/fields/non_native/check_mod_p.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

using namespace nil;
using namespace nil::blueprint;

template<typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk,
         bool to_pass = true, bool expect_output = false, bool overflow = false>
void test_mod_p_check(
    const std::vector<typename BlueprintFieldType::value_type> &public_input) {
    using FieldType = BlueprintFieldType;
    using TYPE = typename FieldType::value_type;
    typename bbf::components::check_mod_p<
        FieldType, bbf::GenerationStage::ASSIGNMENT>::input_type input;
    input.x =
        std::vector<TYPE>(public_input.begin(), public_input.begin() + num_chunks);
    input.pp = std::vector<TYPE>(public_input.begin() + num_chunks,
                                     public_input.begin() + 2 * num_chunks);
    input.zero = TYPE(0);
    auto B = bbf::circuit_builder<FieldType, bbf::components::check_mod_p, std::size_t,
                                  std::size_t, bool>(num_chunks, bit_size_chunk,
                                                     expect_output);
    auto [at, A, desc] = B.assign(input);
    bool pass = B.is_satisfied(at);
    std::cout << "Is_satisfied = " << pass << std::endl;

    assert(pass == to_pass);

    if (to_pass && expect_output) {
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "Expected output: " << std::dec << overflow << std::endl;
        std::cout << "Real output:     " << std::dec << A.output << std::endl;
#endif
        assert(overflow == A.output.to_integral());
    }
}

template<typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk,
         std::size_t RandomTestsAmount, bool overflow = false>
void mod_p_check_tests() {
    using integral_type = typename BlueprintFieldType::integral_type;
    using value_type = typename BlueprintFieldType::value_type;

    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random(
        seed_seq);
    boost::random::uniform_int_distribution<> t_dist(0, 1);
    const integral_type B = integral_type(1) << bit_size_chunk;

    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        std::vector<typename BlueprintFieldType::value_type> public_input;
        integral_type p = integral_type(generate_random().to_integral());
        p = (p == 0) ? 1 : p;  // avoid p == 0

        integral_type x =
            overflow ? p + 1 : (integral_type(generate_random().to_integral()) % p);

        for (std::size_t j = 0; j < num_chunks; j++) {  // the x's
            public_input.push_back(value_type(x % B));
            x /= B;
        }
        for (std::size_t j = 0; j < num_chunks; j++) {  // the pp's
            public_input.push_back(value_type(
                B - (j > 0) - (p % B)));  // these are B-base digits of (2^{kb} - p)
            p /= B;
        }

        // Test with output, should always succeed
        test_mod_p_check<BlueprintFieldType, num_chunks, bit_size_chunk, true, true,
                         overflow>(public_input);

        // Test without output, should fail when there is an overflow
        test_mod_p_check<BlueprintFieldType, num_chunks, bit_size_chunk, !overflow, false,
                         overflow>(public_input);
    }
}

constexpr static const std::size_t random_tests_amount = 2;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_check_mod_p_test) {
    using pallas_field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using vesta_field_type = typename crypto3::algebra::curves::vesta::base_field_type;

    mod_p_check_tests<pallas_field_type, 3, 96, random_tests_amount>();
    mod_p_check_tests<pallas_field_type, 4, 65, random_tests_amount>();
    mod_p_check_tests<pallas_field_type, 5, 63, random_tests_amount>();

    mod_p_check_tests<vesta_field_type, 2, 252, random_tests_amount>();
    mod_p_check_tests<vesta_field_type, 12, 22, random_tests_amount>();
    mod_p_check_tests<vesta_field_type, 2, 129, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_check_mod_p_test_overflow) {
    using pallas_field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using vesta_field_type = typename crypto3::algebra::curves::vesta::base_field_type;

    mod_p_check_tests<pallas_field_type, 9, 30, random_tests_amount, true>();
    mod_p_check_tests<pallas_field_type, 12, 22, random_tests_amount, true>();
    mod_p_check_tests<pallas_field_type, 2, 128, random_tests_amount, true>();

    mod_p_check_tests<vesta_field_type, 2, 252, random_tests_amount, true>();
    mod_p_check_tests<vesta_field_type, 2, 220, random_tests_amount, true>();
    mod_p_check_tests<vesta_field_type, 4, 65, random_tests_amount, true>();
}

BOOST_AUTO_TEST_SUITE_END()
