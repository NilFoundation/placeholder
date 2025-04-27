//---------------------------------------------------------------------------//
// Copyright (c) 2024 Valeh Farzaliyev <estoniaa@nil.foundation>
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

#define BOOST_TEST_MODULE bbf_negation_mod_p_test

#include <boost/test/unit_test.hpp>
#include <nil/blueprint/bbf/circuit_builder.hpp>
#include <nil/blueprint/bbf/components/algebra/fields/non_native/negation_mod_p.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/secp_k1.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

using namespace nil;
using namespace nil::blueprint;

template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks,
         std::size_t bit_size_chunk>
void test_negation_mod_p(
    const std::vector<typename BlueprintFieldType::value_type> &public_input) {
    using FieldType = BlueprintFieldType;
    using TYPE = typename FieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    typedef nil::crypto3::multiprecision::big_uint<2 * NonNativeFieldType::modulus_bits>
        extended_integral_type;

    extended_integral_type x = 0, p = 0, pow = 1;
    // Populate x, p
    for (std::size_t i = 0; i < num_chunks; ++i) {
        x += extended_integral_type(integral_type(public_input[i].to_integral())) * pow;
        p += extended_integral_type(
                 integral_type(public_input[i + num_chunks].to_integral())) *
             pow;
        pow <<= bit_size_chunk;
    }

    extended_integral_type r = (x == 0) ? 0 : p - x;  // if x = 0, then r = 0

    auto assign_and_check = [&](auto &B, auto &input) {
        input.x =
            std::vector<TYPE>(public_input.begin(), public_input.begin() + num_chunks);
        input.p = std::vector<TYPE>(public_input.begin() + num_chunks,
                                        public_input.begin() + 2 * num_chunks);
        input.pp = std::vector<TYPE>(public_input.begin() + 2 * num_chunks,
                                         public_input.begin() + 3 * num_chunks);
        input.zero = public_input[3 * num_chunks];

        auto [at, A, desc] = B.assign(input);
        bool pass = B.is_satisfied(at);
        std::cout << "Is_satisfied = " << pass << std::endl;

        assert(pass == true);
        extended_integral_type R = 0;
        pow = 1;
        for (std::size_t i = 0; i < num_chunks; i++) {
            R += extended_integral_type(integral_type(A.r[i].to_integral())) * pow;
            pow <<= bit_size_chunk;
        }
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "negation_mod_p test" << std::endl;
        std::cout << "Expected res: " << std::dec << r << std::endl;
        std::cout << "Real res:     " << std::dec << R << std::endl;
#endif
        assert(r == R);
    };

    if constexpr (std::is_same_v<NonNativeFieldType,
                                 crypto3::algebra::curves::pallas::base_field_type>) {
        typename bbf::components::pallas_negation_mod_p<
            FieldType, bbf::GenerationStage::ASSIGNMENT>::input_type input;

        auto B =
            bbf::circuit_builder<FieldType, bbf::components::pallas_negation_mod_p,
                                 std::size_t, std::size_t>(num_chunks, bit_size_chunk);

        assign_and_check(B, input);
    } else if constexpr (std::is_same_v<
                             NonNativeFieldType,
                             crypto3::algebra::curves::vesta::base_field_type>) {
        typename bbf::components::vesta_negation_mod_p<
            FieldType, bbf::GenerationStage::ASSIGNMENT>::input_type input;
        auto B =
            bbf::circuit_builder<FieldType, bbf::components::vesta_negation_mod_p,
                                 std::size_t, std::size_t>(num_chunks, bit_size_chunk);

        assign_and_check(B, input);
    } else if constexpr (std::is_same_v<
                             NonNativeFieldType,
                             crypto3::algebra::curves::secp_k1<256>::base_field_type>) {
        typename bbf::components::secp_k1_256_negation_mod_p<
            FieldType, bbf::GenerationStage::ASSIGNMENT>::input_type input;
        auto B =
            bbf::circuit_builder<FieldType, bbf::components::secp_k1_256_negation_mod_p,
                                 std::size_t, std::size_t>(num_chunks, bit_size_chunk);

        assign_and_check(B, input);
    }
}

template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks,
         std::size_t bit_size_chunk, std::size_t RandomTestsAmount>
void negation_mod_p_tests() {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    using foreign_value_type = typename NonNativeFieldType::value_type;
    using foreign_integral_type = NonNativeFieldType::integral_type;
    typedef nil::crypto3::multiprecision::big_uint<2 * NonNativeFieldType::modulus_bits>
        extended_foreign_integral_type;

    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<NonNativeFieldType> generate_random(
        seed_seq);
    boost::random::uniform_int_distribution<> t_dist(0, 1);
    extended_foreign_integral_type mask = (extended_foreign_integral_type(1) << bit_size_chunk) - 1;

    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        std::vector<typename BlueprintFieldType::value_type> public_input;

        extended_foreign_integral_type x = extended_foreign_integral_type(
                                           foreign_integral_type(
                                               generate_random().to_integral())),
                                       extended_base = 1,
                                       ext_pow = extended_base
                                                 << (num_chunks * bit_size_chunk),
                                       p = NonNativeFieldType::modulus;
        extended_foreign_integral_type pp = ext_pow - p;

        public_input.resize(4 * num_chunks);
        for (std::size_t j = 0; j < num_chunks; j++) {
            public_input[j] = value_type(x & mask);
            x >>= bit_size_chunk;

            public_input[1 * num_chunks + j] = value_type(p & mask);
            p >>= bit_size_chunk;

            public_input[2 * num_chunks + j] = value_type(pp & mask);
            pp >>= bit_size_chunk;
        }
        public_input[3 * num_chunks] = value_type(0);  // the zero

        test_negation_mod_p<BlueprintFieldType, NonNativeFieldType, num_chunks,
                            bit_size_chunk>(public_input);
    }
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_negation_mod_p_test) {
    using pallas_field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using vesta_field_type = typename crypto3::algebra::curves::vesta::base_field_type;
    using secp_k1_256_field_type =
        typename crypto3::algebra::curves::secp_k1<256>::base_field_type;

    negation_mod_p_tests<pallas_field_type, vesta_field_type, 8, 32,
                         random_tests_amount>();

    negation_mod_p_tests<pallas_field_type, vesta_field_type, 4, 65,
                         random_tests_amount>();

    negation_mod_p_tests<pallas_field_type, secp_k1_256_field_type, 8, 34,
                         random_tests_amount>();

    negation_mod_p_tests<vesta_field_type, pallas_field_type, 2, 253,
                         random_tests_amount>();

    negation_mod_p_tests<vesta_field_type, pallas_field_type, 12, 22,
                         random_tests_amount>();

    negation_mod_p_tests<vesta_field_type, secp_k1_256_field_type, 8, 33,
                         random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()
