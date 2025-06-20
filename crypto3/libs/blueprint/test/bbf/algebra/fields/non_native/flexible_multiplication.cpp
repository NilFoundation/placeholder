//---------------------------------------------------------------------------//
// Copyright (c) 2024 Polina Chernyshova <pockvokhbtra@nil.foundation>
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

#define BOOST_TEST_MODULE bbf_flexible_multiplication_test

#include <boost/test/unit_test.hpp>
#include <nil/blueprint/bbf/circuit_builder.hpp>
#include <nil/blueprint/bbf/components/algebra/fields/non_native/flexible_multiplication.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/secp_k1.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/babybear.hpp>
#include <nil/crypto3/algebra/fields/goldilocks.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

using namespace nil;
using namespace nil::blueprint;

template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks,
         std::size_t bit_size_chunk, bool to_pass = true>
void test_mult(const std::vector<typename BlueprintFieldType::value_type> &public_input) {
    using FieldType = BlueprintFieldType;
    using TYPE = typename FieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    using extended_integral_type =
        nil::crypto3::multiprecision::big_uint<2 * NonNativeFieldType::modulus_bits>;

    extended_integral_type x = 0, y = 0, p = 0, pow = 1;

    // Populate x, y, p
    for (std::size_t i = 0; i < num_chunks; ++i) {
        x += extended_integral_type(integral_type(public_input[i].to_integral())) * pow;
        y += extended_integral_type(
                 integral_type(public_input[i + num_chunks].to_integral())) *
             pow;
        p += extended_integral_type(
                 integral_type(public_input[i + 2 * num_chunks].to_integral())) *
             pow;
        pow <<= bit_size_chunk;
    }

    extended_integral_type r = x * y % p;

    auto assign_and_check = [&](auto &B, auto &input) {
        input.x =
            std::vector<TYPE>(public_input.begin(), public_input.begin() + num_chunks);
        input.y = std::vector<TYPE>(public_input.begin() + num_chunks,
                                        public_input.begin() + 2 * num_chunks);
        input.p = std::vector<TYPE>(public_input.begin() + 2 * num_chunks,
                                        public_input.begin() + 3 * num_chunks);
        input.pp = std::vector<TYPE>(public_input.begin() + 3 * num_chunks,
                                         public_input.begin() + 4 * num_chunks);
        input.zero = public_input[4 * num_chunks];

        auto [at, A, desc] = B.assign(input);
        bool pass = B.is_satisfied(at);
        std::cout << "Is_satisfied = " << pass << std::endl;

        assert(pass == to_pass);

        if (to_pass) {
            assert(pass == true);
            extended_integral_type R = 0;
            pow = 1;
            for (std::size_t i = 0; i < num_chunks; i++) {
                R += extended_integral_type(integral_type(A.r[i].to_integral())) * pow;
                pow <<= bit_size_chunk;
            }
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
            std::cout << "Flexible multiplication test" << std::endl;
            std::cout << "Expected res: " << std::dec << r << std::endl;
            std::cout << "Real res:     " << std::dec << R << std::endl;
#endif
            assert(r == R);
        }
    };

    if constexpr (std::is_same_v<NonNativeFieldType,
                                 crypto3::algebra::curves::pallas::base_field_type>) {
        typename bbf::components::pallas_flexible_multiplication<
            FieldType, bbf::GenerationStage::ASSIGNMENT>::input_type input;

        auto B =
            bbf::circuit_builder<FieldType,
                                 bbf::components::pallas_flexible_multiplication,
                                 std::size_t, std::size_t>(num_chunks, bit_size_chunk);

        assign_and_check(B, input);
    } else if constexpr (std::is_same_v<
                             NonNativeFieldType,
                             crypto3::algebra::curves::vesta::base_field_type>) {
        typename bbf::components::vesta_flexible_multiplication<
            FieldType, bbf::GenerationStage::ASSIGNMENT>::input_type input;

        auto B =
            bbf::circuit_builder<FieldType,
                                 bbf::components::vesta_flexible_multiplication,
                                 std::size_t, std::size_t>(num_chunks, bit_size_chunk);

        assign_and_check(B, input);
    }
}

template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks,
         std::size_t bit_size_chunk, std::size_t RandomTestsAmount>
void mult_tests() {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    using foreign_value_type = typename NonNativeFieldType::value_type;
    typedef nil::crypto3::multiprecision::big_uint<2 * NonNativeFieldType::modulus_bits>
        extended_integral_type;

    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<NonNativeFieldType> generate_random(
        seed_seq);
    boost::random::uniform_int_distribution<> t_dist(0, 1);
    extended_integral_type mask = (extended_integral_type(1) << bit_size_chunk) - 1;

    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        std::vector<typename BlueprintFieldType::value_type> public_input;

        foreign_value_type src_x = generate_random(), src_y = generate_random();

        extended_integral_type x = src_x.to_integral(),
                               y = src_y.to_integral(),
                               extended_base = 1,
                               ext_pow = extended_base << (num_chunks * bit_size_chunk),
                               p = NonNativeFieldType::modulus,
                               pp = ext_pow - p;

        public_input.resize(5 * num_chunks);
        // public_input should contain x,y,p,pp,zero
        for (std::size_t j = 0; j < num_chunks; j++) {
            public_input[j] = value_type(x & mask);
            x >>= bit_size_chunk;

            public_input[num_chunks + j] = value_type(y & mask);
            y >>= bit_size_chunk;

            public_input[2 * num_chunks + j] = value_type(p & mask);
            p >>= bit_size_chunk;

            public_input[3 * num_chunks + j] = value_type(pp & mask);
            pp >>= bit_size_chunk;

            public_input[4 * num_chunks + j] = value_type(0);
        }

        test_mult<BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk>(
            public_input);
    }
}

template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks,
         std::size_t bit_size_chunk, std::size_t RandomTestsAmount>
void mult_tests_to_fail() {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    using foreign_value_type = typename NonNativeFieldType::value_type;
    using foreign_integral_type = typename NonNativeFieldType::integral_type;
    typedef nil::crypto3::multiprecision::big_uint<2 * NonNativeFieldType::modulus_bits>
        extended_integral_type;

    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<NonNativeFieldType> generate_random(
        seed_seq);
    boost::random::uniform_int_distribution<> t_dist(0, 1);
    extended_integral_type mask = (extended_integral_type(1) << bit_size_chunk) - 1;

    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        std::vector<typename BlueprintFieldType::value_type> public_input;

        foreign_value_type src_x = generate_random(), src_y = generate_random();

        extended_integral_type x = src_x.to_integral(),
                               y = src_y.to_integral(),
                               extended_base = 1,
                               ext_pow = extended_base << (num_chunks * bit_size_chunk),
                               p = NonNativeFieldType::modulus,
                               // Forcing the test to fail by substracting pp by 1
                               pp = ext_pow - p - 1;

        public_input.resize(4 * num_chunks + 1);
        for (std::size_t j = 0; j < num_chunks; j++) {
            public_input[j] = value_type(x & mask);
            x >>= (bit_size_chunk);

            public_input[num_chunks + j] = value_type(y & mask);
            y >>= bit_size_chunk;

            public_input[2 * num_chunks + j] = value_type(p & mask);
            p >>= bit_size_chunk;

            public_input[3 * num_chunks + j] = value_type(pp & mask);
            pp >>= bit_size_chunk;
        }
        public_input.push_back(value_type(0));  // the zero

        test_mult<BlueprintFieldType, NonNativeFieldType, num_chunks, bit_size_chunk,
                  false>(public_input);
    }
}
constexpr static const std::size_t random_tests_amount = 5;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_flexible_multiplication_test) {
    using pallas_field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using vesta_field_type = typename crypto3::algebra::curves::vesta::base_field_type;
    using secp256k1_field_type = typename crypto3::algebra::curves::secp256k1::base_field_type;
    using crypto3::algebra::fields::goldilocks;
    using crypto3::algebra::fields::babybear;

    std::cout << "Scenario 1\n";
    mult_tests<pallas_field_type, vesta_field_type, 3, 96, random_tests_amount>();

    std::cout << "Scenario 2\n";
    mult_tests<pallas_field_type, vesta_field_type, 5, 64, random_tests_amount>();

    std::cout << "Scenario 3\n";
    mult_tests<vesta_field_type, pallas_field_type, 4, 65, random_tests_amount>();

    std::cout << "Scenario 4\n";
    mult_tests<vesta_field_type, pallas_field_type, 5, 63, random_tests_amount>();

    std::cout << "Scenario 5\n";
    mult_tests<goldilocks, secp256k1_field_type, 16, 29, random_tests_amount>();

    std::cout << "Scenario 6\n";
    mult_tests<babybear, secp256k1_field_type, 41, 12, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_flexible_multiplication_test_to_fail) {
    using pallas_field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using secp256k1_field_type = typename crypto3::algebra::curves::secp256k1::base_field_type;
    using vesta_field_type = typename crypto3::algebra::curves::vesta::base_field_type;
    using crypto3::algebra::fields::goldilocks;
    using crypto3::algebra::fields::babybear;

    std::cout << "Scenario 1\n";
    mult_tests_to_fail<pallas_field_type, vesta_field_type, 4, 64, random_tests_amount>();

    std::cout << "Scenario 2\n";
    mult_tests_to_fail<pallas_field_type, vesta_field_type, 5, 64, random_tests_amount>();

    std::cout << "Scenario 3\n";
    mult_tests_to_fail<vesta_field_type, pallas_field_type, 4, 65, random_tests_amount>();

    std::cout << "Scenario 4\n";
    mult_tests_to_fail<vesta_field_type, pallas_field_type, 5, 63, random_tests_amount>();

    std::cout << "Scenario 5\n";
    mult_tests_to_fail<goldilocks, secp256k1_field_type, 16, 29, random_tests_amount>();

    std::cout << "Scenario 6\n";
    mult_tests_to_fail<babybear, secp256k1_field_type, 41, 12, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()
