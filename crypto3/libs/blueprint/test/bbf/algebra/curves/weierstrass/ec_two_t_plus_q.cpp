//---------------------------------------------------------------------------//
// Copyright (c) 2025 Antoine Cyr <antoinecyr@nil.foundation>
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

#define BOOST_TEST_MODULE bbf_ec_two_t_plus_q_test

#include <boost/test/unit_test.hpp>
#include <nil/blueprint/bbf/circuit_builder.hpp>
#include <nil/blueprint/bbf/components/algebra/curves/weierstrass/ec_two_t_plus_q.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/secp_k1.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

using namespace nil;
using namespace nil::blueprint;

template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks,
         std::size_t bit_size_chunk>
void test_ec_two_t_plus_q(
    const std::vector<typename BlueprintFieldType::value_type>& public_input) {
    using FieldType = BlueprintFieldType;
    using TYPE = typename FieldType::value_type;
    using NON_NATIVE_TYPE = typename NonNativeFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    typedef nil::crypto3::multiprecision::big_uint<2 * NonNativeFieldType::modulus_bits>
        non_native_integral_type;

    non_native_integral_type pow = 1;

    NON_NATIVE_TYPE xT = 0, yT = 0, xQ = 0, yQ = 0;

    for (std::size_t i = 0; i < num_chunks; ++i) {
        xT +=
            non_native_integral_type(integral_type(public_input[i].to_integral())) * pow;
        yT += non_native_integral_type(
                  integral_type(public_input[i + num_chunks].to_integral())) *
              pow;
        xQ += non_native_integral_type(
                  integral_type(public_input[i + 2 * num_chunks].to_integral())) *
              pow;
        yQ += non_native_integral_type(
                  integral_type(public_input[i + 3 * num_chunks].to_integral())) *
              pow;
        pow <<= bit_size_chunk;
    }

    NON_NATIVE_TYPE diff1 = xQ - xT,
                    lambda = (diff1 == 0) ? 0 : (yQ - yT) * diff1.inversed(),
                    xS = lambda * lambda - xT - xQ, diff2 = xS - xT,
                    mu = (diff2 == 0) ? -lambda : -lambda - (2 * yT) * diff2.inversed(),
                    expected_xR = mu * mu - xT - xS,
                    expected_yR = mu * (xT - expected_xR) - yT;

    auto assign_and_check = [&](auto& B, auto& input) {
        input.xT =
            std::vector<TYPE>(public_input.begin(), public_input.begin() + num_chunks);
        input.yT = std::vector<TYPE>(public_input.begin() + num_chunks,
                                         public_input.begin() + 2 * num_chunks);
        input.xQ = std::vector<TYPE>(public_input.begin() + 2 * num_chunks,
                                         public_input.begin() + 3 * num_chunks);
        input.yQ = std::vector<TYPE>(public_input.begin() + 3 * num_chunks,
                                         public_input.begin() + 4 * num_chunks);
        input.p = std::vector<TYPE>(public_input.begin() + 4 * num_chunks,
                                        public_input.begin() + 5 * num_chunks);
        input.pp = std::vector<TYPE>(public_input.begin() + 5 * num_chunks,
                                         public_input.begin() + 6 * num_chunks);                   
        input.zero = public_input.back();

        auto [at, A, desc] = B.assign(input);
        bool pass = B.is_satisfied(at);
        std::cout << "Is_satisfied = " << pass << std::endl;

        assert(pass == true);
        non_native_integral_type xR = 0;
        non_native_integral_type yR = 0;
        pow = 1;
        for (std::size_t i = 0; i < num_chunks; i++) {
            xR += non_native_integral_type(integral_type(A.xR[i].to_integral())) * pow;
            yR += non_native_integral_type(integral_type(A.yR[i].to_integral())) * pow;
            pow <<= bit_size_chunk;
        }
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "Expected xR - yR: " << std::dec << expected_xR << " - "
                  << expected_yR << std::endl;
        std::cout << "Real res xR - yR:  " << std::dec << xR << " - " << yR << std::endl;
#endif
        assert(xR == expected_xR.to_integral());
        assert(yR == expected_yR.to_integral());
    };

    if constexpr (std::is_same_v<NonNativeFieldType,
                                 crypto3::algebra::curves::pallas::base_field_type>) {
        typename bbf::components::pallas_ec_two_t_plus_q<
            FieldType, bbf::GenerationStage::ASSIGNMENT>::input_type input;

        auto B =
            bbf::circuit_builder<FieldType, bbf::components::pallas_ec_two_t_plus_q,
                                 std::size_t, std::size_t>(num_chunks, bit_size_chunk);

        assign_and_check(B, input);
    } else if constexpr (std::is_same_v<
                             NonNativeFieldType,
                             crypto3::algebra::curves::vesta::base_field_type>) {
        typename bbf::components::vesta_ec_two_t_plus_q<
            FieldType, bbf::GenerationStage::ASSIGNMENT>::input_type input;
        auto B =
            bbf::circuit_builder<FieldType, bbf::components::vesta_ec_two_t_plus_q,
                                 std::size_t, std::size_t>(num_chunks, bit_size_chunk);

        assign_and_check(B, input);
    } else if constexpr (std::is_same_v<
                             NonNativeFieldType,
                             crypto3::algebra::curves::secp_k1<256>::base_field_type>) {
        typename bbf::components::secp_k1_256_ec_two_t_plus_q<
            FieldType, bbf::GenerationStage::ASSIGNMENT>::input_type input;
        auto B =
            bbf::circuit_builder<FieldType, bbf::components::secp_k1_256_ec_two_t_plus_q,
                                 std::size_t, std::size_t>(num_chunks, bit_size_chunk);

        assign_and_check(B, input);
    }
}

template<typename BlueprintFieldType, typename Curve, std::size_t num_chunks,
         std::size_t bit_size_chunk, std::size_t RandomTestsAmount>
void ec_two_t_plus_q_tests() {
    using NonNativeFieldType = typename Curve::base_field_type;
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    using foreign_value_type = typename Curve::scalar_field_type::value_type;
    using foreign_integral_type = typename NonNativeFieldType::integral_type;
    using ec_point_value_type = typename Curve::template g1_type<
        nil::crypto3::algebra::curves::coordinates::affine>::value_type;

    typedef nil::crypto3::multiprecision::big_uint<2 * NonNativeFieldType::modulus_bits>
        extended_integral_type;

    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<typename Curve::scalar_field_type> generate_random(
        seed_seq);
    boost::random::uniform_int_distribution<> t_dist(0, 1);

    extended_integral_type mask = (extended_integral_type(1) << bit_size_chunk) - 1;

    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        std::vector<typename BlueprintFieldType::value_type> public_input;

        extended_integral_type extended_base = 1,
                               ext_pow = extended_base << (num_chunks * bit_size_chunk),
                               p = NonNativeFieldType::modulus, pp = ext_pow - p;

        foreign_value_type d = generate_random();
        ec_point_value_type T = ec_point_value_type::one(),
                            Q = ec_point_value_type::one();
        T = T * d;
        Q = Q * d;

        public_input.resize(7 * num_chunks);
        foreign_integral_type xT = foreign_integral_type(T.X.to_integral());
        foreign_integral_type yT = foreign_integral_type(T.Y.to_integral());
        foreign_integral_type xQ = foreign_integral_type(Q.X.to_integral());
        foreign_integral_type yQ = foreign_integral_type(Q.Y.to_integral());
        for (std::size_t j = 0; j < num_chunks; j++) {
            public_input[j] = value_type(xT & mask);
            xT >>= bit_size_chunk;

            public_input[1 * num_chunks + j] = value_type(yT & mask);
            yT >>= bit_size_chunk;

            public_input[2 * num_chunks + j] = value_type(xQ & mask);
            xQ >>= bit_size_chunk;

            public_input[3 * num_chunks + j] = value_type(yQ & mask);
            yQ >>= bit_size_chunk;

            public_input[4 * num_chunks + j] = value_type(p & mask);
            p >>= bit_size_chunk;

            public_input[5 * num_chunks + j] = value_type(pp & mask);
            pp >>= bit_size_chunk;
        }
        public_input[6 * num_chunks] = value_type(0);

        test_ec_two_t_plus_q<BlueprintFieldType, NonNativeFieldType, num_chunks,
                             bit_size_chunk>(public_input);
    }
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_ec_two_t_plus_q_test) {
    // The curve is passed in as an argument to access additionnal properties
    using pallas = typename crypto3::algebra::curves::pallas;
    using vesta = typename crypto3::algebra::curves::vesta;
    using secp_k1_256 = typename crypto3::algebra::curves::secp_k1<256>;

    ec_two_t_plus_q_tests<pallas::base_field_type, vesta, 8, 32, random_tests_amount>();

    ec_two_t_plus_q_tests<pallas::base_field_type, vesta, 4, 65, random_tests_amount>();

    ec_two_t_plus_q_tests<vesta::base_field_type, pallas, 4, 65, random_tests_amount>();

    ec_two_t_plus_q_tests<vesta::base_field_type, pallas, 12, 22, random_tests_amount>();

    ec_two_t_plus_q_tests<pallas::base_field_type, secp_k1_256, 3, 96, random_tests_amount>();

    ec_two_t_plus_q_tests<vesta::base_field_type, secp_k1_256, 3, 96, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()
