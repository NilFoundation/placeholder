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

#define BOOST_TEST_MODULE bbf_ec_scalar_mult_test

#include <boost/test/unit_test.hpp>
#include <nil/blueprint/bbf/circuit_builder.hpp>
#include <nil/blueprint/bbf/components/algebra/curves/weierstrass/ec_scalar_mult.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/secp_k1.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

using namespace nil;
using namespace nil::blueprint;

template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks,
         std::size_t bit_size_chunk>
void test_ec_scalar_mult(
    const std::vector<typename BlueprintFieldType::value_type>& public_input,
    typename NonNativeFieldType::integral_type expected_xR,
    typename NonNativeFieldType::integral_type expected_yR) {
    using FieldType = BlueprintFieldType;
    using TYPE = typename FieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    typedef nil::crypto3::multiprecision::big_uint<2 *
                                                   NonNativeFieldType::modulus_bits>
        non_native_integral_type;

    auto assign_and_check = [&](auto& B, auto& input) {
        input.s =
            std::vector<TYPE>(public_input.begin(), public_input.begin() + num_chunks);
        input.x = std::vector<TYPE>(public_input.begin() + num_chunks,
                                        public_input.begin() + 2 * num_chunks);
        input.y = std::vector<TYPE>(public_input.begin() + 2 * num_chunks,
                                        public_input.begin() + 3 * num_chunks);
        input.p = std::vector<TYPE>(public_input.begin() + 3 * num_chunks,
                                        public_input.begin() + 4 * num_chunks);
        input.pp = std::vector<TYPE>(public_input.begin() + 4 * num_chunks,
                                         public_input.begin() + 5 * num_chunks);
        input.n = std::vector<TYPE>(public_input.begin() + 5 * num_chunks,
                                        public_input.begin() + 6 * num_chunks);
        input.mp = std::vector<TYPE>(public_input.begin() + 6 * num_chunks,
                                         public_input.begin() + 7 * num_chunks);
        input.zero = public_input.back();

        auto [at, A, desc] = B.assign(input);
        bool pass = B.is_satisfied(at);
        std::cout << "Is_satisfied = " << pass << std::endl;

        assert(pass == true);
        non_native_integral_type xR = 0, yR = 0, pow = 1;
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
        assert(xR == expected_xR);
        assert(yR == expected_yR);
    };

    if constexpr (std::is_same_v<NonNativeFieldType,
                                 crypto3::algebra::curves::pallas::base_field_type>) {
        typename bbf::components::pallas_ec_scalar_mult<
            FieldType, bbf::GenerationStage::ASSIGNMENT>::input_type input;

        auto B =
            bbf::circuit_builder<FieldType, bbf::components::pallas_ec_scalar_mult,
                                 std::size_t, std::size_t>(num_chunks, bit_size_chunk);

        assign_and_check(B, input);
    } else if constexpr (std::is_same_v<
                             NonNativeFieldType,
                             crypto3::algebra::curves::vesta::base_field_type>) {
        typename bbf::components::vesta_ec_scalar_mult<
            FieldType, bbf::GenerationStage::ASSIGNMENT>::input_type input;
        auto B =
            bbf::circuit_builder<FieldType, bbf::components::vesta_ec_scalar_mult,
                                 std::size_t, std::size_t>(num_chunks, bit_size_chunk);

        assign_and_check(B, input);
    } else if constexpr (std::is_same_v<
                             NonNativeFieldType,
                             crypto3::algebra::curves::secp_k1<256>::base_field_type>) {
        typename bbf::components::secp_k1_256_ec_scalar_mult<
            FieldType, bbf::GenerationStage::ASSIGNMENT>::input_type input;
        auto B =
            bbf::circuit_builder<FieldType, bbf::components::secp_k1_256_ec_scalar_mult,
                                 std::size_t, std::size_t>(num_chunks, bit_size_chunk);

        assign_and_check(B, input);
    }
}

template<typename BlueprintFieldType, typename CurveType, std::size_t num_chunks,
         std::size_t bit_size_chunk, std::size_t RandomTestsAmount>
void ec_scalar_mult_tests() {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;

    using ec_point_value_type = typename CurveType::template g1_type<
        nil::crypto3::algebra::curves::coordinates::affine>::value_type;
    using scalar_value_type = typename CurveType::scalar_field_type::value_type;
    using foreign_integral_type = typename CurveType::base_field_type::integral_type;

    typedef nil::crypto3::multiprecision::big_uint<2 *
                                                   CurveType::base_field_type::modulus_bits>
        extended_integral_type;
    typedef nil::crypto3::multiprecision::big_uint<2 *
                                                   CurveType::scalar_field_type::modulus_bits>
        scalar_integral_type;

    nil::crypto3::random::algebraic_engine<typename CurveType::scalar_field_type>
        generate_random_scalar;
    boost::random::mt19937 seed_seq;
    generate_random_scalar.seed(seed_seq);

    extended_integral_type mask = (extended_integral_type(1) << bit_size_chunk) - 1;

    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        std::vector<value_type> public_input;

        extended_integral_type extended_base = 1,
                               ext_pow = extended_base << (num_chunks * bit_size_chunk),
                               p = CurveType::base_field_type::modulus, pp = ext_pow - p;

        scalar_integral_type n = CurveType::scalar_field_type::modulus,
                             s_ext_pow = scalar_integral_type(1)
                                         << (num_chunks * bit_size_chunk),
                             m = (n - 1) / 2 + 1, mp = s_ext_pow - m;

        scalar_value_type S = generate_random_scalar(), D = generate_random_scalar();
        ec_point_value_type P = ec_point_value_type::one() * D, R = P * S;

        public_input.resize(8 * num_chunks);
        foreign_integral_type s = foreign_integral_type(S.to_integral());
        foreign_integral_type x = foreign_integral_type(P.X.to_integral());
        foreign_integral_type y = foreign_integral_type(P.Y.to_integral());
        foreign_integral_type xR = foreign_integral_type(R.X.to_integral());
        foreign_integral_type yR = foreign_integral_type(R.Y.to_integral());
        for (std::size_t j = 0; j < num_chunks; j++) {
            public_input[j] = value_type(s & mask);
            s >>= bit_size_chunk;

            public_input[num_chunks + j] = value_type(x & mask);
            x >>= bit_size_chunk;

            public_input[2 * num_chunks + j] = value_type(y & mask);
            y >>= bit_size_chunk;

            public_input[3 * num_chunks + j] = value_type(p & mask);
            p >>= bit_size_chunk;

            public_input[4 * num_chunks + j] = value_type(pp & mask);
            pp >>= bit_size_chunk;

            public_input[5 * num_chunks + j] = value_type(n & mask);
            n >>= bit_size_chunk;

            public_input[6 * num_chunks + j] = value_type(mp & mask);
            mp >>= bit_size_chunk;
        }

        public_input[7 * num_chunks] = value_type(0);

        test_ec_scalar_mult<BlueprintFieldType, typename CurveType::base_field_type,
                            num_chunks, bit_size_chunk>(public_input, xR, yR);
    }
}

constexpr static const std::size_t random_tests_amount = 1;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_ec_scalar_mult_test) {
    // The curve is passed in as an argument to access additionnal properties
    using pallas = typename crypto3::algebra::curves::pallas;
    using vesta = typename crypto3::algebra::curves::vesta;
    using secp_k1_256 = typename crypto3::algebra::curves::secp_k1<256>;


    ec_scalar_mult_tests<pallas::base_field_type, vesta, 3, 96, random_tests_amount>();
    ec_scalar_mult_tests<vesta::base_field_type, pallas, 3, 96, random_tests_amount>();
    ec_scalar_mult_tests<pallas::base_field_type, secp_k1_256, 3, 96, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()
