//---------------------------------------------------------------------------//
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

#define BOOST_TEST_MODULE bbf_ec_scalar_mult_test

#include <boost/test/unit_test.hpp>
#include <nil/blueprint/bbf/components/algebra/curves/weierstrass/ec_scalar_mult.hpp>
#include <nil/blueprint/bbf/circuit_builder.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>

using namespace nil;
using namespace nil::blueprint;

template<typename BlueprintFieldType, typename NonNativeFieldType, std::size_t num_chunks,
    std::size_t bit_size_chunk>
void test_ec_scalar_mult(
    const std::vector<typename BlueprintFieldType::value_type>& public_input, typename BlueprintFieldType::integral_type expected_xR, typename BlueprintFieldType::integral_type expected_yR) {
    using FieldType = BlueprintFieldType;
    using TYPE = typename FieldType::value_type;
    using NON_NATIVE_TYPE = typename NonNativeFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    using non_native_integral_type = typename BlueprintFieldType::integral_type;
    std::cout<<"test_ec_scalar_mult" << std::endl;


    auto assign_and_check = [&](auto& B, auto& raw_input) {
        std::cout<<"test_ec_scalar_mult assign" << std::endl;
        raw_input.s =
            std::vector<TYPE>(public_input.begin(), public_input.begin() + num_chunks);
        raw_input.x =
            std::vector<TYPE>(public_input.begin() + num_chunks, public_input.begin() + 2* num_chunks);
        raw_input.y =
            std::vector<TYPE>(public_input.begin() + 2* num_chunks, public_input.begin() + 3 * num_chunks);
        raw_input.p = std::vector<TYPE>(public_input.begin() + 3 * num_chunks,
            public_input.begin() + 4 * num_chunks);
        raw_input.pp = std::vector<TYPE>(public_input.begin() + 4 * num_chunks,
            public_input.begin() + 5 * num_chunks);
        raw_input.n = std::vector<TYPE>(public_input.begin() + 5 * num_chunks,
            public_input.begin() + 6 * num_chunks);
        raw_input.mp = std::vector<TYPE>(public_input.begin() + 6 * num_chunks,
            public_input.begin() + 7 * num_chunks);
        raw_input.zero = public_input[7 * num_chunks];

        std::cout<<"test_ec_scalar_mult 1" << std::endl;

        auto [at, A, desc] = B.assign(raw_input);
        std::cout<<"test_ec_scalar_mult 2" << std::endl;
        bool pass = B.is_satisfied(at);
        std::cout << "Is_satisfied = " << pass << std::endl;

        assert(pass == true);
        non_native_integral_type xR = 0,
                                yR = 0,
                                pow = 1;
        for (std::size_t i = 0; i < num_chunks; i++) {
            xR += non_native_integral_type(integral_type(A.res_xR[i].data)) * pow;
            yR += non_native_integral_type(integral_type(A.res_yR[i].data)) * pow;
            pow <<= bit_size_chunk;
        }
        //#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "Expected xR - yR: " << std::dec << expected_xR << " - " << expected_yR << std::endl;
        std::cout << "Real res xR - yR:  " << std::dec << xR << " - " << yR << std::endl;
        //#endif
        assert(xR == expected_xR);
        assert(yR == expected_yR);
        };

    if constexpr (std::is_same_v<NonNativeFieldType,
        crypto3::algebra::curves::pallas::base_field_type>) {
            std::cout<<"test_ec_scalar_mult pallas" << std::endl;
        typename bbf::components::pallas_ec_scalar_mult<
            FieldType, bbf::GenerationStage::ASSIGNMENT>::raw_input_type raw_input;

        auto B =
            bbf::circuit_builder<FieldType, bbf::components::pallas_ec_scalar_mult,
            std::size_t, std::size_t>(num_chunks, bit_size_chunk);

        assign_and_check(B, raw_input);
    }
    else if constexpr (std::is_same_v<
        NonNativeFieldType,
        crypto3::algebra::curves::vesta::base_field_type>) {
            std::cout<<"test_ec_scalar_mult vesta" << std::endl;
        typename bbf::components::vesta_ec_scalar_mult<
            FieldType, bbf::GenerationStage::ASSIGNMENT>::raw_input_type raw_input;
            std::cout<<"test_ec_scalar_mult vesta 1" << std::endl;
        auto B =
            bbf::circuit_builder<FieldType, bbf::components::vesta_ec_scalar_mult,
            std::size_t, std::size_t>(num_chunks, bit_size_chunk);
            std::cout<<"test_ec_scalar_mult vesta 2" << std::endl;
        

        assign_and_check(B, raw_input);
    }
    std::cout<<"test_ec_scalar_mult next" << std::endl;

}


template<typename BlueprintFieldType, typename Curve, std::size_t num_chunks,
    std::size_t bit_size_chunk, std::size_t RandomTestsAmount>
void ec_scalar_mult_tests() {
    using NonNativeFieldType = typename Curve::base_field_type;
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    using foreign_value_type = typename NonNativeFieldType::value_type;
    using ec_point_value_type = typename Curve::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type;
    using scalar_value_type = typename Curve::scalar_field_type::value_type;

    typedef nil::crypto3::multiprecision::big_uint<2 * NonNativeFieldType::modulus_bits>
        extended_integral_type;

    nil::crypto3::random::algebraic_engine<typename Curve::scalar_field_type> generate_random_scalar;
    boost::random::mt19937 seed_seq;
    generate_random_scalar.seed(seed_seq);

    extended_integral_type mask = (extended_integral_type(1) << bit_size_chunk) - 1;

    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        std::vector<typename BlueprintFieldType::value_type> public_input;

        extended_integral_type extended_base = 1,
            ext_pow = extended_base << (num_chunks * bit_size_chunk),
            p = NonNativeFieldType::modulus,
            pp = ext_pow - p,
            n = Curve::scalar_field_type::modulus,
            m = (n-1)/2 + 1,
            mp = ext_pow - m;


        scalar_value_type S = generate_random_scalar(),
                             D = generate_random_scalar();
        ec_point_value_type P = ec_point_value_type::one() * D,
                            R = P * S;

        public_input.resize(7 * num_chunks + 1);
        integral_type s = integral_type(S.data);
        integral_type x = integral_type(P.X.data);
        integral_type y = integral_type(P.Y.data);
        integral_type xR = integral_type(R.X.data);
        integral_type yR = integral_type(R.Y.data);
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
        public_input.push_back(value_type(0));  // the zero

        test_ec_scalar_mult<BlueprintFieldType, NonNativeFieldType, num_chunks,
            bit_size_chunk>(public_input,xR,yR);
    }
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_ec_scalar_mult_test) {
    using pallas = typename crypto3::algebra::curves::pallas;
    using vesta = typename crypto3::algebra::curves::vesta;

    ec_scalar_mult_tests<pallas::base_field_type, vesta, 8, 32,
        random_tests_amount>();

    ec_scalar_mult_tests<pallas::base_field_type, vesta, 4, 65, random_tests_amount>();

    ec_scalar_mult_tests<vesta::base_field_type, pallas, 4, 65,
        random_tests_amount>();

    ec_scalar_mult_tests<vesta::base_field_type, pallas, 12, 22,
        random_tests_amount>();

}

BOOST_AUTO_TEST_SUITE_END()
