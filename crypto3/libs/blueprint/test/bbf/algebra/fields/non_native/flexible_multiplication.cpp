//---------------------------------------------------------------------------//
// Copyright (c) 2024 Polina Chernyshova <pockvokhbtra@nil.foundation>
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

#define BOOST_TEST_MODULE bbf_flexible_multiplication_test

#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/goldilocks64/base_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/secp_k1.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <boost/test/unit_test.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/bbf/components/algebra/fields/non_native/flexible_multiplication.hpp>

#include <nil/blueprint/bbf/circuit_builder.hpp>



using namespace nil;
using namespace nil::blueprint;

template <typename BlueprintFieldType, typename NonNativeFieldType, std::size_t double_integral_index,
        std::size_t num_chunks, std::size_t bit_size_chunk,bool to_pass = true>
void test_mult(const std::vector<typename BlueprintFieldType::value_type> &public_input){
    using FieldType = BlueprintFieldType;
    using TYPE = typename FieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    typedef nil::crypto3::multiprecision::big_uint<2 * NonNativeFieldType::modulus_bits> double_non_native_integral_type;
    
    using NonNativeIntegralVariant = std::variant<
        nil::crypto3::multiprecision::big_uint<2* crypto3::algebra::curves::pallas::base_field_type::modulus_bits>,
        nil::crypto3::multiprecision::big_uint<2* crypto3::algebra::curves::vesta::base_field_type::modulus_bits>
    >;

    double_non_native_integral_type x = 0,
                        y = 0,
                        p = 0,
                        pow = 1;
    
    for (std::size_t i = 0; i < num_chunks; ++i) {
        x += double_non_native_integral_type(integral_type(public_input[i].data)) * pow;
        y += double_non_native_integral_type(integral_type(public_input[i + num_chunks].data)) * pow;
        p += double_non_native_integral_type(integral_type(public_input[i + 2*num_chunks].data)) * pow;
        pow <<= bit_size_chunk;
    }
    
    double_non_native_integral_type r = x*y % p;

    NonNativeIntegralVariant double_non_native_integral_type_variant = NonNativeIntegralVariant{std::in_place_index<double_integral_index>};
    typename bbf::components::flexible_multiplication<FieldType,bbf::GenerationStage::ASSIGNMENT>::raw_input_type raw_input;
    raw_input.x = std::vector<TYPE>(public_input.begin(), public_input.begin() + num_chunks);
    raw_input.y = std::vector<TYPE>(public_input.begin() + num_chunks , public_input.begin() + 2*num_chunks);
    raw_input.p = std::vector<TYPE>(public_input.begin() + 2*num_chunks, public_input.begin() + 3*num_chunks);
    raw_input.pp = std::vector<TYPE>(public_input.begin() + 3*num_chunks, public_input.begin() + 4*num_chunks);
    auto B = bbf::circuit_builder<FieldType,bbf::components::flexible_multiplication,NonNativeIntegralVariant,std::size_t, std::size_t>(double_non_native_integral_type_variant,num_chunks,bit_size_chunk);
    auto [at, A, desc] = B.assign(raw_input);
    bool pass = B.is_satisfied(at);
    std::cout << "Is_satisfied = " << pass << std::endl;
    std::cout << "to_pass: " << to_pass << std::endl;

    if (to_pass) {
        assert(pass == true);
        double_non_native_integral_type R = 0;
        pow = 1;
        for(std::size_t i = 0; i < num_chunks; i++) {
            R += double_non_native_integral_type(integral_type(A.res[i].data)) * pow;
            pow <<= bit_size_chunk;
        }
    #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
    std::cout << "Flexible multiplication test" << std::endl;
    std::cout << "Expected res: " << std::dec << r << std::endl;
    std::cout << "Real res:     " << std::dec << R  << std::endl;
    #endif
    assert(r == R);
    } else {
        assert(pass == false);
    }

}

template <typename BlueprintFieldType, typename NonNativeFieldType,std::size_t double_integral_index,
        std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t RandomTestsAmount>
void mult_tests() {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    using foreign_value_type = typename NonNativeFieldType::value_type;
    using foreign_integral_type = typename NonNativeFieldType::integral_type;
    typedef nil::crypto3::multiprecision::big_uint<2 * NonNativeFieldType::modulus_bits> double_non_native_integral_type;
    

    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<NonNativeFieldType> generate_random(seed_seq);
    boost::random::uniform_int_distribution<> t_dist(0, 1);
    double_non_native_integral_type mask = (double_non_native_integral_type(1) << bit_size_chunk) - 1;

    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        std::vector<typename BlueprintFieldType::value_type> public_input;

        foreign_value_type src_x = generate_random(),
                           src_y = generate_random();

        double_non_native_integral_type x = double_non_native_integral_type(foreign_integral_type(src_x.data)),
                                       y = double_non_native_integral_type(foreign_integral_type(src_y.data)),
                                       extended_base = 1,
                                       ext_pow = extended_base << (num_chunks*bit_size_chunk),
                                       p = NonNativeFieldType::modulus,
                                       pp = ext_pow - p;

        public_input.resize(4*num_chunks); // public_input should contain x,y,p,pp
        //std::cout << "PI x = " << x << std::endl;
        //std::cout << "PI y = " << y << std::endl;
        //std::cout << "PI p = " << p << std::endl;
        for(std::size_t j = 0; j < num_chunks; j++) {
            public_input[j] = value_type(x & mask);
            x >>= bit_size_chunk;

            public_input[num_chunks + j] = value_type(y & mask);
            y >>= bit_size_chunk;

            public_input[2*num_chunks + j] = value_type(p & mask);
            p >>= bit_size_chunk;

            public_input[3*num_chunks + j] = value_type(pp & mask);
            pp >>= bit_size_chunk;
        }

        test_mult<BlueprintFieldType, NonNativeFieldType,double_integral_index,
                num_chunks, bit_size_chunk>(public_input);
    }
}

template <typename BlueprintFieldType, typename NonNativeFieldType,std::size_t double_integral_index,
        std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t RandomTestsAmount>
void mult_tests_to_fail() {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    using foreign_value_type = typename NonNativeFieldType::value_type;
    using foreign_integral_type = typename NonNativeFieldType::integral_type;
    typedef nil::crypto3::multiprecision::big_uint<2 * NonNativeFieldType::modulus_bits> double_non_native_integral_type;

    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<NonNativeFieldType> generate_random(seed_seq);
    boost::random::uniform_int_distribution<> t_dist(0, 1);
    double_non_native_integral_type mask = (double_non_native_integral_type(1) << bit_size_chunk) - 1;

    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        std::vector<typename BlueprintFieldType::value_type> public_input;

        foreign_value_type src_x = generate_random(),
                           src_y = generate_random();

        double_non_native_integral_type x = double_non_native_integral_type(foreign_integral_type(src_x.data)),
                                       y = double_non_native_integral_type(foreign_integral_type(src_y.data)),
                                       extended_base = 1,
                                       ext_pow = extended_base << (num_chunks*bit_size_chunk),
                                       p = NonNativeFieldType::modulus,
                                       //Forcing the test to fail by substracting pp by 1
                                       pp = ext_pow - p - 1;

        public_input.resize(4*num_chunks);
        for(std::size_t j = 0; j < num_chunks; j++) {
            public_input[j] = value_type(x & mask);
            x >>= (bit_size_chunk);

            public_input[num_chunks + j] = value_type(y & mask);
            y >>= bit_size_chunk;

            public_input[2*num_chunks + j] = value_type(p & mask);
            p >>= bit_size_chunk;

            public_input[3*num_chunks + j] = value_type(pp & mask);
            pp >>= bit_size_chunk;
        }

        test_mult<BlueprintFieldType, NonNativeFieldType,double_integral_index,
                num_chunks, bit_size_chunk,false>(public_input);
    }
}
constexpr static const std::size_t random_tests_amount = 5;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_flexible_multiplication_test) {
    using pallas_field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using vesta_field_type = typename crypto3::algebra::curves::vesta::base_field_type;

    std::cout << "Scenario 1\n";
    mult_tests<pallas_field_type, vesta_field_type,1, 4, 64, random_tests_amount>();

    std::cout << "Scenario 2\n";
    mult_tests<pallas_field_type, vesta_field_type, 1,5, 64, random_tests_amount>();

    std::cout << "Scenario 3\n";
    mult_tests<vesta_field_type, pallas_field_type,0, 4, 65, random_tests_amount>();

    std::cout << "Scenario 4\n";
    mult_tests<vesta_field_type, pallas_field_type,0, 5, 63, random_tests_amount>();

}

BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_flexible_multiplication_test_to_fail) {
    using pallas_field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using vesta_field_type = typename crypto3::algebra::curves::vesta::base_field_type;

    std::cout << "Scenario 1\n";
    mult_tests_to_fail<pallas_field_type, vesta_field_type,1, 4, 64, random_tests_amount>();

    std::cout << "Scenario 2\n";
    mult_tests_to_fail<pallas_field_type, vesta_field_type,1, 5, 64, random_tests_amount>();

    std::cout << "Scenario 3\n";
    mult_tests_to_fail<vesta_field_type, pallas_field_type,0, 4, 65, random_tests_amount>();

    std::cout << "Scenario 4\n";
    mult_tests_to_fail<vesta_field_type, pallas_field_type,0, 5, 63, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()