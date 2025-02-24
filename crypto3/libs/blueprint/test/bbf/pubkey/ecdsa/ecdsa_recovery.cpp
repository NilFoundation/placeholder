//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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

#define BOOST_TEST_MODULE bbf_ecdsa_recovery_test

#include <boost/test/unit_test.hpp>
#include <nil/blueprint/zkevm/zkevm_word.hpp>
#include <nil/blueprint/bbf/circuit_builder.hpp>
#include <nil/blueprint/bbf/components/pubkey/ecdsa/ecdsa_recovery.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/curves/secp_k1.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

using namespace nil;
using namespace nil::blueprint;

template<typename FieldType, typename CurveType, std::size_t num_chunks,
         std::size_t bit_size_chunk>
void test_ecdsa_recovery(
    typename CurveType::scalar_field_type::value_type z,
    typename CurveType::scalar_field_type::value_type r,
    typename CurveType::scalar_field_type::value_type s,
    typename CurveType::scalar_field_type::value_type v,
    typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type QA,
    bool to_pass = true) {

    using foreign_basic_integral_type = typename CurveType::scalar_field_type::integral_type;
    typedef nil::crypto3::multiprecision::big_uint<2 *
                                                   CurveType::scalar_field_type::modulus_bits>
        foreign_integral_type;
    using TYPE = typename FieldType::value_type;
    using integral_type = typename FieldType::integral_type;

    using BaseField = typename CurveType::base_field_type;

    std::vector<TYPE> public_input;

    foreign_integral_type B = foreign_integral_type(1) << bit_size_chunk,
                          zf = foreign_integral_type(foreign_basic_integral_type(z.data)),
                          rf = foreign_integral_type(foreign_basic_integral_type(r.data)),
                          sf = foreign_integral_type(foreign_basic_integral_type(s.data)),
                          vf = foreign_integral_type(foreign_basic_integral_type(v.data));

    auto chunks_to_public_input = [&public_input, &B](foreign_integral_type &t) {
        for(std::size_t i = 0; i < num_chunks; i++) {
            public_input.push_back(TYPE(t % B));
            t /= B;
            
        }
    };
    chunks_to_public_input(zf);
    chunks_to_public_input(rf);
    chunks_to_public_input(sf);
    public_input.push_back(TYPE(vf));

    auto assign_and_check = [&](auto& B, auto& raw_input) {
        raw_input.z =
            std::vector<TYPE>(public_input.begin(), public_input.begin() + num_chunks);
        raw_input.r = std::vector<TYPE>(public_input.begin() + num_chunks,
                                        public_input.begin() + 2 * num_chunks);
        raw_input.s = std::vector<TYPE>(public_input.begin() + 2 * num_chunks,
                                        public_input.begin() + 3 * num_chunks);
        raw_input.v = public_input[3 * num_chunks];

        auto [at, A, desc] = B.assign(raw_input);

        if (to_pass) {
            BOOST_TEST(B.is_satisfied(at), "constraints are not satisfied");
        }

        if (to_pass){
            foreign_integral_type xQA = 0, yQA = 0, pow = 1;
            for (std::size_t i = 0; i < num_chunks; i++) {
                xQA += foreign_integral_type(integral_type(A.xQA[i].data)) * pow;
                yQA += foreign_integral_type(integral_type(A.yQA[i].data)) * pow;
                pow <<= bit_size_chunk;
            }
//#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
            std::cout << "expected: " << QA.X.data << " " << QA.Y.data << "\n";
            std::cout << "real    : " << xQA << " " << yQA << "\n";
            std::cout << "c = " << A.c << "\n\n";
//#endif
            if (!A.c.is_zero()) {
                BOOST_TEST(QA.X.data == xQA);
                BOOST_TEST(QA.Y.data == yQA);
            }
        }
    };

    if constexpr (std::is_same_v<BaseField,
                                 crypto3::algebra::curves::pallas::base_field_type>) {
        typename bbf::components::pallas_ecdsa_recovery<
            FieldType, bbf::GenerationStage::ASSIGNMENT>::raw_input_type raw_input;

        auto B =
            bbf::circuit_builder<FieldType, bbf::components::pallas_ecdsa_recovery,
                                 std::size_t, std::size_t>(num_chunks, bit_size_chunk);

        assign_and_check(B, raw_input);
    } else if constexpr (std::is_same_v<
                             BaseField,
                             crypto3::algebra::curves::vesta::base_field_type>) {
        typename bbf::components::vesta_ecdsa_recovery<
            FieldType, bbf::GenerationStage::ASSIGNMENT>::raw_input_type raw_input;
        auto B =
            bbf::circuit_builder<FieldType, bbf::components::vesta_ecdsa_recovery,
                                 std::size_t, std::size_t>(num_chunks, bit_size_chunk);

        assign_and_check(B, raw_input);
    } else if constexpr (std::is_same_v<
                             BaseField,
                             crypto3::algebra::curves::secp_k1<256>::base_field_type>) {
        typename bbf::components::secp_k1_256_ecdsa_recovery<
            FieldType, bbf::GenerationStage::ASSIGNMENT>::raw_input_type raw_input;
        auto B =
            bbf::circuit_builder<FieldType, bbf::components::secp_k1_256_ecdsa_recovery,
                                 std::size_t, std::size_t>(num_chunks, bit_size_chunk);

        assign_and_check(B, raw_input);
    }
}


template<typename FieldType, typename CurveType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t RandomTestAmount> void multi_test_recovery() {
    nil::crypto3::random::algebraic_engine<typename CurveType::scalar_field_type> generate_random_scalar;

    boost::random::mt19937 seed_seq;
    generate_random_scalar.seed(seed_seq);

    using ec_point_value_type = typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type;
    using scalar_value_type = typename CurveType::scalar_field_type::value_type;
    using scalar_integral_type = typename CurveType::scalar_field_type::integral_type;
    using base_integral_type = typename CurveType::base_field_type::integral_type;

    scalar_value_type d, z, k, r, s, v;
    scalar_integral_type n = CurveType::scalar_field_type::modulus,
                         m = (n-1)/2 + 1;
    ec_point_value_type G = ec_point_value_type::one(),
                        QA, R;


    for (std::size_t i = 0; i < RandomTestAmount; i++) {
        d = generate_random_scalar(); // private key
        QA = G*d; // public key

        z = generate_random_scalar(); // instead of taking part of the hash we just generate a random number

        do {
           k = generate_random_scalar(); // this random generation is part of the signature procedure
           R = G*k;
           v = scalar_value_type(scalar_integral_type(R.Y.data) % 2);
           r = base_integral_type(R.X.data);
           s = k.inversed() * (z + r*d);
        } while(r.is_zero() || s.is_zero() || (scalar_integral_type(r.data) >= n) || (scalar_integral_type(s.data) >= m));

        std::cout << "Random test # " << (i+1) << std::endl;
        test_ecdsa_recovery<FieldType,CurveType,num_chunks,bit_size_chunk>(z,r,s,v,QA);
    }
}

template<typename FieldType, typename CurveType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t RandomTestAmount> void multi_test_recovery_invalid() {
    nil::crypto3::random::algebraic_engine<typename CurveType::scalar_field_type> generate_random_scalar;

    boost::random::mt19937 seed_seq;
    generate_random_scalar.seed(seed_seq);

    using ec_point_value_type = typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type;
    using scalar_value_type = typename CurveType::scalar_field_type::value_type;
    using scalar_integral_type = typename CurveType::scalar_field_type::integral_type;
    using base_value_type = typename CurveType::base_field_type::value_type;
    using base_integral_type = typename CurveType::base_field_type::integral_type;

    scalar_value_type d, z, k, r, s, v;
    scalar_integral_type n = CurveType::scalar_field_type::modulus,
                         m = (n-1)/2 + 1;
    ec_point_value_type G = ec_point_value_type::one(),
                        QA, R;
    base_value_type a = CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::params_type::b;

    for (std::size_t i = 0; i < RandomTestAmount; i++) {
        std::cout << "Random test # " << (i+1) << std::endl;
        d = generate_random_scalar(); // private key
        QA = G*d; // public key

        z = generate_random_scalar(); // instead of taking part of the hash we just generate a random number

        std::cout << "Invalid with s > n/2" << std::endl;
        do {
           k = generate_random_scalar(); // this random generation is part of the signature procedure
           R = G*k;
           v = scalar_value_type(scalar_integral_type(R.Y.data) % 2);
           r = base_integral_type(R.X.data);
           s = k.inversed() * (z + r*d);
        } while(r.is_zero() || s.is_zero() || (scalar_integral_type(r.data) >= n) || (scalar_integral_type(s.data) < m));
        test_ecdsa_recovery<FieldType,CurveType,num_chunks,bit_size_chunk>(z,r,s,v,QA,false);

        std::cout << "Invalid off elliptic curve" << std::endl;
        do {
           k = generate_random_scalar(); // this random generation is part of the signature procedure
           R = G*k;
           v = scalar_value_type(scalar_integral_type(R.Y.data) % 2);
           r = base_integral_type(R.X.data);
           s = k.inversed() * (z + r*d);
        } while(r.is_zero() || s.is_zero() || (scalar_integral_type(r.data) >= n) || (scalar_integral_type(s.data) >= m));

        base_value_type x1 = base_integral_type(r.data);
        while((x1*x1*x1 + a).is_square()) {
            x1 = x1 + 1;
        }
        
        test_ecdsa_recovery<FieldType,CurveType,num_chunks,bit_size_chunk>(
            z,scalar_value_type(base_integral_type(x1.data)),s,v,QA,false);  
    }
}

template<typename FieldType, typename CurveType, std::size_t num_chunks, std::size_t bit_size_chunk> void test_real_data() {
    using ec_point_value_type = typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type;
    using scalar_value_type = typename CurveType::scalar_field_type::value_type;

    scalar_value_type z, r, s, v;
    z = 0x0a0a207c037b61815ce0d1fd1be660806002b16ce4b714fe7ff5f3f929324c5b_big_uint256;
    r = 0xcf03d98f88bb7c12d9c73212891852dd7b4bc0681f1f7d77d0098ebf3627c6_big_uint256;
    s = 0x47d6ecfa1eebf313349c9c79d53342b0fc42939c7e10556ee97296c00b3eee_big_uint256;
    v = 0x01_big_uint256;

    ec_point_value_type QA;
    QA.X = 0x3059732f1ab47f8e34a1919cf621f074d479722dcd0c63dd5d3100dd1372bd1c_big_uint256;
    QA.Y = 0xdd6003a72e6ba49073e2286c645acf5d93417b1c3c7a0fda81246469ae3b7f2f_big_uint256;

    std::cout << "Test real data: hash = " << z << ", r = " << r << ", s = " << s << ", v = " << v
        << ", QA.X = " << QA.X << ", QA.Y = " << QA.Y << std::endl;

    test_ecdsa_recovery<FieldType,CurveType,num_chunks,bit_size_chunk>(z,r,s,v,QA);
}

constexpr static const std::size_t random_tests_amount = 1;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_pubkey_non_native_ecdsa_vesta) {
    using vesta = typename crypto3::algebra::curves::vesta;
    using pallas_base_field = typename crypto3::algebra::curves::pallas::base_field_type;

    //<base_field_type,curve_type, num_chunks, bit_size_chunk, random_tests_amount>
    //multi_test_recovery<pallas_base_field,vesta, 3, 96, random_tests_amount>();

    //multi_test_recovery_invalid<pallas_base_field,vesta, 3, 96, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_pubkey_non_native_ecdsa_pallas) {
    using pallas = typename crypto3::algebra::curves::pallas;
    using vesta_field_type = typename crypto3::algebra::curves::vesta::base_field_type;

    // <base_field_type,curve_type, num_chunks, bit_size_chunk, random_tests_amount>
    //multi_test_recovery<vesta_field_type,pallas, 3, 96, random_tests_amount>();

    //multi_test_recovery_invalid<vesta_field_type,pallas, 3, 96, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_pubkey_non_native_ecdsa_secp_k1_256) {
    using secp_k1_256 = typename crypto3::algebra::curves::secp_k1<256>;
    using pallas_base_field = typename crypto3::algebra::curves::pallas::base_field_type;

    test_real_data<pallas_base_field, secp_k1_256, 3, 96>();
}

BOOST_AUTO_TEST_SUITE_END()