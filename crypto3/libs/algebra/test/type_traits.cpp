//---------------------------------------------------------------------------//
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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

#define BOOST_TEST_MODULE type_traits_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>
#include <boost/container/vector.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/jubjub.hpp>
#include <nil/crypto3/algebra/curves/babyjubjub.hpp>
#include <nil/crypto3/algebra/curves/secp_k1.hpp>
#include <nil/crypto3/algebra/curves/secp_r1.hpp>
#include <nil/crypto3/algebra/curves/ed25519.hpp>


#include <nil/crypto3/algebra/fields/fp2.hpp>
#include <nil/crypto3/algebra/fields/fp3.hpp>
#include <nil/crypto3/algebra/fields/fp4.hpp>
#include <nil/crypto3/algebra/fields/fp6_3over2.hpp>
#include <nil/crypto3/algebra/fields/fp6_2over3.hpp>
#include <nil/crypto3/algebra/fields/fp12_2over3over2.hpp>

#include <nil/crypto3/algebra/fields/babybear.hpp>
#include <nil/crypto3/algebra/fields/goldilocks.hpp>
#include <nil/crypto3/algebra/fields/koalabear.hpp>
#include <nil/crypto3/algebra/fields/mersenne31.hpp>

#include <nil/crypto3/algebra/type_traits.hpp>

using namespace nil::crypto3::algebra;

BOOST_AUTO_TEST_SUITE(type_traits_manual_tests)
/**/


template<typename value_type>
void test_field_value_types()
{
   BOOST_ASSERT( has_type_field_type<value_type>::value );
   BOOST_ASSERT( (has_function_is_zero<const value_type, bool>::value) );
   BOOST_ASSERT( (has_function_inversed<const value_type, value_type>::value) );
   BOOST_ASSERT( (has_static_member_function_zero<value_type, const value_type&>::value) );
   BOOST_ASSERT( (has_static_member_function_one<value_type, const value_type&>::value) );

   BOOST_ASSERT( is_field_element<value_type>::value );
}

template<typename field_type>
void test_field_types()
{
    BOOST_ASSERT( has_type_value_type<field_type>::value );
    BOOST_ASSERT( has_type_integral_type<field_type>::value );
    BOOST_ASSERT( has_type_modular_type<field_type>::value );

    BOOST_ASSERT( (has_static_member_data_value_bits<field_type, const std::size_t>::value) );
    BOOST_ASSERT( (has_static_member_data_modulus_bits<field_type, const std::size_t>::value) );
    BOOST_ASSERT( (has_static_member_data_arity<field_type, const std::size_t>::value) );

    BOOST_ASSERT( is_field<field_type>::value );

    test_field_value_types<typename field_type::value_type>();

}

template<typename field_type>
void test_extended_field_types()
{
    test_field_types<field_type>();

    BOOST_ASSERT( has_type_extension_policy<field_type>::value );
    BOOST_ASSERT( is_extended_field<field_type>::value );

    BOOST_ASSERT( is_extended_field_element<typename field_type::value_type>::value );

    test_field_value_types<typename field_type::value_type>();
}


template<typename curve_group_type>
void test_curve_group_types()
{
    BOOST_ASSERT( is_curve_group<curve_group_type>::value );
    BOOST_ASSERT( has_type_curve_type<curve_group_type>::value );

    BOOST_ASSERT( has_type_value_type<curve_group_type>::value );
    using value_type = typename curve_group_type::value_type;

    BOOST_ASSERT( has_type_field_type<value_type>::value );
    BOOST_ASSERT( has_type_group_type<value_type>::value );

    BOOST_ASSERT( (has_static_member_function_zero<value_type, value_type>::value) );
    BOOST_ASSERT( (has_static_member_function_one<value_type, value_type>::value) );
    BOOST_ASSERT( (has_function_is_zero<const value_type, bool>::value) );
    BOOST_ASSERT( (has_function_is_well_formed<const value_type, bool>::value) );
    BOOST_ASSERT( (has_function_double_inplace<value_type, void>::value) );

    BOOST_ASSERT( is_curve_element<value_type>::value );

}

template<typename curve_type>
void test_ordinary_curve_types()
{
    BOOST_ASSERT( has_type_base_field_type<curve_type>::value );
    test_field_types<typename curve_type::base_field_type>();

    BOOST_ASSERT( has_type_scalar_field_type<curve_type>::value );
    test_field_types<typename curve_type::scalar_field_type>();

    BOOST_ASSERT( has_type_g1_type<curve_type>::value );
    test_curve_group_types<typename curve_type::template g1_type<>>();

    BOOST_ASSERT(is_curve<curve_type>::value);
}

template<typename curve_type>
void test_pairing_friendly_curve_types()
{
    test_ordinary_curve_types<curve_type>();

    BOOST_ASSERT( has_type_g2_type<curve_type>::value );
    test_curve_group_types<typename curve_type::template g2_type<>>();

    using g2_base_field = typename curve_type::template g2_type<>::params_type::field_type;
    test_extended_field_types<g2_base_field>();

    BOOST_ASSERT( has_type_gt_type<curve_type>::value );
    test_extended_field_types<typename curve_type::gt_type>();
}

BOOST_AUTO_TEST_CASE(pasta_type_traits) {
    test_ordinary_curve_types<curves::pallas>();
    test_ordinary_curve_types<curves::vesta>();
}

BOOST_AUTO_TEST_CASE(bls12_type_traits) {
    test_pairing_friendly_curve_types<curves::bls12<381>>();
    test_pairing_friendly_curve_types<curves::bls12<377>>();
}

BOOST_AUTO_TEST_CASE(mnt_type_traits) {
    test_pairing_friendly_curve_types<curves::mnt4<298>>();
    test_pairing_friendly_curve_types<curves::mnt6<298>>();
}

BOOST_AUTO_TEST_CASE(alt_bn128_type_traits) {
    test_pairing_friendly_curve_types<curves::alt_bn128<254>>();
}

BOOST_AUTO_TEST_CASE(jubjub_type_traits) {
    test_ordinary_curve_types<curves::jubjub>();
}

BOOST_AUTO_TEST_CASE(babyjubjub_type_traits) {
    test_ordinary_curve_types<curves::babyjubjub>();
}

BOOST_AUTO_TEST_CASE(goldilocks_field_type_traits) {
    test_field_types<fields::goldilocks>();
}

BOOST_AUTO_TEST_CASE(mersenne31_field_type_traits) {
    test_field_types<fields::mersenne31>();
}

BOOST_AUTO_TEST_CASE(koalabear_field_type_traits) {
    test_field_types<fields::koalabear>();
}

BOOST_AUTO_TEST_CASE(babybear_field_type_traits) { test_field_types<fields::babybear>(); }

BOOST_AUTO_TEST_CASE(secp_type_traits) {
    test_ordinary_curve_types<curves::secp160r1>();
    test_ordinary_curve_types<curves::secp192r1>();
    test_ordinary_curve_types<curves::secp224r1>();
    test_ordinary_curve_types<curves::secp256r1>();
    test_ordinary_curve_types<curves::secp384r1>();
    test_ordinary_curve_types<curves::secp521r1>();

    test_ordinary_curve_types<curves::secp160k1>();
    test_ordinary_curve_types<curves::secp192k1>();
    test_ordinary_curve_types<curves::secp224k1>();
    test_ordinary_curve_types<curves::secp256k1>();
}

BOOST_AUTO_TEST_CASE(ed25519_type_traits) {
    test_ordinary_curve_types<curves::ed25519>();
}

#define FIELD_HAS_SQRT(field) \
    (has_function_sqrt<const field::value_type, field::value_type>::value)

BOOST_AUTO_TEST_CASE(test_extended_fields_sqrt_trait) {

    BOOST_ASSERT( FIELD_HAS_SQRT(curves::alt_bn128_254::base_field_type) );
    BOOST_ASSERT( FIELD_HAS_SQRT(curves::alt_bn128_254::scalar_field_type) );
    BOOST_ASSERT( FIELD_HAS_SQRT(curves::alt_bn128_254::template g1_type<>::field_type) );
    BOOST_ASSERT( FIELD_HAS_SQRT(curves::alt_bn128_254::template g2_type<>::field_type) );
    BOOST_ASSERT( !FIELD_HAS_SQRT(curves::alt_bn128_254::gt_type) );

    BOOST_ASSERT( FIELD_HAS_SQRT(curves::bls12_381::base_field_type) );
    BOOST_ASSERT( FIELD_HAS_SQRT(curves::bls12_381::scalar_field_type) );
    BOOST_ASSERT( FIELD_HAS_SQRT(curves::bls12_381::template g1_type<>::field_type) );
    BOOST_ASSERT( FIELD_HAS_SQRT(curves::bls12_381::template g2_type<>::field_type) );
    BOOST_ASSERT( !FIELD_HAS_SQRT(curves::bls12_381::gt_type) );

    BOOST_ASSERT( FIELD_HAS_SQRT(curves::bls12_377::base_field_type) );
    BOOST_ASSERT( FIELD_HAS_SQRT(curves::bls12_377::scalar_field_type) );
    BOOST_ASSERT( FIELD_HAS_SQRT(curves::bls12_377::template g1_type<>::field_type) );
    BOOST_ASSERT( FIELD_HAS_SQRT(curves::bls12_377::template g2_type<>::field_type) );
    BOOST_ASSERT( !FIELD_HAS_SQRT(curves::bls12_377::gt_type) );

    BOOST_ASSERT( FIELD_HAS_SQRT(curves::mnt4_298::base_field_type) );
    BOOST_ASSERT( FIELD_HAS_SQRT(curves::mnt4_298::scalar_field_type) );
    BOOST_ASSERT( FIELD_HAS_SQRT(curves::mnt4_298::template g1_type<>::field_type) );
    BOOST_ASSERT( FIELD_HAS_SQRT(curves::mnt4_298::template g2_type<>::field_type) );
    BOOST_ASSERT( !FIELD_HAS_SQRT(curves::mnt4_298::gt_type) );

    BOOST_ASSERT( FIELD_HAS_SQRT(curves::mnt6_298::base_field_type) );
    BOOST_ASSERT( FIELD_HAS_SQRT(curves::mnt6_298::scalar_field_type) );
    BOOST_ASSERT( FIELD_HAS_SQRT(curves::mnt6_298::template g1_type<>::field_type) );
    BOOST_ASSERT( FIELD_HAS_SQRT(curves::mnt6_298::template g2_type<>::field_type) );
    BOOST_ASSERT( !FIELD_HAS_SQRT(curves::mnt6_298::gt_type) );

    BOOST_ASSERT( FIELD_HAS_SQRT(curves::pallas::base_field_type) );
    BOOST_ASSERT( FIELD_HAS_SQRT(curves::pallas::scalar_field_type) );
    BOOST_ASSERT( FIELD_HAS_SQRT(curves::pallas::template g1_type<>::field_type) );

    BOOST_ASSERT( FIELD_HAS_SQRT(curves::vesta::base_field_type) );
    BOOST_ASSERT( FIELD_HAS_SQRT(curves::vesta::scalar_field_type) );
    BOOST_ASSERT( FIELD_HAS_SQRT(curves::vesta::template g1_type<>::field_type) );

    BOOST_ASSERT( FIELD_HAS_SQRT(curves::jubjub::base_field_type) );
    BOOST_ASSERT( FIELD_HAS_SQRT(curves::jubjub::scalar_field_type) );
    BOOST_ASSERT( FIELD_HAS_SQRT(curves::jubjub::template g1_type<>::field_type) );

    BOOST_ASSERT( FIELD_HAS_SQRT(curves::babyjubjub::base_field_type) );
    BOOST_ASSERT( FIELD_HAS_SQRT(curves::babyjubjub::scalar_field_type) );
    BOOST_ASSERT( FIELD_HAS_SQRT(curves::babyjubjub::template g1_type<>::field_type) );

    BOOST_ASSERT( FIELD_HAS_SQRT(curves::ed25519::base_field_type) );
    BOOST_ASSERT( FIELD_HAS_SQRT(curves::ed25519::scalar_field_type) );
    BOOST_ASSERT( FIELD_HAS_SQRT(curves::ed25519::template g1_type<>::field_type) );

    BOOST_ASSERT(FIELD_HAS_SQRT(fields::goldilocks));
    BOOST_ASSERT(FIELD_HAS_SQRT(fields::mersenne31));
    BOOST_ASSERT(FIELD_HAS_SQRT(fields::koalabear));
    BOOST_ASSERT(FIELD_HAS_SQRT(fields::babybear));
}

BOOST_AUTO_TEST_CASE(test_extended_fields_trait) {

    BOOST_ASSERT( !is_extended_field_element<curves::alt_bn128_254::base_field_type::value_type>::value );
    BOOST_ASSERT( !is_extended_field_element<curves::alt_bn128_254::scalar_field_type::value_type>::value );
    BOOST_ASSERT( !is_extended_field_element<curves::alt_bn128_254::template g1_type<>::field_type::value_type>::value );
    BOOST_ASSERT( is_extended_field_element<curves::alt_bn128_254::template g2_type<>::field_type::value_type>::value );
    BOOST_ASSERT( is_extended_field_element<curves::alt_bn128_254::gt_type::value_type>::value );

    BOOST_ASSERT( !is_extended_field_element<curves::bls12_381::base_field_type::value_type>::value );
    BOOST_ASSERT( !is_extended_field_element<curves::bls12_381::scalar_field_type::value_type>::value );
    BOOST_ASSERT( !is_extended_field_element<curves::bls12_381::template g1_type<>::field_type::value_type>::value );
    BOOST_ASSERT( is_extended_field_element<curves::bls12_381::template g2_type<>::field_type::value_type>::value );
    BOOST_ASSERT( is_extended_field_element<curves::bls12_381::gt_type::value_type>::value );

    BOOST_ASSERT( !is_extended_field_element<curves::bls12_377::base_field_type::value_type>::value );
    BOOST_ASSERT( !is_extended_field_element<curves::bls12_377::scalar_field_type::value_type>::value );
    BOOST_ASSERT( !is_extended_field_element<curves::bls12_377::template g1_type<>::field_type::value_type>::value );
    BOOST_ASSERT( is_extended_field_element<curves::bls12_377::template g2_type<>::field_type::value_type>::value );
    BOOST_ASSERT( is_extended_field_element<curves::bls12_377::gt_type::value_type>::value );

    BOOST_ASSERT( !is_extended_field_element<curves::mnt4_298::base_field_type::value_type>::value );
    BOOST_ASSERT( !is_extended_field_element<curves::mnt4_298::scalar_field_type::value_type>::value );
    BOOST_ASSERT( !is_extended_field_element<curves::mnt4_298::template g1_type<>::field_type::value_type>::value );
    BOOST_ASSERT( is_extended_field_element<curves::mnt4_298::template g2_type<>::field_type::value_type>::value );
    BOOST_ASSERT( is_extended_field_element<curves::mnt4_298::gt_type::value_type>::value );

    BOOST_ASSERT( !is_extended_field_element<curves::mnt6_298::base_field_type::value_type>::value );
    BOOST_ASSERT( !is_extended_field_element<curves::mnt6_298::scalar_field_type::value_type>::value );
    BOOST_ASSERT( !is_extended_field_element<curves::mnt6_298::template g1_type<>::field_type::value_type>::value );
    BOOST_ASSERT( is_extended_field_element<curves::mnt6_298::template g2_type<>::field_type::value_type>::value );
    BOOST_ASSERT( is_extended_field_element<curves::mnt6_298::gt_type::value_type>::value );

    BOOST_ASSERT( !is_extended_field_element<curves::pallas::base_field_type::value_type>::value );
    BOOST_ASSERT( !is_extended_field_element<curves::pallas::scalar_field_type::value_type>::value );
    BOOST_ASSERT( !is_extended_field_element<curves::pallas::template g1_type<>::field_type::value_type>::value );

    BOOST_ASSERT( !is_extended_field_element<curves::vesta::base_field_type::value_type>::value );
    BOOST_ASSERT( !is_extended_field_element<curves::vesta::scalar_field_type::value_type>::value );
    BOOST_ASSERT( !is_extended_field_element<curves::vesta::template g1_type<>::field_type::value_type>::value );

    BOOST_ASSERT( !is_extended_field_element<curves::jubjub::base_field_type::value_type>::value );
    BOOST_ASSERT( !is_extended_field_element<curves::jubjub::scalar_field_type::value_type>::value );
    BOOST_ASSERT( !is_extended_field_element<curves::jubjub::template g1_type<>::field_type::value_type>::value );

    BOOST_ASSERT( !is_extended_field_element<curves::babyjubjub::base_field_type::value_type>::value );
    BOOST_ASSERT( !is_extended_field_element<curves::babyjubjub::scalar_field_type::value_type>::value );
    BOOST_ASSERT( !is_extended_field_element<curves::babyjubjub::template g1_type<>::field_type::value_type>::value );

    BOOST_ASSERT( !is_extended_field_element<curves::ed25519::base_field_type::value_type>::value );
    BOOST_ASSERT( !is_extended_field_element<curves::ed25519::scalar_field_type::value_type>::value );
    BOOST_ASSERT( !is_extended_field_element<curves::ed25519::template g1_type<>::field_type::value_type>::value );

    BOOST_ASSERT(!is_extended_field_element<fields::goldilocks::value_type>::value);
    BOOST_ASSERT(!is_extended_field_element<fields::mersenne31::value_type>::value);
    BOOST_ASSERT(!is_extended_field_element<fields::koalabear::value_type>::value);
    BOOST_ASSERT(!is_extended_field_element<fields::babybear::value_type>::value);
}



BOOST_AUTO_TEST_SUITE_END()
