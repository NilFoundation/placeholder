//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE crypto3_marshalling_field_element_test

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <iostream>
#include <iomanip>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/marshalling/algorithms/pack.hpp>
#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

template<typename T, typename Endianness>
void test_field_element(T val) {

    using namespace nil::crypto3::marshalling;

    using unit_type = unsigned char;
    using field_element_type = types::field_element<nil::crypto3::marshalling::field_type<Endianness>,
        T>;

    static_assert(nil::crypto3::algebra::is_field_element<T>::value);
    static_assert(nil::crypto3::marshalling::is_field_element<field_element_type>::value);
    static_assert(nil::crypto3::marshalling::is_compatible<T>::value);
    
    using inferenced_type = typename nil::crypto3::marshalling::is_compatible<T>::template type<Endianness>;

    static_assert(std::is_same<inferenced_type, field_element_type>::value);

    nil::crypto3::marshalling::status_type status;
    std::vector<unit_type> cv = nil::crypto3::marshalling::pack<Endianness>(val, status);

    BOOST_CHECK(status == nil::crypto3::marshalling::status_type::success);

    T test_val = nil::crypto3::marshalling::pack<Endianness>(cv, status);

    BOOST_CHECK(val == test_val);
    BOOST_CHECK(status == nil::crypto3::marshalling::status_type::success);
}

template<typename T, typename Endianness>
void test_field_element_vector() {

    using namespace nil::crypto3::marshalling;

    using unit_type = unsigned char;
    std::vector<typename T::value_type> vec(16);

    for(auto &v : vec) {
        v = nil::crypto3::algebra::random_element<T>();
    }

    nil::crypto3::marshalling::status_type status;
    std::vector<unit_type> cv = nil::crypto3::marshalling::pack<Endianness>(vec, status);

    BOOST_CHECK(status == nil::crypto3::marshalling::status_type::success);

    std::vector<typename T::value_type> test_val = nil::crypto3::marshalling::pack<Endianness>(cv, status);

    BOOST_CHECK(vec == test_val);
    BOOST_CHECK(status == nil::crypto3::marshalling::status_type::success);
}


template<typename FieldType, typename Endianness>
void test_field_element() {
    for (unsigned i = 0; i < 128; ++i) {
        typename FieldType::value_type val = nil::crypto3::algebra::random_element<FieldType>();
        test_field_element<typename FieldType::value_type, Endianness>(val);
    }

    test_field_element_vector<FieldType, Endianness>();
}

BOOST_AUTO_TEST_SUITE(field_element_test_suite)

BOOST_AUTO_TEST_CASE(field_element_bls12_381_g1_field_be) {
    test_field_element<nil::crypto3::algebra::curves::bls12<381>::g1_type<>::field_type,
                       nil::crypto3::marshalling::option::big_endian>();
}

BOOST_AUTO_TEST_CASE(field_element_bls12_381_g1_field_le) {
    test_field_element<nil::crypto3::algebra::curves::bls12<381>::g1_type<>::field_type,
                       nil::crypto3::marshalling::option::little_endian>();
}

BOOST_AUTO_TEST_CASE(field_element_bls12_381_g2_field_be) {
    test_field_element<nil::crypto3::algebra::curves::bls12<381>::g2_type<>::field_type,
                       nil::crypto3::marshalling::option::big_endian>();
}

BOOST_AUTO_TEST_CASE(field_element_bls12_381_g2_field_le) {
    test_field_element<nil::crypto3::algebra::curves::bls12<381>::g2_type<>::field_type,
                       nil::crypto3::marshalling::option::little_endian>();
}

BOOST_AUTO_TEST_SUITE_END()
