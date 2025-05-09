//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
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
// This example shows different field operations: addition, multiplication,
// squaring and inverting

#include <iostream>

#include <nil/crypto3/multiprecision/literals.hpp>


#include <nil/crypto3/algebra/fields/fp2.hpp>
#include <nil/crypto3/algebra/fields/fp3.hpp>
#include <nil/crypto3/algebra/fields/alt_bn128/base_field.hpp>
#include <nil/crypto3/algebra/fields/alt_bn128/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/mnt6/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt6/scalar_field.hpp>

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp2.hpp>

using namespace nil::crypto3::algebra;

template<typename FpField>
void fields_fp_basic_math_examples() {
    using policy_type = FpField;
    typedef typename policy_type::value_type value_type;

    std::cout << "Field module value: " << policy_type::modulus << std::endl;

    value_type e1 = value_type(76749407), e2(44410867), e3 = value_type::one(), e4(121160274);

    std::cout << "Field element values: " << std::endl;
    std::cout << "e1 value: " << e1 << std::endl;

    std::cout << "e2 value: " << e2 << std::endl;

    std::cout << "e3 value: " << e3 << std::endl;

    value_type e1inv = e1.inversed();

    std::cout << "e1 inversed value: " << e1inv << std::endl;

    std::cout << "e1 * e1^(-1) \n" << e1 * e1inv << std::endl;

    value_type e1e2 = e1 * e2, e1sqr = e1.squared();

    std::cout << "e1 * e2 value: " << e1e2 << std::endl;

    value_type e1sqrsqrt = e1sqr.sqrt();

    std::cout << "e1 square value: " << e1sqr << std::endl;

    std::cout << "e1 square sqrt value: " << e1sqrsqrt << std::endl;

    std::cout << "Is e1 square: ";
    std::cout << e1.is_square() << std::endl;

    std::cout << "Is e1square square: ";
    std::cout << e1sqr.is_square() << std::endl;

    std::cout << "e1 square square value: " << e1.squared().squared() << std::endl;

    std::cout << "e1 pow 4 value: " << e1.pow(4) << std::endl;

    std::cout << "e1 pow 11 value: " << e1.pow(11) << std::endl;

    std::cout << "e1 pow 44410867 value: " << e1.pow(44410867) << std::endl;

    value_type complex_eq = e1 * e3 + e1 * e4 + e2 * e3 + e2 * e4;
    value_type complex_eq1 = (e1 + e2) * (e3 + e4);

    std::cout << "e1 * e3 + e1 * e4 + e2 * e3 + e2 * e4 value: " << complex_eq << std::endl;

    std::cout << "(e1 + e2) * (e3 + e4) value: " << complex_eq1 << std::endl;

    std::cout << "Doubled e1 value: " << e1.doubled() << std::endl;

    e1 += e2;

    std::cout << "e1 += e2 value: " << e1 << std::endl;
}

template<typename Fp2Field>
void fields_fp2_basic_math_examples() {
    using policy_type = Fp2Field;
    typedef typename policy_type::value_type value_type;

    std::cout << "Field module value: " << policy_type::modulus << std::endl;

    value_type e1 = value_type(76749407, 44410867), e2(44410867, 1), e3 = value_type::one(), e4(121160274, 7);

    value_type ee(e1);

    std::cout << "ee value: " << ee << std::endl;

    std::cout << "Non residue: " << e1.non_residue << std::endl;

    std::cout << "Field element values: " << std::endl;
    std::cout << "e1 value: " << e1 << std::endl;

    e1 += e2;

    std::cout << "e1 value: " << e1 << std::endl;
    std::cout << "ee value: " << ee << std::endl;

    std::cout << "e2 value: " << e2 << std::endl;

    std::cout << "e3 value: " << e3 << std::endl;

    value_type e1inv = e1.inversed();

    std::cout << "e1 inversed value: " << e1inv << std::endl;

    std::cout << "e1 * e1^(-1) \n" << e1 * e1inv << std::endl;

    value_type e1e2 = e1 * e2, e1sqr = e1.squared();

    std::cout << "e1 * e2 value: " << e1e2 << std::endl;

    value_type e1sqrsqrt = e1sqr.sqrt();

    std::cout << "e1 square value: " << e1sqr << std::endl;

    std::cout << "e1 square sqrt value: " << e1sqrsqrt << std::endl;

    std::cout << "e1 square square value: " << e1.squared().squared() << std::endl;

    std::cout << "e1 pow 4 value: " << e1.pow(4) << std::endl;

    std::cout << "e1 pow 11 value: " << e1.pow(11) << std::endl;

    std::cout << "e1 pow 44410867 value: " << e1.pow(44410867) << std::endl;

    value_type complex_eq = e1 * e3 + e1 * e4 + e2 * e3 + e2 * e4;
    value_type complex_eq1 = (e1 + e2) * (e3 + e4);

    std::cout << "e1 * e3 + e1 * e4 + e2 * e3 + e2 * e4 value: " << complex_eq << std::endl;

    std::cout << "(e1 + e2) * (e3 + e4) value: " << complex_eq1 << std::endl;

    std::cout << "Doubled e1 value: " << e1.doubled() << std::endl;

    e1 += e2;

    std::cout << "e1 += e2 value: " << e1 << std::endl;

    // std::cout << "e1 inversed value: " << e1.inversed() << std::endl;
}

template<typename Fp3Field>
void fields_fp3_basic_math_examples() {
    using policy_type = Fp3Field;
    typedef typename policy_type::value_type value_type;

    std::cout << "Field module value: " << policy_type::modulus << std::endl;

    value_type e1 = value_type(76749407, 44410867, 44410867), e2(44410867, 44410867, 1), e3 = value_type::one(),
               e4(121160274, 7, 121160274);

    value_type ee(e1);

    std::cout << "ee value: " << ee << std::endl;

    std::cout << "Non residue: " << e1.non_residue << std::endl;

    std::cout << "Field element values: " << std::endl;
    std::cout << "e1 value: " << e1 << std::endl;

    e1 += e2;

    std::cout << "e1 value: " << e1 << std::endl;
    std::cout << "ee value: " << ee << std::endl;

    std::cout << "e2 value: " << e2 << std::endl;

    std::cout << "e3 value: " << e3 << std::endl;

    value_type e1inv = e1.inversed();

    std::cout << "e1 inversed value: " << e1inv << std::endl;

    std::cout << "e1 * e1^(-1) \n" << e1 * e1inv << std::endl;

    value_type e1e2 = e1 * e2, e1sqr = e1.squared();

    std::cout << "e1 * e2 value: " << e1e2 << std::endl;

    // value_type e1sqrsqrt = e1sqr.sqrt();

    std::cout << "e1 square value: " << e1sqr << std::endl;

    // std::cout << "e1 square sqrt value: " << e1sqrsqrt << std::endl;

    std::cout << "e1 square square value: " << e1.squared().squared() << std::endl;

    std::cout << "e1 pow 4 value: " << e1.pow(4) << std::endl;

    std::cout << "e1 pow 11 value: " << e1.pow(11) << std::endl;

    std::cout << "e1 pow 44410867 value: " << e1.pow(44410867) << std::endl;

    value_type complex_eq = e1 * e3 + e1 * e4 + e2 * e3 + e2 * e4;
    value_type complex_eq1 = (e1 + e2) * (e3 + e4);

    std::cout << "e1 * e3 + e1 * e4 + e2 * e3 + e2 * e4 value: " << complex_eq << std::endl;

    std::cout << "(e1 + e2) * (e3 + e4) value: " << complex_eq1 << std::endl;

    std::cout << "Doubled e1 value: " << e1.doubled() << std::endl;

    e1 += e2;

    std::cout << "e1 += e2 value: " << e1 << std::endl;
}

int main() {
    std::cout << "ALT_BN128-254 Fq basic math:" << std::endl;
    fields_fp_basic_math_examples<fields::alt_bn128_fq<254>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "ALT_BN128-254 Fq2 basic math:" << std::endl;
    fields_fp2_basic_math_examples<fields::fp2<fields::alt_bn128_fq<254>>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "ALT_BN128-254 Fr basic math:" << std::endl;
    fields_fp_basic_math_examples<fields::alt_bn128_fr<254>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "BLS12-381 Fq basic math:" << std::endl;
    fields_fp_basic_math_examples<fields::bls12_fq<381>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "BLS12-381 Fq2 basic math:" << std::endl;
    fields_fp2_basic_math_examples<fields::fp2<fields::bls12_fq<381>>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "BLS12-381 Fr basic math:" << std::endl;
    fields_fp_basic_math_examples<fields::bls12_fr<381>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "BLS12-377 Fq basic math:" << std::endl;
    fields_fp_basic_math_examples<fields::bls12_fq<377>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "BLS12-377 Fq2 basic math:" << std::endl;
    fields_fp2_basic_math_examples<fields::fp2<fields::bls12_fq<377>>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "BLS12-377 Fr basic math:" << std::endl;
    fields_fp_basic_math_examples<fields::bls12_fr<377>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "MNT4 Fq basic math:" << std::endl;
    fields_fp_basic_math_examples<fields::mnt4_fq<298>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "MNT4 Fq2 basic math:" << std::endl;
    fields_fp2_basic_math_examples<fields::fp2<fields::mnt4_fq<298>>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "MNT4 Fr basic math:" << std::endl;
    fields_fp_basic_math_examples<fields::mnt4_fr<298>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "MNT6 Fq basic math:" << std::endl;
    fields_fp_basic_math_examples<fields::mnt6_fq<298>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "MNT6 Fq3 basic math:" << std::endl;
    fields_fp3_basic_math_examples<fields::fp3<fields::mnt6_fq<298>>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "MNT6 Fr basic math:" << std::endl;
    fields_fp_basic_math_examples<fields::mnt6_fr<298>>();

    std::cout << "----------------------------" << std::endl;

    return 0;
}
