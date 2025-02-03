//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2024  Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_FIELDS_ELEMENT_FP12_2OVER3OVER2_HPP
#define CRYPTO3_ALGEBRA_FIELDS_ELEMENT_FP12_2OVER3OVER2_HPP

#include <nil/crypto3/algebra/fields/detail/exponentiation.hpp>
#include <nil/crypto3/algebra/fields/detail/element/operations.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {
                namespace detail {

                    template<typename FieldParams>
                    class element_fp12_2over3over2 {
                        typedef FieldParams policy_type;

                    public:
                        typedef typename policy_type::field_type field_type;
                        typedef typename policy_type::non_residue_type non_residue_type;
                        constexpr static const non_residue_type non_residue = policy_type::non_residue;

                        typedef typename policy_type::underlying_type underlying_type;

                        using data_type = std::array<underlying_type, 2>;

                        data_type data;

                        constexpr element_fp12_2over3over2() = default;

                        constexpr element_fp12_2over3over2(const underlying_type& in_data0, 
                                                           const underlying_type& in_data1)
                            : data({in_data0, in_data1}) {}

                        constexpr element_fp12_2over3over2(const data_type &in_data)
                            : data({in_data[0], in_data[1]}) {}

                        constexpr element_fp12_2over3over2(const element_fp12_2over3over2 &B)
                            : data {B.data} {};

                        constexpr element_fp12_2over3over2(const element_fp12_2over3over2 &&B) BOOST_NOEXCEPT 
                            : data(std::move(B.data)) {};

                        // Creating a zero is a fairly slow operation and is called very often, so we must return a
                        // reference to the same static object every time.
                        constexpr static const element_fp12_2over3over2& zero();
                        constexpr static const element_fp12_2over3over2& one();

                        constexpr bool is_zero() const {
                            return *this == zero();
                        }

                        constexpr bool is_one() const {
                            return *this == one();
                        }

                        bool operator==(const element_fp12_2over3over2 &B) const {
                            return (data[0] == B.data[0]) && (data[1] == B.data[1]);
                        }

                        bool operator!=(const element_fp12_2over3over2 &B) const {
                            return (data[0] != B.data[0]) || (data[1] != B.data[1]);
                        }

                        element_fp12_2over3over2 &operator=(const element_fp12_2over3over2 &B) {
                            data[0] = B.data[0];
                            data[1] = B.data[1];

                            return *this;
                        }

                        element_fp12_2over3over2 operator+(const element_fp12_2over3over2 &B) const {
                            return element_fp12_2over3over2(data[0] + B.data[0], data[1] + B.data[1]);
                        }

                        element_fp12_2over3over2 doubled() const {
                            return element_fp12_2over3over2(data[0].doubled(), data[1].doubled());
                        }

                        element_fp12_2over3over2 operator-(const element_fp12_2over3over2 &B) const {
                            return element_fp12_2over3over2(data[0] - B.data[0], data[1] - B.data[1]);
                        }

                        element_fp12_2over3over2 &operator-=(const element_fp12_2over3over2 &B) {
                            data[0] -= B.data[0];
                            data[1] -= B.data[1];

                            return *this;
                        }

                        element_fp12_2over3over2 &operator+=(const element_fp12_2over3over2 &B) {
                            data[0] += B.data[0];
                            data[1] += B.data[1];

                            return *this;
                        }

                        element_fp12_2over3over2 operator-() const {
                            return zero() - *this;
                        }

                        element_fp12_2over3over2 operator*(const element_fp12_2over3over2 &B) const {
                            const underlying_type A0B0 = data[0] * B.data[0], A1B1 = data[1] * B.data[1];

                            return element_fp12_2over3over2(A0B0 + mul_by_non_residue(A1B1),
                                                            (data[0] + data[1]) * (B.data[0] + B.data[1]) - A0B0 -
                                                                A1B1);
                        }

                        element_fp12_2over3over2& operator*=(const element_fp12_2over3over2 &B) {
                            const underlying_type A0B0 = data[0] * B.data[0], A1B1 = data[1] * B.data[1];

                            data[1] = (data[0] + data[1]) * (B.data[0] + B.data[1]) - A0B0 - A1B1;
                            data[0] = A0B0 + mul_by_non_residue(A1B1);
                            return *this;
                        }

                        element_fp12_2over3over2 squared() const {

                            return (*this) * (*this);    // maybe can be done more effective
                        }

                        template<typename PowerType>
                        element_fp12_2over3over2 pow(const PowerType &pwr) const {
                            return element_fp12_2over3over2(power(*this, pwr));
                        }

                        element_fp12_2over3over2 inversed() const {

                            /* From "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig
                             * Curves"; Algorithm 8 */

                            const underlying_type &A0 = data[0], &A1 = data[1];

                            const underlying_type t0 = A0.squared();
                            const underlying_type t1 = A1.squared();
                            const underlying_type t2 = t0 - mul_by_non_residue(t1);
                            const underlying_type t3 = t2.inversed();
                            const underlying_type c0 = A0 * t3;
                            const underlying_type c1 = -(A1 * t3);

                            return element_fp12_2over3over2(c0, c1);
                        }

                        /** @brief Frobenius map: exponentiation by a degree of field characteristic
                         * For $a\in F_{p^k}$ this returns $a^{p^pwr}$ */
                        template<typename PowerType>
                        element_fp12_2over3over2 Frobenius_map(const PowerType &pwr) const {
                            return element_fp12_2over3over2(data[0].Frobenius_map(pwr),
                                                            typename policy_type::non_residue_type(
                                                                policy_type::Frobenius_coeffs_c1[(pwr % 12) * 2],
                                                                policy_type::Frobenius_coeffs_c1[(pwr % 12) * 2 + 1]) *
                                                                data[1].Frobenius_map(pwr));
                        }

                        /** @brief For normalized values inverse is conjugation */
                        element_fp12_2over3over2 unitary_inversed() const {
                            return element_fp12_2over3over2(data[0], -data[1]);
                        }

                        /** @brief Elements from cyclotomic subgroup allow fast squaring */
                        element_fp12_2over3over2 cyclotomic_squared() const {

                            typename underlying_type::underlying_type z0 = data[0].data[0];
                            typename underlying_type::underlying_type z4 = data[0].data[1];
                            typename underlying_type::underlying_type z3 = data[0].data[2];

                            typename underlying_type::underlying_type z2 = data[1].data[0];
                            typename underlying_type::underlying_type z1 = data[1].data[1];
                            typename underlying_type::underlying_type z5 = data[1].data[2];

                            typename underlying_type::underlying_type t0, t1, t2, t3, t4, t5, tmp;

                            // t0 + t1*y = (z0 + z1*y)^2 = a^2
                            tmp = z0 * z1;
                            t0 = (z0 + z1) * (z0 + underlying_type::non_residue * z1) - tmp -
                                 underlying_type::non_residue * tmp;
                            t1 = tmp + tmp;
                            // t2 + t3*y = (z2 + z3*y)^2 = b^2
                            tmp = z2 * z3;
                            t2 = (z2 + z3) * (z2 + underlying_type::non_residue * z3) - tmp -
                                 underlying_type::non_residue * tmp;
                            t3 = tmp + tmp;
                            // t4 + t5*y = (z4 + z5*y)^2 = c^2
                            tmp = z4 * z5;
                            t4 = (z4 + z5) * (z4 + underlying_type::non_residue * z5) - tmp -
                                 underlying_type::non_residue * tmp;
                            t5 = tmp + tmp;

                            // for A

                            // z0 = 3 * t0 - 2 * z0
                            z0 = t0 - z0;
                            z0 = z0 + z0;
                            z0 = z0 + t0;
                            // z1 = 3 * t1 + 2 * z1
                            z1 = t1 + z1;
                            z1 = z1 + z1;
                            z1 = z1 + t1;

                            // for B

                            // z2 = 3 * (xi * t5) + 2 * z2
                            tmp = underlying_type::non_residue * t5;
                            z2 = tmp + z2;
                            z2 = z2 + z2;
                            z2 = z2 + tmp;

                            // z3 = 3 * t4 - 2 * z3
                            z3 = t4 - z3;
                            z3 = z3 + z3;
                            z3 = z3 + t4;

                            // for C

                            // z4 = 3 * t2 - 2 * z4
                            z4 = t2 - z4;
                            z4 = z4 + z4;
                            z4 = z4 + t2;

                            // z5 = 3 * t3 + 2 * z5
                            z5 = t3 + z5;
                            z5 = z5 + z5;
                            z5 = z5 + t3;

                            return element_fp12_2over3over2(underlying_type(z0, z4, z3), underlying_type(z2, z1, z5));
                        }

                        /** @brief Square-and-multiply exponentiation, with cyclotomic_square */
                        template<typename PowerType>
                        element_fp12_2over3over2 cyclotomic_exp(const PowerType &exponent) const {
                            element_fp12_2over3over2 res = one();

                            if (exponent == 0)
                                return res;

                            bool found_one = false;
                            for (long i = exponent.msb(); i >= 0; --i) {
                                if (found_one) {
                                    res = res.cyclotomic_squared();
                                }

                                if (exponent.bit_test(i)) {
                                    found_one = true;
                                    res = res * (*this);
                                }
                            }

                            return res;
                        }

                        /** @brief multiply by [ [c0, 0, 0], [c3, c4, 0] ] */
                        element_fp12_2over3over2
                            mul_by_034(const typename underlying_type::underlying_type &c0,
                                       const typename underlying_type::underlying_type &c3,
                                       const typename underlying_type::underlying_type &c4) const
                        {
                            auto a0 = this->data[0].data[0] * c0;
                            auto a1 = this->data[0].data[1] * c0;
                            auto a2 = this->data[0].data[2] * c0;

                            auto a = underlying_type(a0,a1,a2);
                            auto b = this->data[1].mul_by_01(c3, c4);

                            auto _c0 = c0 + c3;
                            auto e = (this->data[0]+this->data[1]).mul_by_01(_c0, c4);
                            auto rc1 = e - (a+b);
                            auto rc0 = mul_by_non_residue(b);
                            rc0 += a;

                            return element_fp12_2over3over2(rc0, rc1);
                        }

                        /** @brief multiply by [ [c0, c1, 0], [0, c4, 0] ] */
                        element_fp12_2over3over2
                            mul_by_014(const typename underlying_type::underlying_type &c0,
                                       const typename underlying_type::underlying_type &c1,
                                       const typename underlying_type::underlying_type &c4) const
                        {
                            auto aa = this->data[0].mul_by_01(c0, c1);
                            auto bb = this->data[1].mul_by_1(c4);
                            auto o = c1+c4;

                            auto rc1 = this->data[0]+this->data[1];
                            rc1 = rc1.mul_by_01(c0, o);
                            rc1 -= aa;
                            rc1 -= bb;
                            auto rc0 = mul_by_non_residue(bb);
                            rc0 += aa;

                            return element_fp12_2over3over2(rc0, rc1);
                        }


                        /** @brief multiply by [ [c0, 0, 0], [0, c4, c5] ] */
                        element_fp12_2over3over2
                            mul_by_045(const typename underlying_type::underlying_type &ell_0,
                                       const typename underlying_type::underlying_type &ell_VW,
                                       const typename underlying_type::underlying_type &ell_VV) const {

                            typename underlying_type::underlying_type z0 = this->data[0].data[0];
                            typename underlying_type::underlying_type z1 = this->data[0].data[1];
                            typename underlying_type::underlying_type z2 = this->data[0].data[2];
                            typename underlying_type::underlying_type z3 = this->data[1].data[0];
                            typename underlying_type::underlying_type z4 = this->data[1].data[1];
                            typename underlying_type::underlying_type z5 = this->data[1].data[2];

                            typename underlying_type::underlying_type x0 = ell_VW;
                            typename underlying_type::underlying_type x4 = ell_0;
                            typename underlying_type::underlying_type x5 = ell_VV;

                            typename underlying_type::underlying_type t0, t1, t2, t3, t4, t5;
                            typename underlying_type::underlying_type tmp1, tmp2;

                            tmp1 = element_fp12_2over3over2::non_residue * x4;
                            tmp2 = element_fp12_2over3over2::non_residue * x5;

                            t0 = x0 * z0 + tmp1 * z4 + tmp2 * z3;
                            t1 = x0 * z1 + tmp1 * z5 + tmp2 * z4;
                            t2 = x0 * z2 + x4 * z3 + tmp2 * z5;
                            t3 = x0 * z3 + tmp1 * z2 + tmp2 * z1;
                            t4 = x0 * z4 + x4 * z0 + tmp2 * z2;
                            t5 = x0 * z5 + x4 * z1 + x5 * z0;

                            return element_fp12_2over3over2(underlying_type(t0, t1, t2), underlying_type(t3, t4, t5));
                        }

                        /** @brief multiply by [ [c0, 0, c2], [0, c4, 0] ] */
                        element_fp12_2over3over2
                            mul_by_024(const typename underlying_type::underlying_type &ell_0,
                                       const typename underlying_type::underlying_type &ell_VW,
                                       const typename underlying_type::underlying_type &ell_VV) const {
                            element_fp12_2over3over2 a(
                                underlying_type(ell_0, underlying_type::underlying_type::zero(), ell_VV),
                                underlying_type(underlying_type::underlying_type::zero(), ell_VW,
                                                underlying_type::underlying_type::zero()));

                            return (*this) * a;
                        }


                        inline static underlying_type mul_by_non_residue(const underlying_type &A) {
                            return underlying_type(non_residue * A.data[2], A.data[0], A.data[1]);
                        }
                    };

                    template<typename FieldParams>
                    element_fp12_2over3over2<FieldParams>
                        operator*(const typename FieldParams::underlying_type::underlying_type::underlying_type &lhs,
                                  const element_fp12_2over3over2<FieldParams> &rhs) {

                        return element_fp12_2over3over2<FieldParams>(lhs * rhs.data[0], lhs * rhs.data[1]);
                    }

                    template<typename FieldParams>
                    element_fp12_2over3over2<FieldParams>
                        operator*(const element_fp12_2over3over2<FieldParams> &lhs,
                                  const typename FieldParams::underlying_type::underlying_type::underlying_type &rhs) {

                        return rhs * lhs;
                    }

                    template<typename FieldParams>
                    element_fp12_2over3over2<FieldParams>
                        operator*(const typename FieldParams::underlying_type::underlying_type &lhs,
                                  const element_fp12_2over3over2<FieldParams> &rhs) {

                        return element_fp12_2over3over2<FieldParams>(lhs * rhs.data[0], lhs * rhs.data[1]);
                    }

                    template<typename FieldParams>
                    element_fp12_2over3over2<FieldParams>
                        operator*(const element_fp12_2over3over2<FieldParams> &lhs,
                                  const typename FieldParams::underlying_type::underlying_type &rhs) {

                        return rhs * lhs;
                    }

                    template<typename FieldParams>
                    element_fp12_2over3over2<FieldParams> operator*(const typename FieldParams::underlying_type &lhs,
                                                                    const element_fp12_2over3over2<FieldParams> &rhs) {

                        return element_fp12_2over3over2<FieldParams>(lhs * rhs.data[0], lhs * rhs.data[1]);
                    }

                    template<typename FieldParams>
                    element_fp12_2over3over2<FieldParams> operator*(const element_fp12_2over3over2<FieldParams> &lhs,
                                                                    const typename FieldParams::underlying_type &rhs) {

                        return rhs * lhs;
                    }

                    template<typename FieldParams>
                    constexpr const typename element_fp12_2over3over2<FieldParams>::non_residue_type
                        element_fp12_2over3over2<FieldParams>::non_residue;

                    namespace element_fp12_2over3over2_details {
                        // These constexpr static variables can not be members of element_fp2, because 
                        // element_fp2 is incomplete type until the end of its declaration.
                        template<typename FieldParams>
                        constexpr static element_fp12_2over3over2<FieldParams> zero_instance(
                            FieldParams::underlying_type::zero(),
                            FieldParams::underlying_type::zero());

                        template<typename FieldParams>
                        constexpr static element_fp12_2over3over2<FieldParams> one_instance(
                            FieldParams::underlying_type::one(),
                            FieldParams::underlying_type::zero());
                    }

                    template<typename FieldParams>
                    constexpr const element_fp12_2over3over2<FieldParams>& element_fp12_2over3over2<FieldParams>::zero() {
                        return element_fp12_2over3over2_details::zero_instance<FieldParams>;
                    }

                    template<typename FieldParams>
                    constexpr const element_fp12_2over3over2<FieldParams>& element_fp12_2over3over2<FieldParams>::one() {
                        return element_fp12_2over3over2_details::one_instance<FieldParams>;
                    }

                    template<typename FieldParams>
                    std::ostream& operator<<(std::ostream& os, const element_fp12_2over3over2<FieldParams>& elem) {
                        os << "[" << elem.data[0] << "," << elem.data[1] << "]";
                        return os;
                    }
                }    // namespace detail
            }        // namespace fields
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_ELEMENT_FP12_2OVER3OVER2_HPP
