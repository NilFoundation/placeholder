//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_CURVES_SCALAR_MUL_HPP
#define CRYPTO3_ALGEBRA_CURVES_SCALAR_MUL_HPP

#include <nil/crypto3/algebra/type_traits.hpp>

#include <boost/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/modular/modular_adaptor.hpp>

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>

#include <nil/crypto3/algebra/wnaf.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    template<typename CurveElementType>
                    constexpr void scalar_mul_inplace(
                            CurveElementType &base,
                            typename CurveElementType::params_type::scalar_field_type::value_type const& scalar)
                    {
                        if (scalar.is_zero()) {
                            base = CurveElementType::zero();
                            return;
                        }

                        const size_t window_size = 3;
                        auto integral_scalar = static_cast<typename CurveElementType::params_type::scalar_field_type::integral_type>(scalar.data);

                        auto naf = boost::multiprecision::eval_find_wnaf_a(window_size + 1, integral_scalar.backend());
                        std::array<CurveElementType, 1ul << window_size > table;
                        CurveElementType dbl = base;
                        dbl.double_inplace();
                        for (size_t i = 0; i < 1ul << window_size; ++i) {
                            table[i] = base;
                            base += dbl;
                        }

                        base = CurveElementType::zero();
                        bool found_nonzero = false;
                        for (long i = naf.size() - 1; i >= 0; --i) {
                            if (found_nonzero) {
                                base.double_inplace();
                            }

                            if (naf[i] != 0) {
                                found_nonzero = true;
                                if (naf[i] > 0) {
                                    base += table[naf[i] / 2];
                                } else {
                                    base -= table[(-naf[i]) / 2];
                                }
                            }
                        }
                    }

                    template<typename CurveElementType>
                    constexpr CurveElementType& operator *= (
                            CurveElementType& point,
                            typename CurveElementType::params_type::scalar_field_type::value_type const& scalar)
                    {
                        scalar_mul_inplace(point, scalar.data);
                        return point;
                    }

                    template<typename CurveElementType>
                    constexpr CurveElementType operator * (
                            CurveElementType const& point,
                            typename CurveElementType::params_type::scalar_field_type::value_type const& scalar)
                    {
                        CurveElementType res = point;
                        scalar_mul_inplace(res, scalar.data);
                        return res;
                    }

                    template<typename CurveElementType>
                    constexpr CurveElementType operator * (
                            typename CurveElementType::params_type::scalar_field_type::value_type const& scalar,
                            CurveElementType const& point)
                    {
                        CurveElementType res = point;
                        scalar_mul_inplace(res, scalar.data);
                        return res;
                    }

                    template<typename CurveElementType>
                    std::enable_if_t<is_curve_element<CurveElementType>::value, CurveElementType>
                    constexpr operator * (
                            const CurveElementType &point,
                            const std::size_t &multiplier)
                    {
                        typename CurveElementType::params_type::scalar_field_type::value_type scalar(multiplier);
                        return point * scalar;
                    }

                    template<typename CurveElementType>
                    std::enable_if_t<is_curve_element<CurveElementType>::value, CurveElementType>
                    constexpr operator * (
                            const std::size_t &multiplier,
                            const CurveElementType &point)
                    {
                        typename CurveElementType::params_type::scalar_field_type::value_type scalar(multiplier);
                        return point * scalar;
                    }

                    // TODO: temporary implementation due to absence of GroupValueType type_trait
                    //  Should be implemented as class method
                    template<typename CurveElementType>
                    std::enable_if_t<is_curve_element<CurveElementType>::value, bool>
                    subgroup_check(const CurveElementType &point) {
                        /* Point can be multiplied only by scalar, scalar is modulo prime subgroup */
                        auto scalar_modulus = CurveElementType::group_type::curve_type::scalar_field_type::modulus;
                        return (point * (scalar_modulus -1) + point).is_zero();
                    }

#if 0
                    template<typename CurveElementType,
                             typename Backend,
                             boost::multiprecision::expression_template_option ExpressionTemplates>
                    CurveElementType constexpr scalar_mul(const CurveElementType &base,
                                   const boost::multiprecision::number<Backend, ExpressionTemplates> &scalar) {
                        if (scalar.is_zero()) {
                            return CurveElementType::zero();
                        }

                        const size_t window_size = 3;
                        auto naf = boost::multiprecision::eval_find_wnaf_a(window_size + 1, scalar.backend());
                        std::array<CurveElementType, 1ul << window_size > table;
                        CurveElementType tmp = base;
                        CurveElementType dbl = base;
                        dbl.double_inplace();
                        for (size_t i = 0; i < 1ul << window_size; ++i) {
                            table[i] = tmp;
                            tmp += dbl;
                        }

                        CurveElementType res = CurveElementType::zero();
                        bool found_nonzero = false;
                        for (long i = naf.size() - 1; i >= 0; --i) {
                            if (found_nonzero) {
                                res.double_inplace();
                            }

                            if (naf[i] != 0) {
                                found_nonzero = true;
                                if (naf[i] > 0) {
                                    res += table[naf[i] / 2];
                                } else {
                                    res -= table[(-naf[i]) / 2];
                                }
                            }
                        }
                        return res;
                    }

                    template<typename CurveElementType>
                    constexpr CurveElementType& operator *= (
                            CurveElementType& point,
                            typename CurveElementType::params_type::scalar_field_type::value_type const& scalar)
                    {
                        return point *= static_cast<typename CurveElementType::params_type::scalar_field_type::integral_type>(scalar.data);
                    }

                    template<typename CurveElementType,
                             typename Backend,
                             boost::multiprecision::expression_template_option ExpressionTemplates>
                    constexpr CurveElementType& operator *= (
                            CurveElementType& point,
                            const boost::multiprecision::number<Backend, ExpressionTemplates> &scalar)
                    {
                        if (scalar.is_zero()) {
                            point = CurveElementType::zero();
                            return point;
                        }

                        const size_t window_size = 3;
                        auto naf = boost::multiprecision::eval_find_wnaf_a(window_size + 1, scalar.backend());
                        std::array<CurveElementType, 1ul << window_size > table;
                        CurveElementType tmp = point;
                        CurveElementType dbl = point;
                        dbl.double_inplace();
                        for (size_t i = 0; i < 1ul << window_size; ++i) {
                            table[i] = tmp;
                            tmp += dbl;
                        }

                        CurveElementType res = CurveElementType::zero();
                        bool found_nonzero = false;
                        for (long i = naf.size() - 1; i >= 0; --i) {
                            if (found_nonzero) {
                                res.double_inplace();
                            }

                            if (naf[i] != 0) {
                                found_nonzero = true;
                                if (naf[i] > 0) {
                                    res += table[naf[i] / 2];
                                } else {
                                    res -= table[(-naf[i]) / 2];
                                }
                            }
                        }

                        point = res;
                        return point;
                    }

#if 1
                    template<typename GroupValueType, typename FieldValueType>
                    typename std::enable_if<is_elliptic_curve_scalar<GroupValueType, FieldValueType>::value,
                            GroupValueType>::type
                        operator*(const FieldValueType &scalar, const GroupValueType &point) {
                        return scalar_mul(point, scalar.data);
                    }

                    template<typename GroupValueType, typename FieldValueType>
                    typename std::enable_if<is_elliptic_curve_scalar<GroupValueType, FieldValueType>::value,
                            GroupValueType>::type
                        operator*(const GroupValueType &point,const FieldValueType &scalar) {
                        return scalar_mul(point, scalar.data);
                    }
#endif


#if 0
                    template<typename GroupValueType,
                             typename Backend, typename SafeType,
                             boost::multiprecision::expression_template_option ExpressionTemplates>
                    constexpr GroupValueType
                        operator*(const GroupValueType &left,
                                  const boost::multiprecision::number<boost::multiprecision::backends::modular_adaptor<Backend, SafeType>, ExpressionTemplates> &right) {
                        return scalar_mul(left, right);
                    }

                    template<typename GroupValueType,
                             typename Backend,
                             boost::multiprecision::expression_template_option ExpressionTemplates>
                    typename std::enable_if<
                        is_curve_group<typename GroupValueType::group_type>::value &&
                        !is_field<typename GroupValueType::group_type>::value,
                        GroupValueType>::type
                    constexpr operator*(const GroupValueType &left,
                            const boost::multiprecision::number<Backend, ExpressionTemplates> &right) {
                        return scalar_mul(left, right);
                    }

                    template<typename GroupValueType,
                             typename Backend,
                             boost::multiprecision::expression_template_option ExpressionTemplates>
                    typename std::enable_if<
                        is_curve_group<typename GroupValueType::group_type>::value &&
                        !is_field<typename GroupValueType::group_type>::value,
                        GroupValueType>::type
                    constexpr operator*(const boost::multiprecision::number<Backend, ExpressionTemplates> &left,
                            const GroupValueType &right) {
                        return scalar_mul(right, left);
                    }

                    /*
                    template<typename GroupValueType, typename FieldValueType>
                    typename std::enable_if<is_curve_group<typename GroupValueType::group_type>::value &&
                                                !is_field<typename GroupValueType::group_type>::value &&
                                                is_field<typename FieldValueType::field_type>::value &&
                                                !is_extended_field<typename FieldValueType::field_type>::value,
                                            GroupValueType>::type
                        operator*(const GroupValueType &left, const FieldValueType &right) {

                        // TODO(martun): consider deleting this function, and forcing all the callers to convert to the
                        // required type before multiplication.
                        return left * static_cast<typename GroupValueType::params_type::scalar_field_type::integral_type>(
                            typename FieldValueType::integral_type(right.data));
                    }
                    */

                    template<typename GroupValueType, typename FieldValueType>
                    typename std::enable_if<is_curve_group<typename GroupValueType::group_type>::value &&
                                                !is_field<typename GroupValueType::group_type>::value &&
                                                is_field<typename FieldValueType::field_type>::value &&
                                                !is_extended_field<typename FieldValueType::field_type>::value,
                                            GroupValueType>::type
                        operator*(const FieldValueType &left, const GroupValueType &right) {

                        return right * left;
                    }

#endif
                    template<typename GroupValueType>
                    constexpr GroupValueType operator*(const GroupValueType &left, const std::size_t &right) {

                        return scalar_mul(left, typename GroupValueType::field_type::integral_type::value_type(right));
                    }

                    template<typename GroupValueType>
                    constexpr GroupValueType operator*(const std::size_t &left, const GroupValueType &right) {

                        return right * left;
                    }
#endif

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_SCALAR_MUL_HPP
