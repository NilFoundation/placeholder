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

#include <nil/crypto3/multiprecision/big_uint.hpp>
#include <nil/crypto3/multiprecision/wnaf.hpp>

#include <nil/crypto3/algebra/wnaf.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    template<typename CurveElementType, std::size_t Bits>
                    constexpr void scalar_mul_inplace(
                            CurveElementType &base,
                            nil::crypto3::multiprecision::big_uint<Bits> const& scalar)
                    {
                        if (scalar.is_zero()) {
                            base = CurveElementType::zero();
                            return;
                        }

                        const size_t window_size = 3;
                        auto naf = nil::crypto3::multiprecision::find_wnaf_a(window_size + 1, scalar);
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
                        using scalar_integral_type = typename CurveElementType::params_type::scalar_field_type::integral_type;
                        scalar_mul_inplace(point, static_cast<scalar_integral_type>(
                                                      scalar.to_integral()));
                        return point;
                    }

                    template<typename CurveElementType>
                    constexpr CurveElementType operator * (
                            CurveElementType const& point,
                            typename CurveElementType::params_type::scalar_field_type::value_type const& scalar)
                    {
                        using scalar_integral_type = typename CurveElementType::params_type::scalar_field_type::integral_type;
                        CurveElementType res = point;
                        scalar_mul_inplace(
                            res, static_cast<scalar_integral_type>(scalar.to_integral()));
                        return res;
                    }

                    template<typename CurveElementType>
                    constexpr CurveElementType operator * (
                            typename CurveElementType::params_type::scalar_field_type::value_type const& scalar,
                            CurveElementType const& point)
                    {
                        using scalar_integral_type = typename CurveElementType::params_type::scalar_field_type::integral_type;
                        CurveElementType res = point;
                        scalar_mul_inplace(
                            res, static_cast<scalar_integral_type>(scalar.to_integral()));
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

                    template<typename CurveElementType>
                    std::enable_if_t<is_curve_element<CurveElementType>::value, bool>
                    subgroup_check(CurveElementType point) {
                        auto scalar_modulus = CurveElementType::group_type::curve_type::scalar_field_type::modulus;
                        scalar_mul_inplace(point, scalar_modulus);
                        return point.is_zero();
                    }

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_SCALAR_MUL_HPP
