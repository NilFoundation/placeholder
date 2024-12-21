//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_WNAF_HPP
#define CRYPTO3_ALGEBRA_WNAF_HPP

#include <nil/crypto3/algebra/curves/params.hpp>
#include <nil/crypto3/algebra/type_traits.hpp>

#include <nil/crypto3/multiprecision/big_uint.hpp>
#include <nil/crypto3/multiprecision/wnaf.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            template<typename BaseValueType, std::size_t Bits>
            BaseValueType fixed_window_wnaf_exp(const std::size_t window_size, const BaseValueType &base,
                                                const nil::crypto3::multiprecision::big_uint<Bits> &scalar) {
                std::vector<long> naf = nil::crypto3::multiprecision::find_wnaf(window_size, scalar);
                std::vector<BaseValueType> table(1ul << (window_size - 1));
                BaseValueType tmp = base;
                BaseValueType dbl = base;
                dbl.double_inplace();
                for (size_t i = 0; i < 1ul << (window_size - 1); ++i) {
                    table[i] = tmp;
                    tmp = tmp + dbl;
                }

                BaseValueType res = BaseValueType::zero();
                bool found_nonzero = false;
                for (long i = naf.size() - 1; i >= 0; --i) {
                    if (found_nonzero) {
                        res.double_inplace();
                    }

                    if (naf[i] != 0) {
                        found_nonzero = true;
                        if (naf[i] > 0) {
                            res = res + table[naf[i] / 2];
                        } else {
                            res = res - table[(-naf[i]) / 2];
                        }
                    }
                }

                return res;
            }

            template<typename CurveGroupValueType, std::size_t Bits>
            std::enable_if_t<
                is_curve_element<CurveGroupValueType>::value,
                CurveGroupValueType>
            opt_window_wnaf_exp(const CurveGroupValueType &base,
                const nil::crypto3::multiprecision::big_uint<Bits> &scalar,
                const std::size_t scalar_bits) {
                std::size_t best = 0;
                for (long i =
                         curves::wnaf_params<typename CurveGroupValueType::group_type>::wnaf_window_table.size() - 1;
                     i >= 0;
                     --i) {
                    if (scalar_bits >=
                        curves::wnaf_params<typename CurveGroupValueType::group_type>::wnaf_window_table[i]) {
                        best = i + 1;
                        break;
                    }
                }

                if (best > 0) {
                    return fixed_window_wnaf_exp(best, base, scalar);
                } else {
                    return scalar * base;
                }
            }
        }    // namespace algebra
    }        // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_RANDOM_ELEMENT_HPP
