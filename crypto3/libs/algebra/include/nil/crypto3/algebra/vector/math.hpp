//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_VECTOR_MATH_HPP
#define CRYPTO3_ALGEBRA_VECTOR_MATH_HPP

#include <functional>

#include <nil/crypto3/algebra/vector/utility.hpp>
#include <nil/crypto3/algebra/vector/vector.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {

            /** \addtogroup vector
             *  @{
             */


            /** @brief computes the elementwise square root
             *  @param v an N-vector of type T
             *  @return an N-vector \f$ \begin{bmatrix} \sqrt{v_1} & \ldots &\sqrt{v_N} \end{bmatrix} \f$ of type T
             *
             *  Computes the elementwise square root of a vector.
             */
            template<typename T, std::size_t N>
            constexpr vector<T, N> sqrt(const vector<T, N> &v) {
                return elementwise(static_cast<T (*)(T)>(sqrt), v);
            }

            /** @brief computes the dot product
             *  @param a an N-vector of type T
             *  @param b an N-vector of type T
             *  @return a scalar \f$ \textbf{a} \cdot \textbf{b} \f$ of type T such that
             *  \f$ \left(\textbf{a}\cdot\textbf{b}\right)_i = a_i \overline{b_i} \f$
             *
             *  Computes the dot (inner) product of two vectors.
             */
            template<typename T, std::size_t N>
            constexpr T dot(const vector<T, N> &a, const vector<T, N> &b) {
                T r = 0;
                for (std::size_t i = 0; i < vector<T, N>::size; ++i)
                    r += a[i] * conj(b[i]);
                return r;
            }

            /** @brief computes the sum of elements
             *  @param v an N-vector of type T
             *  @return a scalar \f$ \sum\limits_{i} v_i \f$ of type T
             *
             *  Computes the sum of the elements of a vector.
             */
            template<typename T, std::size_t N>
            constexpr T sum(const vector<T, N> &v) {
                return accumulate(v, T(0u), std::plus<T>());
            }

            /** @brief computes the minimum valued element
             *  @param v an N-vector of type T
             *  @return a scalar \f$ v_i \f$ of type T where \f$ v_i \leq v_j,\ \forall j \f$
             *
             *  Computes the minimum valued element of a vector.
             */
            template<typename T, std::size_t N>
            constexpr T min(const vector<T, N> &v) {
                return accumulate(v, v[0], [](T a, T b) { return std::min(a, b); });
            }

            /** @brief computes the maximum valued element
             *  @param v an N-vector of type T
             *  @return a scalar \f$ v_i \f$ of type T where \f$ v_i \geq v_j,\ \forall j \f$
             *
             *  Computes the maximum valued element of a vector.
             */
            template<typename T, std::size_t N>
            constexpr T max(const vector<T, N> &v) {
                return accumulate(v, v[0], [](T a, T b) { return std::max(a, b); });
            }

            /** @brief computes the index of the minimum valued element
             *  @param v an N-vector of type T
             *  @return an index \f$ i \f$ where \f$ v_i \leq v_j,\ \forall j \f$
             *
             *  Computes the index of the minimum valued element of a vector.
             *  Note: the return value is zero-indexed.
             */
            template<typename T, std::size_t N>
            constexpr std::size_t min_index(const vector<T, N> &v) {
                T min = v[0];
                std::size_t index = 0;
                for (std::size_t i = 0; i < vector<T, N>::size; ++i)
                    if (v[i] < min) {
                        index = i;
                        min = v[i];
                    }
                return index;
            }

            /** @brief computes the index of the maximum valued element
             *  @param v an N-vector of type T
             *  @return an index \f$ i \f$ where \f$ v_i \geq v_j,\ \forall j \f$
             *
             *  Computes the index of the maximum valued element of a vector.
             *  Note: the return value is zero-indexed.
             */
            template<typename T, std::size_t N>
            constexpr std::size_t max_index(const vector<T, N> &v) {
                T max = v[0];
                std::size_t index = 0;
                for (std::size_t i = 0; i < vector<T, N>::size; ++i)
                    if (v[i] > max) {
                        index = i;
                        max = v[i];
                    }
                return index;
            }

            /** @}*/

        }    // namespace algebra
    }        // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_VECTOR_MATH_HPP
