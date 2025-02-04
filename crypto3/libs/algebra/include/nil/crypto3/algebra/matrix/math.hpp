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

#ifndef CRYPTO3_ALGEBRA_MATRIX_MATH_HPP
#define CRYPTO3_ALGEBRA_MATRIX_MATH_HPP

#include <nil/crypto3/algebra/vector/vector.hpp>
#include <nil/crypto3/algebra/vector/math.hpp>

#include <nil/crypto3/algebra/matrix/matrix.hpp>
#include <nil/crypto3/algebra/matrix/utility.hpp>


namespace nil {
    namespace crypto3 {
        namespace algebra {
            /** \addtogroup matrix
             *  @{
             */

            /** @brief computes the transpose
             *  @param m an \f$ M \times N \f$ matrix of type T
             *  @return an \f$ N \times M \f$ matrix \f$ \textbf{m}^{\mathrm{T}} \f$ of type T such that
             *  \f$ \left(\textbf{m}^{\mathrm{T}}\right)_{ij} = \textbf{m}_{ji},\ \forall i,j \f$
             *
             *  Computes the matrix transpose.
             */
            template<typename T, std::size_t M, std::size_t N>
            constexpr matrix<T, N, M> transpose(const matrix<T, M, N> &m) {
                return generate<N, M>([&m](auto i, auto j) { return m[j][i]; });
            }

            /** @brief computes the matrix product
             *  @param a an \f$M \times N\f$ matrix
             *  @param b an \f$N \times P\f$ matrix
             *  @return an \f$ M \times P \f$ matrix \f$ \textbf{a}\textbf{b} \f$ of type T such that
             *  \f$ \left(\textbf{ab}\right)_{ij} = \sum\limits_{k=1}^{N}\textbf{a}_{ik}\textbf{b}_{kj} \f$
             *
             *  Computes the product of two matrices.
             */
            template<typename T, std::size_t M, std::size_t N, std::size_t P>
            constexpr matrix<T, M, P> matmul(const matrix<T, M, N> &a, const matrix<T, N, P> &b) {
                return generate<M, P>([&a, &b](auto i, auto j) { return algebra::sum(a.row(i) * b.column(j)); });
            }

            /*!
             * @brief computes the product of vector and matrix
             * @param v an M-vector
             * @param m an \f$M \times N\f$ matrix
             * @return an N-vector of type T
             */
            template<typename T, std::size_t M, std::size_t N>
            constexpr vector<T, N> vectmatmul(const vector<T, M> &v, const matrix<T, M, N> &m) {
                return generate<N>([&v, &m](auto i) { return sum(v * m.column(i)); });
            }

            /*!
             * @brief computes the product of matrix and vector
             * @param m an \f$M \times N\f$ matrix
             * @param v an N-vector
             * @return an M-vector of type T
             */
            template<typename T, std::size_t M, std::size_t N>
            constexpr vector<T, M> matvectmul(const matrix<T, M, N> &m, const vector<T, N> &v) {
                return generate<M>([&v, &m](auto i) { return sum(m.row(i) * v); });
            }

            /** @brief Computes the kronecker tensor product
             *  @param a an \f$M \times N\f$ matrix
             *  @param b an \f$P \times Q\f$ matrix
             *  @return An \f$ MP \times NQ \f$ matrix \f$ \textbf{a}\otimes\textbf{b} \f$ of type T such that
             *  \f$ \left(\textbf{a}\otimes\textbf{b}\right)_{ij} = \textbf{a}_{\lfloor i/P \rfloor,\lfloor j/Q
             * \rfloor}\textbf{b}_{i\textrm{%}P,j\textrm{%}Q} \f$ where \f$ i \textrm{%} P \f$ is the remainder of \f$
             * i/P \f$
             *
             * Computes the kronecker tensor product of two matrices.
             */
            template<typename T, std::size_t M, std::size_t N, std::size_t P, std::size_t Q>
            constexpr matrix<T, M * P, N * Q> kron(const matrix<T, M, N> &a, const matrix<T, P, Q> &b) {
                return generate<M * P, N * Q>([&a, &b](auto i, auto j) { return a[i / P][j / Q] * b[i % P][j % Q]; });
            }

            /// @private
            template<typename T, std::size_t M, std::size_t N>
            constexpr std::tuple<matrix<T, M, N>, std::size_t, T> gauss_jordan_impl(matrix<T, M, N> m) {
                // CRYPTO3_DETAIL_ASSERT_FLOATING_POINT(T)
                // CRYPTO3_DETAIL_ASSERT_REAL(T)

                auto negligible = [](const T &v) { return v == T::zero(); };

                T det = 1;
                std::size_t rank = 0;
                std::size_t i = 0, j = 0;
                while (i < M && j < N) {
                    // Choose largest magnitude as pivot to avoid adding different magnitudes
                    for (std::size_t ip = i + 1; ip < M; ++ip) {
                        if (m[ip][j] > m[i][j]) {
                            for (std::size_t jp = 0; jp < N; ++jp) {
                                auto tmp = m[ip][jp];
                                m[ip][jp] = m[i][jp];
                                m[i][jp] = tmp;
                            }
                            det = -det;
                            break;
                        }
                    }

                    // If m_ij is still 0, continue to the next column
                    if (!negligible(m[i][j])) {
                        // Scale m_ij to 1
                        auto s = m[i][j];
                        for (std::size_t jp = 0; jp < N; ++jp)
                            m[i][jp] /= s;
                        det /= s;

                        // Eliminate other values in the column
                        for (std::size_t ip = 0; ip < M; ++ip) {
                            if (ip == i)
                                continue;
                            if (!negligible(m[ip][j])) {
                                auto s = m[ip][j];
                                [&]() {    // wrap this in a lambda to get around a gcc bug
                                    for (std::size_t jp = 0; jp < N; ++jp)
                                        m[ip][jp] -= s * m[i][jp];
                                }();
                            }
                        }

                        // Increment rank
                        ++rank;

                        // Select next row
                        ++i;
                    }
                    ++j;
                }
                det = (rank == M) ? det : 0;
                return {m, rank, det};
            }

            /** @brief Compute the reduced row echelon form
             *  @param m an \f$ M \times N \f$ matrix of type T
             *  @return an \f$ M \times N \f$ matrix of type T, the reduced row echelon form
             * of \f$ \textbf{m} \f$
             *
             *  Computes the reduced row echelon form of a matrix using Gauss-Jordan
             * elimination.  The tolerance for determining negligible elements is \f$
             * \max\left(N, M\right) \cdot \epsilon \cdot {\left\lVert \textbf{m}
             * \right\rVert}_\infty \f$.
             */
            template<typename T, std::size_t M, std::size_t N>
            constexpr matrix<T, M, N> rref(const matrix<T, M, N> &m) {
                return std::get<0>(gauss_jordan_impl(m));
            }

            /** @brief Compute the rank
             *  @param m \f$ M \times N \f$ matrix of type T
             *  @return a scalar \f$ \textrm{rank}\left(\textbf{m}\right) \f$
             *
             *  Computes the rank using the reduced row echelon form.
             */
            template<typename T, std::size_t M, std::size_t N>
            constexpr std::size_t rank(const matrix<T, M, N> &m) {
                return std::get<1>(gauss_jordan_impl(m));
            }

            /** @brief Compute the determinant
             *  @param m \f$ M \times M \f$ matrix of type T
             *  @return a scalar \f$ \left\lvert \textbf{m} \right\rvert \f$ of type T
             *
             *  Computes the determinant using the reduced row echelon form.
             */
            template<typename T, std::size_t M>
            constexpr T det(const matrix<T, M, M> &m) {
                return std::get<2>(gauss_jordan_impl(m));
            }

            /** @brief computes the matrix inverse
             *  @param m an \f$ M \times M \f$ matrix of type T
             *  @return The inverse of \f$ \textbf{m} \f$, \f$ \textbf{m}^{-1}\f$ such that
             *  \f$ \textbf{m}\textbf{m}^{-1} = \textbf{m}^{-1}\textbf{m} = \textbf{I}_{M}
             * \f$
             *
             *  Computes the inverse of a matrix using the reduced row echelon form.
             */
            template<typename T, std::size_t M>
            constexpr matrix<T, M, M> inverse(const matrix<T, M, M> &m) {
                if (rank(m) < M)
                    throw "matrix is not invertible";
                return submat<M, M>(rref(horzcat(m, get_identity<T, M>())), 0, M);
            }

            /** @brief computes the trace
             *  @param m an \f$ M \times M \f$ matrix of type T
             *  @return the trace of \f$ \textbf{m} \f$, \f$ \textrm{tr}\left(\textbf{m}\right) \f$
             *  such that \f$ \textrm{tr}\left(\textbf{m}\right) = \sum\limits_{n=1}^{M} \textbf{m}_{nn} \f$
             *
             *  Computes the trace of a matrix.
             */
            template<typename T, std::size_t M>
            constexpr T trace(const matrix<T, M, M> &m) {
                return sum(generate<M>([&m](std::size_t i) { return m[i][i]; }));
            }

            /** }@*/

        }    // namespace algebra
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_MATRIX_MATH_HPP
