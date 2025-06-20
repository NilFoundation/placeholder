//---------------------------------------------------------------------------//
// Copyright (c) 2024 Polina Chernyshova <pockvokhbtra@nil.foundation>
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
// Copyright (c) 2024 Antoine Cyr <antoinecyr@nil.foundation>
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
// @file Declaration of interfaces for PLONK component wrapping the BBF-component
// interface
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BBF_COMPONENTS_FLEXIBLE_MULTIPLICATION_HPP
#define CRYPTO3_BBF_COMPONENTS_FLEXIBLE_MULTIPLICATION_HPP

#include <nil/blueprint/bbf/components/algebra/fields/non_native/check_mod_p.hpp>
#include <nil/blueprint/bbf/components/detail/range_check_multi.hpp>
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            namespace components {
                // Multiplication in non-native field with k-chunks and p > n, x * y - p * q - r = 0
                // Parameters: num_chunks = k, bit_size_chunk = b, T = k*b
                // native field module = n, non-native field module = p, pp = 2^T - p ( or -p(mod2^t))
                // NB: 2^T * n > p^2 + p
                // Input: x[0],..., x[k-1], y[0],..., y[k-1], p[0],..., p[k-1], pp[0],...,p[k-1], 0
                // (expects zero constant as input) 
                // Output: r[0],..., r[k-1]

                template<typename FieldType, GenerationStage stage,
                         typename NonNativeFieldType>
                class flexible_multiplication
                    : public generic_component<FieldType, stage> {
                    using generic_component<FieldType, stage>::allocate;
                    using generic_component<FieldType, stage>::copy_constrain;
                    using generic_component<FieldType, stage>::constrain;

                  public:
                    using typename generic_component<FieldType, stage>::TYPE;
                    using typename generic_component<FieldType, stage>::context_type;
                    using typename generic_component<FieldType, stage>::table_params;

                    struct input_type {
                      std::vector<TYPE> x;
                      std::vector<TYPE> y;
                      std::vector<TYPE> p;
                      std::vector<TYPE> pp;
                      TYPE zero;
                    };

                  public:
                    std::vector<TYPE> r;

                    static table_params get_minimal_requirements(
                        std::size_t num_chunks, std::size_t bit_size_chunk) {
                        // The 6 variables chunks fit in 2 rows, and there is a 3rd
                        // additionnal row available for the constraint values
                        std::size_t witness = 3 * num_chunks;
                        constexpr std::size_t public_inputs = 1;
                        constexpr std::size_t constants = 0;
                        // rows = 4096-1 so that lookup table is not too hard to fit and
                        // padding doesn't inflate the table
                        constexpr std::size_t rows = 4095;
                        return {witness, public_inputs, constants, rows};
                    }

                    static void allocate_public_inputs(
                            context_type &ctx, input_type &input,
                            std::size_t num_chunks, std::size_t bit_size_chunk) {
                        AllocatePublicInputChunks allocate_chunks(ctx, num_chunks);

                        std::size_t row = 0;
                        allocate_chunks(input.x, 0, &row);
                        allocate_chunks(input.y, 0, &row);
                        allocate_chunks(input.p, 0, &row);
                        allocate_chunks(input.pp, 0, &row);
                        ctx.allocate(input.zero, 0, row++, column_type::public_input);
                    }

                    flexible_multiplication(context_type &context_object,
                                            const input_type &input,
                                            std::size_t num_chunks,
                                            std::size_t bit_size_chunk,
                                            bool make_links = true)
                        : generic_component<FieldType, stage>(context_object) {

                        using extended_integral_type =
                            nil::crypto3::multiprecision::big_uint<
                                2 * NonNativeFieldType::modulus_bits>;

                        using integral_type = typename FieldType::integral_type;

                        using Check_Mod_P =
                            typename bbf::components::check_mod_p<FieldType, stage>;
                        using Range_Check =
                            typename bbf::components::range_check_multi<FieldType, stage>;

                        std::vector<TYPE> X(num_chunks);
                        std::vector<TYPE> Y(num_chunks);
                        std::vector<TYPE> P(num_chunks);
                        std::vector<TYPE> PP(num_chunks);

                        std::vector<TYPE> Q(num_chunks);
                        std::vector<TYPE> R(num_chunks);

                        std::vector<TYPE> Z(num_chunks);
                        std::vector<TYPE> A(num_chunks);
                        std::vector<TYPE> B(2 * (num_chunks - 2));

                        TYPE x_n;
                        TYPE y_n;
                        TYPE q_n;
                        TYPE r_n;
                        TYPE p_n;

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            for (std::size_t i = 0; i < num_chunks; ++i) {
                                X[i] = input.x[i];
                                Y[i] = input.y[i];
                                P[i] = input.p[i];
                                PP[i] = input.pp[i];
                            }
                            extended_integral_type foreign_p = 0, foreign_x = 0,
                                                   foreign_y = 0, pow = 1;

                            for (std::size_t i = 0; i < num_chunks; ++i) {
                                foreign_x += extended_integral_type(
                                                 integral_type(X[i].to_integral())) *
                                             pow;
                                foreign_y += extended_integral_type(
                                                 integral_type(Y[i].to_integral())) *
                                             pow;
                                foreign_p += extended_integral_type(
                                                 integral_type(P[i].to_integral())) *
                                             pow;
                                pow <<= bit_size_chunk;
                            }

                            extended_integral_type foreign_r = (foreign_x * foreign_y) %
                                                               foreign_p,  // r = x*y % p
                                foreign_q = (foreign_x * foreign_y - foreign_r) /
                                            foreign_p;  // q = (x*y - r)/p
                            extended_integral_type mask =
                                (extended_integral_type(1) << bit_size_chunk) - 1;
                            for (std::size_t j = 0; j < num_chunks; ++j) {
                                Q[j] = TYPE(foreign_q & mask);
                                R[j] = TYPE(foreign_r & mask);
                                foreign_q >>= bit_size_chunk;
                                foreign_r >>= bit_size_chunk;
                            }
                        }

                        for (std::size_t i = 0; i < num_chunks; ++i) {
                            allocate(X[i]);
                            allocate(Y[i]);
                            allocate(PP[i]);
                            allocate(Q[i]);
                            allocate(R[i]);
                            allocate(P[i]);
                        }

                        TYPE pow = 1;
                        for (std::size_t j = 0; j < num_chunks; ++j) {
                            x_n += X[j] * pow;
                            y_n += Y[j] * pow;
                            q_n += Q[j] * pow;
                            r_n += R[j] * pow;
                            p_n += P[j] * pow;
                            pow *= integral_type{1} << bit_size_chunk;
                        }

                        allocate(x_n);
                        allocate(y_n);
                        allocate(q_n);
                        allocate(p_n);
                        allocate(r_n);
                        // constrain X*Y - Q*P - R = 0
                        constrain(x_n * y_n - q_n * p_n - r_n);

                        // computation mod 2^T
                        // (mod 2^t)xy + qp' = [x_0, x_1, x_2, x_3] ⋅ [y_0, y_1, y_2, y_3]
                        // + [q_0, q_1, q_2, q_3] ⋅ [pp_0, pp_1, pp_2, pp_3]
                        //    z_0 = x_0 ⋅ y_0 + q_0 ⋅ pp_0
                        //    z_1 = x_0 ⋅ y_1 + x_1 ⋅ y_0 + q_0 ⋅ pp_1 + q_1 ⋅ pp_0
                        //    z_2 = x_0 ⋅ y_2 + x_1 ⋅ y_1 + x_2 ⋅ y_0 + q_0 ⋅ pp_2 + 
                        //          q_1 ⋅ pp_1 + q_2 ⋅ pp_0 
                        //    z_3 = x_0 ⋅ y_3 + x_1 ⋅ y_2 + x_2 ⋅ y_1 +
                        //      x_3 ⋅ y_0 + q_0 ⋅ pp_3 + q_1 ⋅ pp_2 + q_2 ⋅ pp_1 + 
                        //      q_3 ⋅ pp_0
                        //   Result = z_0 ⋅ 2^{0b} + z_1 ⋅ 2^{1b} + z_2 ⋅ 2^{2b} + z_3 ⋅
                        //   2^{3b}
                        BOOST_ASSERT(num_chunks * 2 * (integral_type{1} << 2 * bit_size_chunk) < FieldType::modulus);
                        for (std::size_t i = 0; i < num_chunks; ++i) {
                            Z[i] = TYPE(0);
                            for (std::size_t j = 0; j <= i; ++j) {
                                Z[i] += X[j] * Y[i - j] + PP[j] * Q[i - j];
                            }
                            allocate(Z[i]);
                        }

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            A[0] = Z[0] - R[0];
                            integral_type a_integral =
                                integral_type(A[0].to_integral()) >> bit_size_chunk;
                            A[0] = TYPE(a_integral);
                            for (std::size_t i = 1; i < num_chunks; ++i) {
                                A[i] = (Z[i] + A[i - 1] - R[i]);
                                a_integral =
                                    integral_type(A[i].to_integral()) >> bit_size_chunk;
                                A[i] = TYPE(a_integral);
                            }
                            for (std::size_t i = 0; i < num_chunks - 2; ++i) {
                                B[2 * i] =
                                    TYPE(integral_type(A[i].to_integral()) &
                                         ((integral_type(1) << bit_size_chunk) - 1));
                                B[2 * i + 1] = TYPE(integral_type(A[i].to_integral()) >>
                                                    bit_size_chunk);
                            }
                        }

                        integral_type b_shift = integral_type(1) << bit_size_chunk;
                        allocate(A[0]);
                        constrain(A[0] * b_shift - Z[0] + R[0]);
                        // constrain that the last t bits of z are equal to r:
                        // z_0 - r_0 = a_0 ⋅ 2^b
                        // z_1 + a_0 - r_1 = a_1 ⋅ 2^b
                        // z_2 + a_1 - r_2 = a_2 ⋅ 2^b
                        // z_3 + a_2 - r_3 = a_3 ⋅ 2^b
                        for (std::size_t i = 1; i < num_chunks; ++i) {
                            allocate(A[i]);
                            constrain(A[i] * b_shift - Z[i] - A[i - 1] + R[i]);
                        }

                        // If there is a fault in the computation:
                        // a'_0 = a_0 + 2^{3b+1}
                        // a'_1 = a_1 + 2^{2b+1}, a'_2 = a_2 + 2^{b+1}
                        //
                        // This results in a faulty `a_2`, which can cause an error in
                        // `z_3 - r_3`. The same issue applies for `a_1`. However, higher
                        // `a_i` values will only interfere with other `a_j` values and
                        // not with `z_i` or `r_i`.
                        //
                        // a_0 = b_0 + b_1 ⋅ 2^b
                        // a_1 = b_2 + b_3 ⋅ 2^b

                        for (std::size_t i = 0; i < num_chunks - 2; ++i) {
                            allocate(B[2 * i]);
                            allocate(B[2 * i + 1]);
                            constrain(B[2 * i] + B[2 * i + 1] * b_shift - A[i]);
                        }

                        Range_Check rc1 =
                            Range_Check(context_object, R, num_chunks, bit_size_chunk);
                        Range_Check rc2 =
                            Range_Check(context_object, Q, num_chunks, bit_size_chunk);
                        Range_Check rc3 =
                            Range_Check(context_object, B, 2 * (num_chunks - 2), bit_size_chunk);

                        Check_Mod_P c1 = Check_Mod_P(context_object, {R, PP, input.zero},
                                                     num_chunks, bit_size_chunk, false);
                        Check_Mod_P c2 = Check_Mod_P(context_object, {Q, PP, input.zero},
                                                     num_chunks, bit_size_chunk, false);

                        // Starting b\n
                        if (num_chunks > 2) {
                            std::vector<TYPE> B_X[2 * (num_chunks > 2)];
                            for (int i = 0; i < 2 * (num_chunks > 2); ++i) {
                                B_X[i].resize(num_chunks);

                                for (std::size_t j = 0; j < num_chunks - 2; ++j) {
                                    B_X[i].push_back(B[j + i * (num_chunks - 2)]);
                                    allocate(B_X[i][j]);
                                }

                                B_X[i].push_back(X[num_chunks - 3]);
                                B_X[i].push_back(X[num_chunks - 3]);
                                allocate(B_X[i][num_chunks - 2]);
                                allocate(B_X[i][num_chunks - 1]);
                                Range_Check(context_object, B_X[i], num_chunks,
                                            bit_size_chunk);
                            }
                        }

                        if (make_links) {
                            for (std::size_t i = 0; i < num_chunks; ++i) {
                                copy_constrain(X[i], input.x[i]);
                                copy_constrain(Y[i], input.y[i]);
                                copy_constrain(P[i], input.p[i]);
                                copy_constrain(PP[i], input.pp[i]);
                            }
                        }

                        for (int i = 0; i < num_chunks; ++i) {
                            r.push_back(R[i]);
                        }
                    }
                };

                template<typename FieldType, GenerationStage stage>
                class pallas_flexible_multiplication
                    : public flexible_multiplication<
                          FieldType, stage,
                          crypto3::algebra::curves::pallas::base_field_type> {
                    using Base = flexible_multiplication<
                        FieldType, stage,
                        crypto3::algebra::curves::pallas::base_field_type>;

                  public:
                    using Base::Base;
                };

                template<typename FieldType, GenerationStage stage>
                class vesta_flexible_multiplication
                    : public flexible_multiplication<
                          FieldType, stage,
                          crypto3::algebra::curves::vesta::base_field_type> {
                    using Base = flexible_multiplication<
                        FieldType, stage,
                        crypto3::algebra::curves::vesta::base_field_type>;

                  public:
                    using Base::Base;
                };

            }  // namespace components
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil

#endif  // CRYPTO3_BBF_COMPONENTS_FLEXIBLE_MULTIPLICATION_HPP
