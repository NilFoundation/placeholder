//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
// Copyright (c) 2025 Antoine Cyr <antoinecyr@nil.foundation>
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
// @file Declaration of interfaces for addition of EC points T,Q as T+Q+T over a
// non-native field
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BBF_COMPONENTS_EC_TWO_T_PLUS_Q_ECDSA_HPP
#define CRYPTO3_BBF_COMPONENTS_EC_TWO_T_PLUS_Q_ECDSA_HPP

#include <nil/blueprint/bbf/components/algebra/fields/non_native/add_sub_mod_p.hpp>
#include <nil/blueprint/bbf/components/algebra/fields/non_native/check_mod_p.hpp>
#include <nil/blueprint/bbf/components/algebra/fields/non_native/flexible_multiplication.hpp>
#include <nil/blueprint/bbf/components/detail/range_check_multi.hpp>
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/secp_k1.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            namespace components {
                // Parameters: num_chunks = k, bit_size_chunk = b
                // For points T = (x_T,y_T), Q = (x_Q,y_Q), x_T != x_T, T,Q != O
                // from an elliptic curve over F[p]
                // computes R = (x_R, y_R) = T + Q + T
                // Expects input as k-chunked values with b bits per chunk
                // p' = 2^(kb) - p
                // Input: xT[0],...,xT[k-1],yT[0],...,yT[k-1],xQ[0],...,xQ[k-1],
                //      yQ[0],...,yQ[k-1], p[0], ..., p[k-1], pp[0], ..., pp[k-1],
                //      0 (expects zero constant as input)
                // Output: xR[0],...,xR[k-1], yR[0],...,yR[k-1]
                //
                template<typename FieldType, GenerationStage stage,
                         typename NonNativeFieldType>
                class ec_two_t_plus_q : public generic_component<FieldType, stage> {
                    using generic_component<FieldType, stage>::allocate;
                    using generic_component<FieldType, stage>::copy_constrain;
                    using generic_component<FieldType, stage>::constrain;

                  public:
                    using typename generic_component<FieldType, stage>::TYPE;
                    using typename generic_component<FieldType, stage>::context_type;
                    using typename generic_component<FieldType, stage>::table_params;

                    struct input_type {
                      std::vector<TYPE> xT;
                      std::vector<TYPE> yT;
                      std::vector<TYPE> xQ;
                      std::vector<TYPE> yQ;
                      std::vector<TYPE> p;
                      std::vector<TYPE> pp;
                      TYPE zero;
                    };

                  public:
                    std::vector<TYPE> xR;
                    std::vector<TYPE> yR;

                    static table_params get_minimal_requirements(
                        std::size_t num_chunks, std::size_t bit_size_chunk) {
                        std::size_t witness = 6 * num_chunks + 1;
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
                        allocate_chunks(input.xT, 0, &row);
                        allocate_chunks(input.yT, 0, &row);
                        allocate_chunks(input.xQ, 0, &row);
                        allocate_chunks(input.yQ, 0, &row);
                        allocate_chunks(input.p, 0, &row);
                        allocate_chunks(input.pp, 0, &row);
                        ctx.allocate(input.zero, 0, row++,
                                     column_type::public_input);
                    }

                    ec_two_t_plus_q(context_type& context_object, const input_type &input,
                                    std::size_t num_chunks, std::size_t bit_size_chunk,
                                    bool make_links = true)
                        : generic_component<FieldType, stage>(context_object) {
                        using integral_type = typename FieldType::integral_type;
                        using NON_NATIVE_TYPE = typename NonNativeFieldType::value_type;
                        using non_native_integral_type =
                            typename NonNativeFieldType::integral_type;

                        using Range_Check =
                            typename bbf::components::range_check_multi<FieldType, stage>;
                        using Check_Mod_P =
                            typename bbf::components::check_mod_p<FieldType, stage>;
                        using Addition_Mod_P = typename bbf::components::add_sub_mod_p<
                            FieldType, stage, NonNativeFieldType, true>;
                        using Substraction_Mod_P =
                            typename bbf::components::add_sub_mod_p<
                                FieldType, stage, NonNativeFieldType, false>;
                        using Multiplication_Mod_P =
                            typename bbf::components::flexible_multiplication<
                                FieldType, stage, NonNativeFieldType>;

                        std::vector<TYPE> LAMBDA(num_chunks);
                        std::vector<TYPE> MU(num_chunks);
                        std::vector<TYPE> XS(num_chunks);
                        std::vector<TYPE> XR(num_chunks);
                        std::vector<TYPE> YR(num_chunks);

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            non_native_integral_type pow = 1;
                            NON_NATIVE_TYPE xT = 0, yT = 0, xQ = 0, yQ = 0;

                            for (std::size_t i = 0; i < num_chunks; ++i) {
                                xT += non_native_integral_type(
                                          integral_type(input.xT[i].to_integral())) *
                                      pow;
                                yT += non_native_integral_type(
                                          integral_type(input.yT[i].to_integral())) *
                                      pow;
                                xQ += non_native_integral_type(
                                          integral_type(input.xQ[i].to_integral())) *
                                      pow;
                                yQ += non_native_integral_type(
                                          integral_type(input.yQ[i].to_integral())) *
                                      pow;
                                pow <<= bit_size_chunk;
                            }

                            NON_NATIVE_TYPE diff1 = xQ - xT,
                                            lambda = (diff1 == 0)
                                                         ? 0
                                                         : (yQ - yT) * diff1.inversed(),
                                            xS = lambda * lambda - xT - xQ,
                                            diff2 = xS - xT,
                                            mu = (diff2 == 0)
                                                     ? -lambda
                                                     : -lambda -
                                                           (2 * yT) * diff2.inversed(),
                                            xR = mu * mu - xT - xS,
                                            yR = mu * (xT - xR) - yT;

                            auto base = [num_chunks, bit_size_chunk](NON_NATIVE_TYPE x) {
                                std::vector<TYPE> res(num_chunks);
                                non_native_integral_type mask =
                                    (non_native_integral_type(1) << bit_size_chunk) - 1;
                                non_native_integral_type x_value =
                                    non_native_integral_type(x.to_integral());
                                for (std::size_t i = 0; i < num_chunks; i++) {
                                    res[i] = TYPE(x_value & mask);
                                    x_value >>= bit_size_chunk;
                                }
                                return res;
                            };

                            LAMBDA = base(lambda);
                            MU = base(mu);
                            XS = base(xS);
                            XR = base(xR);
                            YR = base(yR);
                        }

                        for (std::size_t i = 0; i < num_chunks; ++i) {
                            allocate(LAMBDA[i]);
                            allocate(MU[i]);
                            allocate(XS[i]);
                            allocate(XR[i]);
                            allocate(YR[i]);
                        }

                        auto check_chunked = [&context_object, num_chunks, bit_size_chunk,
                                              &input](std::vector<TYPE> x) {
                            Range_Check rc = Range_Check(context_object, x, num_chunks,
                                                         bit_size_chunk);
                            Check_Mod_P cm =
                                Check_Mod_P(context_object, {x, input.pp, input.zero},
                                            num_chunks, bit_size_chunk);
                        };

                        // Copy constraint generation lambda expression
                        auto CopyConstrain = [this, num_chunks](std::vector<TYPE> x,
                                                                std::vector<TYPE> y) {
                            for (std::size_t i = 0; i < num_chunks; i++) {
                                copy_constrain(x[i], y[i]);
                            }
                        };

                        // perform range checks and mod p checks on all stored variables
                        check_chunked(LAMBDA);
                        check_chunked(MU);
                        check_chunked(XS);
                        check_chunked(XR);
                        check_chunked(YR);

                        auto MultModP = [&context_object, &input,
                                         num_chunks, bit_size_chunk](
                                            std::vector<TYPE> x, std::vector<TYPE> y) {
                            Multiplication_Mod_P t = Multiplication_Mod_P(
                                context_object, {x, y, input.p, input.pp, input.zero},
                                num_chunks, bit_size_chunk);
                            return t.r;
                        };
                        auto AddModP = [&context_object, &input,
                                        num_chunks, bit_size_chunk](std::vector<TYPE> x,
                                                                    std::vector<TYPE> y) {
                            Addition_Mod_P t =
                                Addition_Mod_P(
                                    context_object, {x, y, input.p, input.pp, input.zero},
                                    num_chunks, bit_size_chunk);
                            return t.r;
                        };
                        auto SubModP = [&context_object, &input,
                                        num_chunks, bit_size_chunk](std::vector<TYPE> x,
                                                                    std::vector<TYPE> y) {
                            Substraction_Mod_P t = Substraction_Mod_P(
                                context_object, {x, y, input.p, input.pp, input.zero},
                                num_chunks, bit_size_chunk);
                            return t.r;
                        };

                        auto t1 = SubModP(input.xQ, input.xT);  // t1 = xQ - xT
                        auto t2 = MultModP(t1, LAMBDA);         // t2 = t1 * lambda = (xQ-xT)lambda
                        auto t3 = AddModP(t2, input.yT);        // t3 = t2 + yT = (xQ-xP)lambda + yT
                        CopyConstrain(t3, input.yQ);  // (xQ - xT)lambda + yP = yQ
                        auto t4 = AddModP(XS, input.xT);        // t4 = xS + xT
                        auto t5 = AddModP(t4, input.xQ);        // t5 = t4 + xQ = xS + xT + xQ
                        auto t6 = MultModP(LAMBDA, LAMBDA);     // t6 = lambda * lambda
                        CopyConstrain(t5, t6);        // xS + xT + xQ = lambda^2
                        auto t7 = AddModP(LAMBDA, MU);          // t7 = lambda + mu
                        auto t8 = SubModP(input.xT, XS);        // t8 = xT - xS
                        auto t9 = MultModP(t7, t8);             // t9 = t7*t8 = (lambda+mu)(xT-xS)
                        auto t10 = AddModP(input.yT, input.yT); // t10 = yT + yT = 2yT
                        CopyConstrain(t9, t10);       // (lambda+mu)(xT - xS) = 2yT
                        auto t11 = AddModP(t4, XR);             // t11 = t4 + xR = xS + xT + xR
                        auto t12 = MultModP(MU, MU);            // t12 = mu * mu
                        CopyConstrain(t11, t12);      // xS + xT + xR = mu^2
                        auto t13 = AddModP(YR, input.yT);       // t13 = yR + yT
                        auto t14 = SubModP(input.xT, XR);       // t14 = xT - xR
                        auto t15 = MultModP(MU, t14);           // t15 = mu * t14 = mu(xT-xR)
                        CopyConstrain(t13, t15);      // yR + yT = mu(xT - xR)

                        for (int i = 0; i < num_chunks; ++i) {
                            xR.push_back(XR[i]);
                            yR.push_back(YR[i]);
                        }
                    }
                };

                template<typename FieldType, GenerationStage stage>
                class pallas_ec_two_t_plus_q
                    : public ec_two_t_plus_q<
                          FieldType, stage,
                          crypto3::algebra::curves::pallas::base_field_type> {
                    using Base = ec_two_t_plus_q<
                        FieldType, stage,
                        crypto3::algebra::curves::pallas::base_field_type>;

                  public:
                    using Base::Base;
                };

                template<typename FieldType, GenerationStage stage>
                class vesta_ec_two_t_plus_q
                    : public ec_two_t_plus_q<
                          FieldType, stage,
                          crypto3::algebra::curves::vesta::base_field_type> {
                    using Base =
                        ec_two_t_plus_q<FieldType, stage,
                                        crypto3::algebra::curves::vesta::base_field_type>;

                  public:
                    using Base::Base;
                };

                template<typename FieldType, GenerationStage stage>
                class secp_k1_256_ec_two_t_plus_q
                    : public ec_two_t_plus_q<
                        FieldType, stage,
                        crypto3::algebra::curves::secp_k1<256>::base_field_type> {
                    using Base = ec_two_t_plus_q<
                        FieldType, stage,
                        crypto3::algebra::curves::secp_k1<256>::base_field_type>;

                public:
                    using Base::Base;
                };

            }  // namespace components
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil

#endif  // CRYPTO3_BBF_COMPONENTS_EC_TWO_T_PLUS_Q_ECDSA_HPP
