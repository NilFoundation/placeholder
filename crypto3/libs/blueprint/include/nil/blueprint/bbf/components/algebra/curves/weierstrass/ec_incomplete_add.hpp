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
// @file Declaration of interfaces for full addition of EC points over a non-native field
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BBF_COMPONENTS_EC_INCOMPLETE_ADD_ECDSA_HPP
#define CRYPTO3_BBF_COMPONENTS_EC_INCOMPLETE_ADD_ECDSA_HPP

#include <nil/blueprint/bbf/components/algebra/fields/non_native/add_sub_mod_p.hpp>
#include <nil/blueprint/bbf/components/algebra/fields/non_native/check_mod_p.hpp>
#include <nil/blueprint/bbf/components/algebra/fields/non_native/flexible_multiplication.hpp>
#include <nil/blueprint/bbf/components/detail/range_check_multi.hpp>
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            namespace components {
                // Parameters: num_chunks = k, bit_size_chunk = b
                // For points P = (x_P,y_P), Q = (x_Q,y_Q), x_P != x_Q, P,Q != O
                // from an elliptic curve over F[p]
                // computes R = (x_R, y_R) = P + Q
                // Expects input as k-chunked values with b bits per chunk
                // p' = 2^(kb) - p
                // Input: xP[0],...,xP[k-1],yP[0],...,yP[k-1],xQ[0],...,xQ[k-1],
                //      yQ[0],...,yQ[k-1], p[0], ..., p[k-1], pp[0], ..., pp[k-1],
                //      0 (expects zero constant as input)
                // Output: xR[0],...,xR[k-1], yR[0],...,yR[k-1]
                //
                template<typename FieldType>
                struct ec_incomplete_add_raw_input {
                    using TYPE = typename FieldType::value_type;
                    std::vector<TYPE> xP;
                    std::vector<TYPE> yP;
                    std::vector<TYPE> xQ;
                    std::vector<TYPE> yQ;
                    std::vector<TYPE> p;
                    std::vector<TYPE> pp;
                    TYPE zero;
                };

                template<typename FieldType, GenerationStage stage,
                         typename NonNativeFieldType>
                class ec_incomplete_add : public generic_component<FieldType, stage> {
                    using generic_component<FieldType, stage>::allocate;
                    using generic_component<FieldType, stage>::copy_constrain;
                    using generic_component<FieldType, stage>::constrain;

                  public:
                    using typename generic_component<FieldType, stage>::TYPE;
                    using typename generic_component<FieldType, stage>::context_type;
                    using typename generic_component<FieldType, stage>::table_params;
                    using raw_input_type =
                        typename std::conditional<stage == GenerationStage::ASSIGNMENT,
                                                  ec_incomplete_add_raw_input<FieldType>,
                                                  std::tuple<>>::type;

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

                    static std::tuple<std::vector<TYPE>, std::vector<TYPE>,
                                      std::vector<TYPE>, std::vector<TYPE>,
                                      std::vector<TYPE>, std::vector<TYPE>, TYPE>
                    form_input(context_type& context_object, raw_input_type raw_input,
                               std::size_t num_chunks, std::size_t bit_size_chunk) {
                        std::vector<TYPE> input_xP(num_chunks);
                        std::vector<TYPE> input_yP(num_chunks);
                        std::vector<TYPE> input_xQ(num_chunks);
                        std::vector<TYPE> input_yQ(num_chunks);
                        std::vector<TYPE> input_p(num_chunks);
                        std::vector<TYPE> input_pp(num_chunks);
                        TYPE input_zero;

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            for (std::size_t i = 0; i < num_chunks; i++) {
                                input_xP[i] = raw_input.xP[i];
                                input_yP[i] = raw_input.yP[i];
                                input_xQ[i] = raw_input.xQ[i];
                                input_yQ[i] = raw_input.yQ[i];
                                input_p[i] = raw_input.p[i];
                                input_pp[i] = raw_input.pp[i];
                            }
                            input_zero = raw_input.zero;
                        }
                        for (std::size_t i = 0; i < num_chunks; i++) {
                            context_object.allocate(input_xP[i], 0, i,
                                                    column_type::public_input);
                            context_object.allocate(input_yP[i], 0, i + num_chunks,
                                                    column_type::public_input);
                            context_object.allocate(input_xQ[i], 0, i + 2 * num_chunks,
                                                    column_type::public_input);
                            context_object.allocate(input_yQ[i], 0, i + 3 * num_chunks,
                                                    column_type::public_input);
                            context_object.allocate(input_p[i], 0, i + 4 * num_chunks,
                                                    column_type::public_input);
                            context_object.allocate(input_pp[i], 0, i + 5 * num_chunks,
                                                    column_type::public_input);
                        }
                        context_object.allocate(input_zero, 0, 6 * num_chunks,
                                                column_type::public_input);
                        return std::make_tuple(input_xP, input_yP, input_xQ, input_yQ,
                                               input_p, input_pp, input_zero);
                    }

                    ec_incomplete_add(context_type& context_object,
                                      std::vector<TYPE> input_xP,
                                      std::vector<TYPE> input_yP,
                                      std::vector<TYPE> input_xQ,
                                      std::vector<TYPE> input_yQ,
                                      std::vector<TYPE> input_p,
                                      std::vector<TYPE> input_pp, TYPE input_zero,
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
                        std::vector<TYPE> XR(num_chunks);
                        std::vector<TYPE> YR(num_chunks);

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            non_native_integral_type pow = 1;
                            NON_NATIVE_TYPE xP = 0, yP = 0, xQ = 0, yQ = 0;

                            for (std::size_t i = 0; i < num_chunks; ++i) {
                                xP += non_native_integral_type(
                                          integral_type(input_xP[i].data)) *
                                      pow;
                                yP += non_native_integral_type(
                                          integral_type(input_yP[i].data)) *
                                      pow;
                                xQ += non_native_integral_type(
                                          integral_type(input_xQ[i].data)) *
                                      pow;
                                yQ += non_native_integral_type(
                                          integral_type(input_yQ[i].data)) *
                                      pow;
                                pow <<= bit_size_chunk;
                            }

                            NON_NATIVE_TYPE lambda =
                                                (xQ == xP)
                                                    ? 0
                                                    : (yQ - yP) * ((xQ - xP).inversed()),
                                            xR = lambda * lambda - xP - xQ,
                                            yR = lambda * (xP - xR) - yP;

                            auto base = [num_chunks, bit_size_chunk](NON_NATIVE_TYPE x) {
                                std::vector<TYPE> res(num_chunks);
                                non_native_integral_type mask =
                                    (non_native_integral_type(1) << bit_size_chunk) - 1;
                                non_native_integral_type x_value =
                                    non_native_integral_type(x.data);
                                for (std::size_t i = 0; i < num_chunks; i++) {
                                    res[i] = TYPE(x_value & mask);
                                    x_value >>= bit_size_chunk;
                                }
                                return res;
                            };

                            LAMBDA = base(lambda);
                            XR = base(xR);
                            YR = base(yR);
                        }

                        for (std::size_t i = 0; i < num_chunks; ++i) {
                            allocate(LAMBDA[i]);
                            allocate(XR[i]);
                            allocate(YR[i]);
                        }

                        auto check_chunked = [&context_object, num_chunks, bit_size_chunk,
                                              input_pp, input_zero](std::vector<TYPE> x) {
                            Range_Check rc = Range_Check(context_object, x, num_chunks,
                                                         bit_size_chunk);
                            Check_Mod_P cm =
                                Check_Mod_P(context_object, x, input_pp, input_zero,
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
                        check_chunked(XR);
                        check_chunked(YR);

                        auto MultModP = [&context_object, input_p, input_pp, input_zero,
                                         num_chunks, bit_size_chunk](
                                            std::vector<TYPE> x, std::vector<TYPE> y) {
                            Multiplication_Mod_P t = Multiplication_Mod_P(
                                context_object, x, y, input_p, input_pp, input_zero,
                                num_chunks, bit_size_chunk);
                            return t.r;
                        };
                        auto AddModP = [&context_object, input_p, input_pp, input_zero,
                                        num_chunks, bit_size_chunk](std::vector<TYPE> x,
                                                                    std::vector<TYPE> y) {
                            Addition_Mod_P t =
                                Addition_Mod_P(context_object, x, y, input_p, input_pp,
                                               input_zero, num_chunks, bit_size_chunk);
                            return t.r;
                        };
                        auto SubModP = [&context_object, input_p, input_pp, input_zero,
                                        num_chunks, bit_size_chunk](std::vector<TYPE> x,
                                                                    std::vector<TYPE> y) {
                            Substraction_Mod_P t = Substraction_Mod_P(
                                context_object, x, y, input_p, input_pp, input_zero,
                                num_chunks, bit_size_chunk);
                            return t.r;
                        };

                        auto t1 = SubModP(input_xQ, input_xP);  // t1 = xQ - xP
                        auto t2 = MultModP(t1, LAMBDA);         // t2 = t1 * lambda = (xQ-xP)lambda
                        auto t3 = AddModP(t2, input_yP);        // t3 = t2 + yP = (xQ-xP)lambda + yP
                        CopyConstrain(t3, input_yQ);  // (xQ - xP)lambda + yP = yQ
                        auto t4 = AddModP(XR, input_xP);        // t4 = xR + xP
                        auto t5 = AddModP(t4, input_xQ);        // t5 = t4 + xQ = xR + xP + xQ
                        auto t6 = MultModP(LAMBDA, LAMBDA);     // t6 = lambda * lambda
                        CopyConstrain(t5, t6);        // xR + xP + xQ = lambda^2
                        auto t7 = AddModP(YR, input_yP);        // t7 = yR + yP
                        auto t8 = SubModP(input_xP, XR);        // t8 = xP - xR
                        auto t9 = MultModP(LAMBDA, t8);         // t9 = lambda * t8 =lambda(xP-xR)
                        CopyConstrain(t7, t9);        // yR + yP = lambda(xP - xR)

                        for (int i = 0; i < num_chunks; ++i) {
                            xR.push_back(XR[i]);
                            yR.push_back(YR[i]);
                        }
                    }
                };

                template<typename FieldType, GenerationStage stage>
                class pallas_ec_incomplete_add
                    : public ec_incomplete_add<
                          FieldType, stage,
                          crypto3::algebra::curves::pallas::base_field_type> {
                    using Base = ec_incomplete_add<
                        FieldType, stage,
                        crypto3::algebra::curves::pallas::base_field_type>;

                  public:
                    using Base::Base;
                };

                template<typename FieldType, GenerationStage stage>
                class vesta_ec_incomplete_add
                    : public ec_incomplete_add<
                          FieldType, stage,
                          crypto3::algebra::curves::vesta::base_field_type> {
                    using Base = ec_incomplete_add<
                        FieldType, stage,
                        crypto3::algebra::curves::vesta::base_field_type>;

                  public:
                    using Base::Base;
                };

            }  // namespace components
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil

#endif  // CRYPTO3_BBF_COMPONENTS_EC_INCOMPLETE_ADD_ECDSA_HPP
