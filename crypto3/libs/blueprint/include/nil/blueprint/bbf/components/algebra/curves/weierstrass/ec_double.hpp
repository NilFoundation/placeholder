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
// @file Declaration of interfaces for doubling an EC points over a non-native field
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BBF_COMPONENTS_EC_DOUBLE_ECDSA_HPP
#define CRYPTO3_BBF_COMPONENTS_EC_DOUBLE_ECDSA_HPP

#include <nil/blueprint/bbf/components/algebra/fields/non_native/add_sub_mod_p.hpp>
#include <nil/blueprint/bbf/components/algebra/fields/non_native/check_mod_p.hpp>
#include <nil/blueprint/bbf/components/algebra/fields/non_native/flexible_multiplication.hpp>
#include <nil/blueprint/bbf/components/detail/allocate_public_input_chunks.hpp>
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
                // For a point Q = (x_Q,y_Q) from an elliptic curve over F[p]
                // computes R = (x_R, y_R) = 2Q (EC doubling)
                // Expects input as k-chunked values with b bits per chunk
                // p' = 2^(kb) - p
                // Input: xQ[0],...,xQ[k-1], yQ[0],...,yQ[k-1], p[0],...,p[k-1],
                //      pp[0],...,pp[k-1], 0 (expects zero constant as input)
                // Output: xR[0],...,xR[k-1], yR[0],...,yR[k-1]

                template<typename FieldType, GenerationStage stage,
                         typename NonNativeFieldType>
                class ec_double : public generic_component<FieldType, stage> {
                    using generic_component<FieldType, stage>::allocate;
                    using generic_component<FieldType, stage>::copy_constrain;
                    using generic_component<FieldType, stage>::constrain;

                  public:
                    using typename generic_component<FieldType, stage>::TYPE;
                    using typename generic_component<FieldType, stage>::context_type;
                    using typename generic_component<FieldType, stage>::table_params;

                    struct input_type {
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
                        std::size_t witness = 4 * num_chunks + 1;
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
                        allocate_chunks(input.xQ, 0, &row);
                        allocate_chunks(input.yQ, 0, &row);
                        allocate_chunks(input.p, 0, &row);
                        allocate_chunks(input.pp, 0, &row);
                        ctx.allocate(input.zero, 0, row++,
                                     column_type::public_input);
                    }

                    ec_double(context_type &context_object, const input_type &input,
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
                        std::vector<TYPE> Z(num_chunks);
                        std::vector<TYPE> XR(num_chunks);
                        std::vector<TYPE> YR(num_chunks);

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            non_native_integral_type pow = 1;
                            NON_NATIVE_TYPE xQ = 0, yQ = 0;

                            for (std::size_t i = 0; i < num_chunks; ++i) {
                                xQ += non_native_integral_type(
                                          integral_type(input.xQ[i].to_integral())) *
                                      pow;
                                yQ += non_native_integral_type(
                                          integral_type(input.yQ[i].to_integral())) *
                                      pow;
                                pow <<= bit_size_chunk;
                            }

                            NON_NATIVE_TYPE
                            lambda =
                                (yQ == 0)
                                    ? 0
                                    : 3 * xQ * xQ *
                                          ((2 * yQ).inversed()),  // if yQ = 0, lambda = 0
                                z = (yQ == 0) ? 0 : yQ.inversed(),  // if yQ = 0, z = 0
                                xR = lambda * lambda - 2 * xQ,
                            yR = lambda * (xQ - xR) - yQ;

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
                            Z = base(z);
                            XR = base(xR);
                            YR = base(yR);
                        }

                        for (std::size_t i = 0; i < num_chunks; ++i) {
                            allocate(LAMBDA[i]);
                            allocate(Z[i]);
                            allocate(XR[i]);
                            allocate(YR[i]);
                        }

                        auto check_chunked = [&context_object, &input, num_chunks, bit_size_chunk](
                                std::vector<TYPE> x) {
                            Range_Check rc = Range_Check(context_object, x, num_chunks,
                                                         bit_size_chunk);
                            Check_Mod_P cm = Check_Mod_P(context_object, {x, input.pp, input.zero},
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
                        check_chunked(Z);
                        check_chunked(XR);
                        check_chunked(YR);

                        auto MultModP = [&context_object, &input, num_chunks, bit_size_chunk](
                                std::vector<TYPE> x, std::vector<TYPE> y) {
                            Multiplication_Mod_P t =
                                Multiplication_Mod_P(context_object, {x, y, input.p, input.pp, input.zero},
                                                     num_chunks, bit_size_chunk);
                            return t.r;
                        };
                        auto AddModP = [&context_object, &input, num_chunks, bit_size_chunk](
                                std::vector<TYPE> x, std::vector<TYPE> y) {
                            Addition_Mod_P t =
                                Addition_Mod_P(context_object, {x, y, input.p, input.pp, input.zero},
                                               num_chunks, bit_size_chunk);
                            return t.r;
                        };
                        auto SubModP = [&context_object, &input, num_chunks, bit_size_chunk](
                                std::vector<TYPE> x, std::vector<TYPE> y) {
                            Substraction_Mod_P t = Substraction_Mod_P(
                                context_object, {x, y, input.p, input.pp, input.zero},
                                num_chunks, bit_size_chunk);
                            return t.r;
                        };

                        auto t1 = MultModP(input.yQ, LAMBDA);   // t1 = yQ * lambda
                        auto t2 = AddModP(t1, t1);              // t2 = t1 + t1 = 2yQ * lambda
                        auto t3 = AddModP(input.xQ, input.xQ);  // t3 = xQ + xQ = 2xQ
                        auto t4 = AddModP(input.xQ, t3);        // t4 = xQ + t3 = 3xQ
                        auto t5 = MultModP(t4, input.xQ);       // t5 = t4 * xQ = 3xQ^2
                        CopyConstrain(t2, t5);       // 2yQ lambda = 3xQ^2
                        auto t6 = AddModP(XR, t3);              // t6 = xR + t3 = xR + 2xQ
                        auto t7 = MultModP(LAMBDA, LAMBDA);     // t7 = lambda * lambda
                        CopyConstrain(t6, t7);       // xR + 2xQ = lambda^2
                        auto t8 = AddModP(YR, input.yQ);        // t8 = yR + yQ
                        auto t9 = SubModP(input.xQ, XR);        // t9 = xQ - xR
                        auto t10 = MultModP(LAMBDA, t9);        // t10 = lambda * t9 =lambda(xQ-xR)
                        CopyConstrain(t8, t10);      // yR + yQ = lambda(xQ - xR)
                        auto t11 = MultModP(Z, t1);             // t11 = z * t1 = z * yQ * lambda
                        CopyConstrain(LAMBDA, t11);  // lambda = z yQ lambda

                        for (int i = 0; i < num_chunks; ++i) {
                            xR.push_back(XR[i]);
                            yR.push_back(YR[i]);
                        }
                    }
                };

                template<typename FieldType, GenerationStage stage>
                class pallas_ec_double
                    : public ec_double<
                          FieldType, stage,
                          crypto3::algebra::curves::pallas::base_field_type> {
                    using Base =
                        ec_double<FieldType, stage,
                                  crypto3::algebra::curves::pallas::base_field_type>;

                  public:
                    using Base::Base;
                };

                template<typename FieldType, GenerationStage stage>
                class vesta_ec_double
                    : public ec_double<FieldType, stage,
                                       crypto3::algebra::curves::vesta::base_field_type> {
                    using Base =
                        ec_double<FieldType, stage,
                                  crypto3::algebra::curves::vesta::base_field_type>;

                  public:
                    using Base::Base;
                };

                template<typename FieldType, GenerationStage stage>
                class secp_k1_256_ec_double
                    : public ec_double<
                          FieldType, stage,
                          crypto3::algebra::curves::secp_k1<256>::base_field_type> {
                    using Base = ec_double<
                        FieldType, stage,
                        crypto3::algebra::curves::secp_k1<256>::base_field_type>;

                  public:
                    using Base::Base;
                };

            }  // namespace components
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil

#endif  // CRYPTO3_BBF_COMPONENTS_EC_DOUBLE_ECDSA_HPP
