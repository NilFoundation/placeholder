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

#ifndef CRYPTO3_BBF_COMPONENTS_EC_FULL_ADD_ECDSA_HPP
#define CRYPTO3_BBF_COMPONENTS_EC_FULL_ADD_ECDSA_HPP

#include <nil/blueprint/bbf/components/algebra/fields/non_native/add_sub_mod_p.hpp>
#include <nil/blueprint/bbf/components/algebra/fields/non_native/check_mod_p.hpp>
#include <nil/blueprint/bbf/components/algebra/fields/non_native/flexible_multiplication.hpp>
#include <nil/blueprint/bbf/components/algebra/fields/non_native/negation_mod_p.hpp>
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
                // For points P = (x_P,y_P), Q = (x_Q,y_Q), x_P != x_Q, P,Q != O
                // from an elliptic curve over F[p]
                // computes R = (x_R, y_R) = P + Q
                // Expects input as k-chunked values with b bits per chunk
                // p' = 2^(kb) - p
                // Input: xP[0],...,xP[k-1],yP[0],...,yP[k-1],xQ[0],...,xQ[k-1],
                //      yQ[0],...,yQ[k-1], p[0], ..., p[k-1], pp[0], ..., pp[k-1],
                //      0 (expects zero constant as input)
                // Output: xR[0],...,xR[k-1], yR[0],...,yR[k-1]

                template<typename FieldType, GenerationStage stage,
                         typename NonNativeFieldType>
                class ec_full_add : public generic_component<FieldType, stage> {
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
                      std::vector<TYPE> xP;
                      std::vector<TYPE> yP;
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
                            context_type& ctx, input_type& input,
                            std::size_t num_chunks, std::size_t bit_size_chunk) {
                        AllocatePublicInputChunks allocate_chunks(ctx, num_chunks);

                        std::size_t row = 0;
                        allocate_chunks(input.xP, 0, &row);
                        allocate_chunks(input.yP, 0, &row);
                        allocate_chunks(input.xQ, 0, &row);
                        allocate_chunks(input.yQ, 0, &row);
                        allocate_chunks(input.p, 0, &row);
                        allocate_chunks(input.pp, 0, &row);
                        ctx.allocate(input.zero, 0, row++,
                                     column_type::public_input);
                    }

                    ec_full_add(context_type& context_object,
                                const input_type &input, std::size_t num_chunks,
                                std::size_t bit_size_chunk,
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
                        using Negation_Mod_P =
                            typename bbf::components::negation_mod_p<FieldType, stage,
                                                                     NonNativeFieldType>;
                        using Multiplication_Mod_P =
                            typename bbf::components::flexible_multiplication<
                                FieldType, stage, NonNativeFieldType>;

                        std::vector<TYPE> LAMBDA(num_chunks);
                        std::vector<TYPE> XR(num_chunks);
                        std::vector<TYPE> YR(num_chunks);
                        std::vector<TYPE> ZP(num_chunks);
                        std::vector<TYPE> ZQ(num_chunks);
                        std::vector<TYPE> ZPQ(num_chunks);
                        std::vector<TYPE> WPQ(num_chunks);

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            non_native_integral_type pow = 1;
                            NON_NATIVE_TYPE xP = 0, yP = 0, xQ = 0, yQ = 0;

                            for (std::size_t i = 0; i < num_chunks; ++i) {
                                xP += non_native_integral_type(
                                          integral_type(input.xP[i].to_integral())) *
                                      pow;
                                yP += non_native_integral_type(
                                          integral_type(input.yP[i].to_integral())) *
                                      pow;
                                xQ += non_native_integral_type(
                                          integral_type(input.xQ[i].to_integral())) *
                                      pow;
                                yQ += non_native_integral_type(
                                          integral_type(input.yQ[i].to_integral())) *
                                      pow;
                                pow <<= bit_size_chunk;
                            }

                            NON_NATIVE_TYPE
                            lambda, xR, yR,
                                // indicator variables
                                zP = (yP == 0) ? 0 : yP.inversed(),
                                zQ = (yQ == 0) ? 0 : yQ.inversed(),
                                zPQ = (xP == xQ) ? 0 : (xP - xQ).inversed(),
                                wPQ = ((xP == xQ) && (yP + yQ != 0))
                                          ? (yP + yQ).inversed()
                                          : 0;

                            if (yP == 0) {
                                xR = xQ;
                                yR = yQ;
                                // lambda doesn't matter for (xR,yR), but needs to satisfy
                                // the constraints
                                lambda =
                                    (xP == xQ) ? 0 : (yQ - yP) * ((xQ - xP).inversed());
                            } else if (yQ == 0) {
                                xR = xP;
                                yR = yP;
                                // lambda doesn't matter for (xR,yR), but needs to satisfy
                                // the constraints
                                lambda =
                                    (xP == xQ) ? 0 : (yQ - yP) * ((xQ - xP).inversed());
                            } else if ((xP == xQ) && (yP + yQ == 0)) {
                                xR = 0;
                                yR = 0;
                                // lambda doesn't matter for (xR,yR), but needs to satisfy
                                // the constraints
                                lambda = 3 * xP * xP * ((2 * yP).inversed());
                            } else {
                                if (xP == xQ) {  // point doubling
                                    lambda = 3 * xP * xP * ((2 * yP).inversed());
                                } else {  // regular addition
                                    NON_NATIVE_TYPE diff = xQ - xP;
                                    lambda = (yQ - yP) * (diff.inversed());
                                }
                                xR = lambda * lambda - xP - xQ,
                                yR = lambda * (xP - xR) - yP;
                            }

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
                            XR = base(xR);
                            YR = base(yR);
                            ZP = base(zP), ZQ = base(zQ), ZPQ = base(zPQ),
                            WPQ = base(wPQ);
                        }

                        for (std::size_t i = 0; i < num_chunks; ++i) {
                            allocate(LAMBDA[i]);
                            allocate(XR[i]);
                            allocate(YR[i]);
                            allocate(ZP[i]);
                            allocate(ZQ[i]);
                            allocate(ZPQ[i]);
                            allocate(WPQ[i]);
                        }

                        auto check_chunked = [&context_object, num_chunks, bit_size_chunk, &input](
                                std::vector<TYPE> x) {
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
                        check_chunked(XR);
                        check_chunked(YR);
                        check_chunked(ZP);
                        check_chunked(ZQ);
                        check_chunked(ZPQ);
                        check_chunked(WPQ);

                        auto MultModP = [&context_object, &input, num_chunks, bit_size_chunk](
                                std::vector<TYPE> x, std::vector<TYPE> y) {
                            Multiplication_Mod_P t = Multiplication_Mod_P(
                                context_object, {x, y, input.p, input.pp, input.zero},
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
                        auto NegModP = [&context_object, &input, num_chunks, bit_size_chunk](
                                std::vector<TYPE> x) {
                            Negation_Mod_P t =
                                Negation_Mod_P(
                                    context_object, {x, input.p, input.pp, input.zero},
                                    num_chunks, bit_size_chunk);
                            return t.r;
                        };

                        std::vector<TYPE> input_zero_vector(num_chunks, input.zero);

                        // part 1
                        auto t1 = SubModP(XR, input.xQ);       // t1 = xR - xQ
                        auto t2 = SubModP(YR, input.yQ);       // t2 = yR - yQ
                        auto t3 = SubModP(XR, input.xP);       // t3 = xR - xP
                        auto t4 = SubModP(YR, input.yP);       // t4 = yR - yP
                        auto t5 = SubModP(input.xP, input.xQ); // t5 = xP - xQ
                        auto t6 = MultModP(input.yP, ZP);      // t6 = yP * zP
                        auto t7 = MultModP(input.yQ, ZQ);      // t7 = yQ * zQ
                        auto t8 = MultModP(t5, ZPQ);           // t8 = (xP - xQ) zPQ = ZPQ
                        auto t9 = MultModP(t1, t6);           // t9 = (xR - xQ) yP zP
                        CopyConstrain(t1, t9);        // t1 = t9
                        auto t10 = MultModP(t2, t6);           // t10 = (yR - yQ) yP zP
                        CopyConstrain(t2, t10);        // t2 = t10
                        auto t11 = MultModP(t3, t7);           // t11 = (xR - xP) yQ zQ
                        CopyConstrain(t3, t11);        // t3 = t11
                        auto t12 = MultModP(t4, t7);           // t12 = (yR - yP) yQ zQ
                        CopyConstrain(t4, t12);        // t4 = t12
                        auto t13 = MultModP(t5, t8);           // t13 = (xP - xQ) ZPQ
                        CopyConstrain(t5, t13);        // t5 = t13

                        // // part 2
                        auto t14 = AddModP(input.yP, input.yQ); // t14 = yP + yQ
                        auto t15 = MultModP(t14, WPQ);          // t15 = (yP + yQ) wPQ = WPQ
                        auto t16 = AddModP(t8, t15);            // t16 = ZPQ + WPQ
                        auto t17 = MultModP(XR, t16);           // t17 = xR(ZPQ + WPQ)
                        CopyConstrain(XR, t17);         // xR = t17
                        auto t18 = MultModP(YR, t16);           // t18 = yR(ZPQ + WPQ)
                        CopyConstrain(YR, t18);         // yR = t18

                        // part 3
                        auto t19 = NegModP(t8);                 // t19 = -ZPQ
                        auto t20 = MultModP(t14, t19);          // t20 = -(yP + yQ) ZPQ
                        auto t21 = AddModP(t14, t20);           // t21 = (yP + yQ)(1 - ZPQ)
                        auto t22 = AddModP(t5, t21);            // t22 = (xP - xQ) + (yP + yQ)(1 - ZPQ)
                        auto t23 = MultModP(input.yP, input.yQ);// t23 = yP * yQ
                        auto t24 = MultModP( t22, t23);         // t24 = yP  yQ (xP - xQ + (yP + yQ)(1 - ZPQ))
                        auto t25 = MultModP(LAMBDA, LAMBDA);    // t25 = lambda * lambda
                        auto t26 = SubModP(XR, t25);            // t26 = xR - lambda^2
                        auto t27 = AddModP(t26, input.xP);      // t27 = xR - lambda^2 + xP
                        auto t28 = AddModP(t27, input.xQ);      // t28 = xR - lambda^2 + xP + xQ
                        auto t29 = AddModP(YR, input.yP);       // t29 = yR + yP
                        auto t30 = MultModP(t3, LAMBDA);        // t30 = (xR - xP) lambda
                        auto t31 = AddModP(t29, t30);           // t31 = yR + yP + (xR - xP)lambda
                        auto t32 = MultModP(t24, t28);          // t32 = yP  yQ (xP - xQ + (yP + yQ)(1 - ZPQ))(xR - lambda^2 + xP + xQ)
                        CopyConstrain(t32, input_zero_vector);  // t32 = 0
                        auto t33 = MultModP(t24, t31);          // t33 = yP  yQ (xP - xQ + (yP + yQ)(1-ZPQ))(yR + yP + (xR - xP)lambda)
                        CopyConstrain(t33, input_zero_vector);  // t33 = 0

                        // part 4
                        auto t34 = MultModP(t5, LAMBDA);        // t34 = (xP - xQ) lambda
                        auto t35 = SubModP(t34, input.yP);      // t35 = (xP - xQ) lambda - yP
                        auto t36 = AddModP(t35, input.yQ);      // t36 = (xP - xQ) lambda - yP + yQ
                        auto t37 = MultModP(t5, t36);           // t37 = (xP - xQ)((xP - xQ) lambda - yP + yQ)
                        CopyConstrain(t37, input_zero_vector);  // t37 = 0
                        auto t38 = MultModP(input.xP, input.xP);      // t38 = xP^2
                        auto t39 = AddModP(t38, t38);           // t39 = 2xP^2
                        auto t40 = AddModP(t38, t39);           // t40 = 3xP^2
                        auto t41 = AddModP(input.yP, input.yP); // t41 = 2yP
                        auto t42 = MultModP(t41, LAMBDA);       // t42 = 2yP lambda
                        auto t43 = SubModP(t42, t40);           // t43 = 2yP lambda - 3xP^2
                        auto t44 = MultModP(t43, t8);           // t44 = (2yP lambda - 3xP^2) ZPQ
                        CopyConstrain(t43, t44);                // t43 = t44

                        for (int i = 0; i < num_chunks; ++i) {
                            xR.push_back(XR[i]);
                            yR.push_back(YR[i]);
                        }
                    }
                };

                template<typename FieldType, GenerationStage stage>
                class pallas_ec_full_add
                    : public ec_full_add<
                          FieldType, stage,
                          crypto3::algebra::curves::pallas::base_field_type> {
                    using Base =
                        ec_full_add<FieldType, stage,
                                    crypto3::algebra::curves::pallas::base_field_type>;

                  public:
                    using Base::Base;
                };

                template<typename FieldType, GenerationStage stage>
                class vesta_ec_full_add
                    : public ec_full_add<
                          FieldType, stage,
                          crypto3::algebra::curves::vesta::base_field_type> {
                    using Base =
                        ec_full_add<FieldType, stage,
                                    crypto3::algebra::curves::vesta::base_field_type>;

                  public:
                    using Base::Base;
                };

                template<typename FieldType, GenerationStage stage>
                class secp_k1_256_ec_full_add
                    : public ec_full_add<
                          FieldType, stage,
                          crypto3::algebra::curves::secp_k1<256>::base_field_type> {
                    using Base = ec_full_add<
                        FieldType, stage,
                        crypto3::algebra::curves::secp_k1<256>::base_field_type>;

                  public:
                    using Base::Base;
                };

            }  // namespace components
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil

#endif  // CRYPTO3_BBF_COMPONENTS_EC_FULL_ADD_ECDSA_HPP
