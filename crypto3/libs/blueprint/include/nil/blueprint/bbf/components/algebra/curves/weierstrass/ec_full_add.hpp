//---------------------------------------------------------------------------//
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
// @file Declaration of interfaces for full addition of EC points over a non-native field
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BBF_COMPONENTS_EC_FULL_ADD_ECDSA_HPP
#define CRYPTO3_BBF_COMPONENTS_EC_FULL_ADD_ECDSA_HPP

#include <functional>
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/bbf/components/algebra/fields/non_native/addition_mod_p.hpp>
#include <nil/blueprint/bbf/components/algebra/fields/non_native/check_mod_p.hpp>
#include <nil/blueprint/bbf/components/algebra/fields/non_native/flexible_multiplication.hpp>
#include <nil/blueprint/bbf/components/algebra/fields/non_native/negation_mod_p.hpp>
#include <nil/blueprint/bbf/components/detail/choice_function.hpp>
#include <nil/blueprint/bbf/components/detail/range_check_multi.hpp>
#include <stdexcept>
#include <variant>

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
                //      yQ[0],...,yQ[k-1], p[0], ..., p[k-1], pp[0], ..., pp[k-1], 0
                // (expects zero constant as input) 
                // Output: xR[0],...,xR[k-1],
                // yR[0],...,yR[k-1]
                //
                template<typename FieldType>
                struct ec_full_add_raw_input {
                    using TYPE = typename FieldType::value_type;
                    std::vector<TYPE> xQ;
                    std::vector<TYPE> yQ;
                    std::vector<TYPE> xP;
                    std::vector<TYPE> yP;
                    std::vector<TYPE> p;
                    std::vector<TYPE> pp;
                    TYPE zero;
                };

                template<typename FieldType, GenerationStage stage,
                         typename NonNativeFieldType>
                class ec_full_add : public generic_component<FieldType, stage> {
                    using generic_component<FieldType, stage>::allocate;
                    using generic_component<FieldType, stage>::copy_constrain;
                    using generic_component<FieldType, stage>::constrain;
                    using generic_component<FieldType, stage>::lookup;
                    using component_type = generic_component<FieldType, stage>;

                  public:
                    using typename generic_component<FieldType, stage>::TYPE;
                    using typename generic_component<FieldType, stage>::context_type;
                    using typename generic_component<FieldType, stage>::table_params;
                    using raw_input_type =
                        typename std::conditional<stage == GenerationStage::ASSIGNMENT,
                                                  ec_full_add_raw_input<FieldType>,
                                                  std::tuple<>>::type;

                  public:
                    std::vector<TYPE> inp_xP;
                    std::vector<TYPE> inp_yP;
                    std::vector<TYPE> inp_xQ;
                    std::vector<TYPE> inp_yQ;
                    std::vector<TYPE> inp_p;
                    std::vector<TYPE> inp_pp;
                    std::vector<TYPE> res_xR;
                    std::vector<TYPE> res_yR;

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

                    ec_full_add(context_type& context_object, std::vector<TYPE> input_xP,
                                std::vector<TYPE> input_yP, std::vector<TYPE> input_xQ,
                                std::vector<TYPE> input_yQ, std::vector<TYPE> input_p,
                                std::vector<TYPE> input_pp, TYPE input_zero,
                                std::size_t num_chunks, std::size_t bit_size_chunk,
                                bool make_links = true)
                        : generic_component<FieldType, stage>(context_object) {
                        using integral_type = typename FieldType::integral_type;
                        using NON_NATIVE_TYPE = typename NonNativeFieldType::value_type;
                        using non_native_integral_type =
                            typename NonNativeFieldType::integral_type;

                        using Choice_Function =
                            typename bbf::components::choice_function<FieldType, stage>;
                        using Range_Check =
                            typename bbf::components::range_check_multi<FieldType, stage>;
                        using Check_Mod_P =
                            typename bbf::components::check_mod_p<FieldType, stage>;
                        using Addition_Mod_P =
                            typename bbf::components::addition_mod_p<FieldType, stage,
                                                                     NonNativeFieldType>;
                        using Negation_Mod_P =
                            typename bbf::components::negation_mod_p<FieldType, stage,
                                                                     NonNativeFieldType>;
                        using Multiplication_Mod_P =
                            typename bbf::components::flexible_multiplication<
                                FieldType, stage, NonNativeFieldType>;

                        std::vector<TYPE> XP(num_chunks);
                        std::vector<TYPE> YP(num_chunks);
                        std::vector<TYPE> XQ(num_chunks);
                        std::vector<TYPE> YQ(num_chunks);
                        std::vector<TYPE> P(num_chunks);
                        std::vector<TYPE> PP(num_chunks);
                        std::vector<TYPE> ZERO(num_chunks);

                        std::vector<TYPE> LAMBDA(num_chunks);
                        std::vector<TYPE> XR(num_chunks);
                        std::vector<TYPE> YR(num_chunks);
                        std::vector<TYPE> ZP(num_chunks);
                        std::vector<TYPE> ZQ(num_chunks);
                        std::vector<TYPE> ZPQ(num_chunks);
                        std::vector<TYPE> WPQ(num_chunks);
                        

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            for (std::size_t i = 0; i < num_chunks; ++i) {
                                XP[i] = input_xP[i];
                                YP[i] = input_yP[i];
                                XQ[i] = input_xQ[i];
                                YQ[i] = input_yQ[i];
                                P[i] = input_p[i];
                                PP[i] = input_pp[i];
                                ZERO[i] = input_zero;
                            }

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
                            ZP = base(zP), ZQ = base(zQ), ZPQ = base(zPQ),
                            WPQ = base(wPQ);
                        }

                        for (std::size_t i = 0; i < num_chunks; ++i) {
                            allocate(XP[i]);
                            allocate(YP[i]);
                            allocate(XQ[i]);
                            allocate(YQ[i]);
                            allocate(P[i]);
                            allocate(PP[i]);
                            allocate(ZERO[i]);

                            allocate(LAMBDA[i]);
                            allocate(XR[i]);
                            allocate(YR[i]);
                            allocate(ZP[i]);
                            allocate(ZQ[i]);
                            allocate(ZPQ[i]);
                            allocate(WPQ[i]);
                        }

                        auto check_chunked = [&context_object, num_chunks, bit_size_chunk,
                                              PP, ZERO](std::vector<TYPE> x) {
                            Range_Check rc = Range_Check(context_object, x, num_chunks,
                                                         bit_size_chunk);
                            Check_Mod_P cm = Check_Mod_P(context_object, x, PP, ZERO[0],
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

                        auto MultModP = [&context_object, P, PP, ZERO, num_chunks,
                                         bit_size_chunk](std::vector<TYPE> x,
                                                         std::vector<TYPE> y) {
                            Multiplication_Mod_P t =
                                Multiplication_Mod_P(context_object, x, y, P, PP, ZERO[0],
                                                     num_chunks, bit_size_chunk);
                            return t.res_r;
                        };
                        auto AddModP = [&context_object, P, PP, ZERO, num_chunks,
                                        bit_size_chunk](std::vector<TYPE> x,
                                                        std::vector<TYPE> y) {
                            Addition_Mod_P t =
                                Addition_Mod_P(context_object, x, y, P, PP, ZERO[0],
                                               num_chunks, bit_size_chunk);
                            return t.res_r;
                        };
                        auto NegModP = [&context_object, P, PP, ZERO, num_chunks,
                                        bit_size_chunk](std::vector<TYPE> x) {
                            Negation_Mod_P t =
                                Negation_Mod_P(context_object, x, P, PP, ZERO[0], num_chunks,
                                               bit_size_chunk);
                            return t.res_r;
                        };

                        // part 1
                        auto t1 = NegModP(XQ);         // t1 = -xQ
                        auto t2 = NegModP(YQ);         // t2 = -yQ
                        auto t3 = NegModP(XP);         // t3 = -xP
                        auto t4 = NegModP(YP);         // t4 = -yP
                        auto t5 = AddModP(XR, t1);     // t5 = xR - xQ
                        auto t6 = AddModP(YR, t2);     // t6 = yR - yQ
                        auto t7 = AddModP(XR, t3);     // t5 = xR - xP
                        auto t8 = AddModP(YR, t4);     // t6 = yR - yP
                        auto t9 = AddModP(XP, t1);     // t9 = xP - xQ
                        auto t10 = MultModP(YP, ZP);   // t10 = yP * zP
                        auto t11 = MultModP(YQ, ZQ);   // t11 = yQ * zQ
                        auto t12 = MultModP(t9, ZPQ);  // t12 = (xP - xQ) zPQ = ZPQ
                        auto t13 = MultModP(t5, t10);  // t13 = (xR - xQ) yP zP
                        CopyConstrain(t5, t13);        // t5 = t13
                        auto t14 = MultModP(t6, t10);  // t14 = (yR - yQ) yP zP
                        CopyConstrain(t6, t14);        // t6 = t14
                        auto t15 = MultModP(t7, t11);  // t15 = (xR - xP) yQ zQ
                        CopyConstrain(t7, t15);        // t7 = t15
                        auto t16 = MultModP(t8, t11);  // t16 = (yR - yP) yQ zQ
                        CopyConstrain(t8, t16);        // t8 = t16
                        auto t17 = MultModP(t9, t12);  // t17 = (xP - xQ) ZPQ
                        CopyConstrain(t9, t17);        // t9 = t17

                        // part 2
                        auto t18 = AddModP(YP, YQ);     // t18 = yP + yQ
                        auto t19 = MultModP(t18, WPQ);  // t19 = (yP + yQ) wPQ = WPQ
                        auto t20 = AddModP(t12, t19);   // t20 = ZPQ + WPQ
                        auto t21 = MultModP(XR, t20);   // t21 = xR(ZPQ + WPQ)
                        CopyConstrain(XR, t21);         // xR = t21
                        auto t22 = MultModP(YR, t20);   // t22 = yR(ZPQ + WPQ)
                        CopyConstrain(YR, t22);         // yR = t22

                        // part 3
                        auto t23 = NegModP(t12);                // t23 = -ZPQ
                        auto t24 = MultModP(t18, t23);          // t24 = -(yP + yQ) ZPQ
                        auto t25 = AddModP(t18, t24);           // t25 = (yP + yQ)(1 - ZPQ)
                        auto t26 = AddModP(t9, t25);            // t26 = (xP - xQ) + (yP + yQ)(1 - ZPQ)
                        auto t27 = MultModP(YP, YQ);            // t27 = yP * yQ
                        auto t28 = MultModP(t26, t27);          // t28 = yP  yQ (xP - xQ + (yP + yQ)(1 - ZPQ))
                        auto t29 = MultModP(LAMBDA, LAMBDA);    // t29 = lambda * lambda
                        auto t30 = NegModP(t29);                // t30 = -lambda^2
                        auto t31 = AddModP(XR, t30);            // t31 = xR - lambda^2
                        auto t32 = AddModP(t31, XP);            // t32 = xR - lambda^2 + xP
                        auto t33 = AddModP(t32, XQ);            // t33 = xR - lambda^2 + xP + xQ
                        auto t34 = AddModP(YR, YP);             // t34 = yR + yP
                        auto t35 = MultModP(t7, LAMBDA);        // t35 = (xR - xP) lambda
                        auto t36 = AddModP(t34, t35);           // t36 = yR + yP + (xR - xP)lambda
                        auto t37 = MultModP(t28, t33);          // t37 = yP  yQ (xP - xQ + (yP + yQ)(1 - ZPQ))(xR - lambda^2 + xP + xQ)
                        CopyConstrain(t37, ZERO);              // t37 = 0
                        auto t38 = MultModP(t28, t36);          // t38 = yP  yQ (xP - xQ + (yP + yQ)(1 -ZPQ))(yR + yP + (xR - xP)lambda)
                        CopyConstrain(t38, ZERO);              // t38 = 0

                        // part 4
                        auto t39 = MultModP(t9, LAMBDA);    // t39 = (xP - xQ) lambda
                        auto t40 = AddModP(t39, t4);        // t40 = (xP - xQ) lambda - yP
                        auto t41 = AddModP(t40, YQ);        // t41 = (xP - xQ) lambda - yP + yQ
                        auto t42 = MultModP(t9, t41);       // t42 = (xP - xQ)((xP - xQ) lambda - yP + yQ)
                        CopyConstrain(t42, ZERO);          // t42 = 0
                        auto t43 = MultModP(XP, t3);        // t43 = -xP^2
                        auto t44 = AddModP(t43, t43);       // t44 = -2xP^2
                        auto t45 = AddModP(t43, t44);       // t45 = -3xP^2
                        auto t46 = AddModP(YP, YP);         // t46 = 2yP
                        auto t47 = MultModP(t46, LAMBDA);   // t47 = 2yP lambda
                        auto t48 = AddModP(t47, t45);       // t48 = 2yP lambda - 3xP^2
                        auto t49 = MultModP(t48, t12);      // t49 = (2yP lambda - 3xP^2) ZPQ
                        CopyConstrain(t48, t49);            // t38 = 0t48 = t49

                        if (make_links) {
                            for (std::size_t i = 0; i < num_chunks; ++i) {
                                copy_constrain(XP[i], input_xP[i]);
                                copy_constrain(YP[i], input_yP[i]);
                                copy_constrain(XQ[i], input_xQ[i]);
                                copy_constrain(YQ[i], input_yQ[i]);
                                copy_constrain(P[i], input_p[i]);
                                copy_constrain(PP[i], input_pp[i]);
                                copy_constrain(ZERO[i], input_zero);
                            }
                        }

                        for (int i = 0; i < num_chunks; ++i) {
                            inp_xP.push_back(input_xP[i]);
                            inp_yP.push_back(input_yP[i]);
                            inp_xQ.push_back(input_xQ[i]);
                            inp_yQ.push_back(input_yQ[i]);
                            inp_pp.push_back(input_p[i]);
                            inp_pp.push_back(input_pp[i]);
                        }
                        for (int i = 0; i < num_chunks; ++i) {
                            res_xR.push_back(XR[i]);
                            res_yR.push_back(YR[i]);
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

            }  // namespace components
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil

#endif  // CRYPTO3_BBF_COMPONENTS_EC_FULL_ADD_ECDSA_HPP
