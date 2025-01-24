//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
// Copyright (c) 2024 Antoine Cyr <antoine.cyr@nil.foundation>
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
// @file Declaration of interfaces for FRI verification array swapping component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BBF_COMPONENTS_EC_DOUBLE_ECDSA_HPP
#define CRYPTO3_BBF_COMPONENTS_EC_DOUBLE_ECDSA_HPP

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
                // For a point Q = (x_Q,y_Q) from an elliptic curve over F[p]
                // computes R = (x_R, y_R) = 2Q (EC doubling)
                // Expects input as k-chunked values with b bits per chunk
                // p' = 2^(kb) - p
                // Input: xQ[0],...,xQ[k-1], yQ[0],...,yQ[k-1], p[0],...,p[k-1],
                // pp[0],...,pp[k-1], 0 (expects zero constant as input) Output:
                // xR[0],...,xR[k-1], yR[0],...,yR[k-1]

                template<typename FieldType>
                struct ec_double_raw_input {
                    using TYPE = typename FieldType::value_type;
                    std::vector<TYPE> xQ;
                    std::vector<TYPE> yQ;
                    std::vector<TYPE> p;
                    std::vector<TYPE> pp;
                    TYPE zero;
                };

                template<typename FieldType, GenerationStage stage,
                    typename NonNativeFieldType>
                class ec_double : public generic_component<FieldType, stage> {
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
                        ec_double_raw_input<FieldType>,
                        std::tuple<>>::type;

                public:
                    std::vector<TYPE> inp_xQ;
                    std::vector<TYPE> inp_yQ;
                    std::vector<TYPE> inp_p;
                    std::vector<TYPE> inp_pp;
                    std::vector<TYPE> res_xR;
                    std::vector<TYPE> res_yR;

                    static table_params get_minimal_requirements(
                        std::size_t num_chunks, std::size_t bit_size_chunk) {
                        std::size_t witness = 4 * num_chunks + 1;
                        constexpr std::size_t public_inputs = 1;
                        constexpr std::size_t constants = 0;
                        // rows = 4096-1 so that lookup table is not too hard to fit and
                        // padding doesn't inflate the table
                        constexpr std::size_t rows = 4095;
                        return { witness, public_inputs, constants, rows };
                    }

                    static std::tuple<std::vector<TYPE>, std::vector<TYPE>,
                        std::vector<TYPE>, std::vector<TYPE>, TYPE>
                        form_input(context_type& context_object, raw_input_type raw_input,
                            std::size_t num_chunks, std::size_t bit_size_chunk) {
                        std::vector<TYPE> input_xQ(num_chunks);
                        std::vector<TYPE> input_yQ(num_chunks);
                        std::vector<TYPE> input_p(num_chunks);
                        std::vector<TYPE> input_pp(num_chunks);
                        TYPE input_zero;

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            for (std::size_t i = 0; i < num_chunks; i++) {
                                input_xQ[i] = raw_input.xQ[i];
                                input_yQ[i] = raw_input.yQ[i];
                                input_p[i] = raw_input.p[i];
                                input_pp[i] = raw_input.pp[i];
                            }
                            input_zero = raw_input.zero;
                        }
                        for (std::size_t i = 0; i < num_chunks; i++) {
                            context_object.allocate(input_xQ[i], 0, i,
                                column_type::public_input);
                            context_object.allocate(input_yQ[i], 0, i + num_chunks,
                                column_type::public_input);
                            context_object.allocate(input_p[i], 0, i + 2 * num_chunks,
                                column_type::public_input);
                            context_object.allocate(input_pp[i], 0, i + 3 * num_chunks,
                                column_type::public_input);
                        }
                        context_object.allocate(input_zero, 0, 4 * num_chunks,
                            column_type::public_input);
                        return std::make_tuple(input_xQ, input_yQ, input_p, input_pp,
                            input_zero);
                    }

                    ec_double(context_type& context_object, std::vector<TYPE> input_xQ,
                        std::vector<TYPE> input_yQ, std::vector<TYPE> input_p,
                        std::vector<TYPE> input_pp, TYPE input_zero,
                        std::size_t num_chunks, std::size_t bit_size_chunk,
                        bool make_links = true)
                        : generic_component<FieldType, stage>(context_object) {
                        using integral_type = typename FieldType::integral_type;
                        using NON_NATIVE_TYPE = typename NonNativeFieldType::value_type;
                        using non_native_integral_type = typename NonNativeFieldType::integral_type;

                        using Choice_Function =
                            typename bbf::components::choice_function<FieldType, stage>;
                        using Range_Check =
                            typename bbf::components::range_check_multi<FieldType, stage>;
                        using Check_Mod_P =
                            typename bbf::components::check_mod_p<FieldType, stage>;
                        using Addition_Mod_P =
                            typename bbf::components::addition_mod_p<FieldType, stage, NonNativeFieldType>;
                        using Negation_Mod_P =
                            typename bbf::components::negation_mod_p<FieldType, stage, NonNativeFieldType>;
                        using Multiplication_Mod_P =
                            typename bbf::components::flexible_multiplication<FieldType,
                            stage, NonNativeFieldType>;

                        std::vector<TYPE> XQ(num_chunks);
                        std::vector<TYPE> YQ(num_chunks);
                        std::vector<TYPE> P(num_chunks);
                        std::vector<TYPE> PP(num_chunks);
                        TYPE ZERO;

                        std::vector<TYPE> LAMBDA(num_chunks);
                        std::vector<TYPE> Z(num_chunks);
                        std::vector<TYPE> XR(num_chunks);
                        std::vector<TYPE> YR(num_chunks);

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            for (std::size_t i = 0; i < num_chunks; ++i) {
                                XQ[i] = input_xQ[i];
                                YQ[i] = input_yQ[i];
                                P[i] = input_p[i];
                                PP[i] = input_pp[i];
                            }
                            ZERO = input_zero;

                            non_native_integral_type pow = 1;
                            NON_NATIVE_TYPE xQ = 0, yQ = 0;

                            for (std::size_t i = 0; i < num_chunks; ++i) {
                                xQ += non_native_integral_type(
                                    integral_type(input_xQ[i].data)) *
                                    pow;
                                yQ += non_native_integral_type(
                                    integral_type(input_yQ[i].data)) *
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
                                non_native_integral_type mask = (non_native_integral_type(1) << bit_size_chunk) - 1;
                                non_native_integral_type x_value = non_native_integral_type(x.data);
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
                            allocate(XQ[i]);
                            allocate(YQ[i]);
                            allocate(P[i]);
                            allocate(PP[i]);

                            allocate(LAMBDA[i]);
                            allocate(Z[i]);
                            allocate(XR[i]);
                            allocate(YR[i]);
                        }
                        allocate(ZERO);

                        auto check_chunked =
                            [&context_object, num_chunks, bit_size_chunk, PP, ZERO](std::vector<TYPE> x) {
                            Range_Check rc = Range_Check(context_object, x,
                                num_chunks, bit_size_chunk);
                            Check_Mod_P cm = Check_Mod_P(context_object, x, PP, ZERO,
                                num_chunks, bit_size_chunk);
                            };

                        // Copy constraint generation lambda expression
                        auto CopyConstrain = [this, num_chunks](std::vector<TYPE> x, std::vector<TYPE> y) {
                            for (std::size_t i = 0; i < num_chunks; i++) {
                                copy_constrain(x[i], y[i]);
                            }
                            };


                        // perform range checks and mod p checks on all stored variables
                        check_chunked(LAMBDA);
                        check_chunked(Z);
                        check_chunked(XR);
                        check_chunked(YR);

                        Multiplication_Mod_P t1 = Multiplication_Mod_P(
                            context_object, YQ, LAMBDA, P, PP, ZERO, num_chunks, bit_size_chunk);  // t1 = yQ * lambda


                        Addition_Mod_P t2 =
                            Addition_Mod_P(context_object, t1.res_z, t1.res_z, P,
                                PP, ZERO, num_chunks, bit_size_chunk);  // t2 = t1 + t1 = 2yQ * lambda
                        Addition_Mod_P t3 = Addition_Mod_P(context_object, XQ, XQ, P, PP,
                            ZERO, num_chunks, bit_size_chunk);  // t3 = xQ + xQ = 2xQ
                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            non_native_integral_type a = 0, b = 0, pow = 1;
                            for (std::size_t i = 0; i < num_chunks; ++i) {
                                a += non_native_integral_type(integral_type(
                                    t1.res_z[i].data)) *
                                    pow;
                                b += non_native_integral_type(integral_type(
                                    t3.res_z[i].data)) *
                                    pow;
                                pow <<= bit_size_chunk;
                            }
                        }
                        Addition_Mod_P t4 =
                            Addition_Mod_P(context_object, XQ, t3.res_z, P, PP,
                                ZERO, num_chunks, bit_size_chunk);  // t4 = xQ + t3 = 3xQ
                        Multiplication_Mod_P t5 = Multiplication_Mod_P(
                            context_object, t4.res_z, XQ, P, PP, ZERO, num_chunks, bit_size_chunk);  // t5 = t4 * xQ = 3xQ^2
                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            non_native_integral_type a = 0, b = 0, pow = 1;
                            for (std::size_t i = 0; i < num_chunks; ++i) {
                                a += non_native_integral_type(
                                    integral_type(t2.res_z[i].data)) *
                                    pow;
                                b += non_native_integral_type(
                                    integral_type(t5.res_z[i].data)) *
                                    pow;
                                pow <<= bit_size_chunk;
                            }
                        }
                        CopyConstrain(t2.res_z, t5.res_z);         // 2yQ * lambda = 3xQ^2
                        Addition_Mod_P t6 =
                            Addition_Mod_P(context_object, XR, t3.res_z, P, PP,
                                ZERO, num_chunks, bit_size_chunk);  // t6 = xR + t3 = xR + 2xQ
                        Multiplication_Mod_P t7 =
                            Multiplication_Mod_P(context_object, LAMBDA, LAMBDA, P,
                                PP, ZERO, num_chunks, bit_size_chunk);       // t7 = lambda * lambda
                        CopyConstrain(t6.res_z, t7.res_z);  // xR + 2xQ = lambda^2
                        Addition_Mod_P t8 = Addition_Mod_P(context_object, YR, YQ, P, PP,
                            ZERO, num_chunks, bit_size_chunk);  // t8 = yR + yQ
                        Negation_Mod_P t9 =
                            Negation_Mod_P(context_object, XR, P, PP, ZERO, num_chunks, bit_size_chunk);  // t9 = -xR
                        Addition_Mod_P t10 =
                            Addition_Mod_P(context_object, XQ, t9.res_z, P, PP,
                                ZERO, num_chunks, bit_size_chunk);  // t10 = xQ + t9 = xQ - xR
                        Multiplication_Mod_P t11 = Multiplication_Mod_P(
                            context_object, LAMBDA, t10.res_z, P,
                            PP, ZERO, num_chunks, bit_size_chunk);  // t11 = lambda * t10 =lambda(xQ-xR)
                        CopyConstrain(t8.res_z, t11.res_z);  // yR + yQ = lambda(xQ - xR)
                        Multiplication_Mod_P t12 =
                            Multiplication_Mod_P(context_object, Z, t1.res_z, P, PP, ZERO,
                                num_chunks, bit_size_chunk);  // t12 = z * t1 = z * yQ * lambda
                        CopyConstrain(LAMBDA, t12.res_z);  // lambda = z yQ lambda

                        if (make_links) {
                            for (std::size_t i = 0; i < num_chunks; ++i) {
                                copy_constrain(XQ[i], input_xQ[i]);
                                copy_constrain(YQ[i], input_yQ[i]);
                                copy_constrain(P[i], input_p[i]);
                                copy_constrain(PP[i], input_pp[i]);
                            }
                            copy_constrain(ZERO, input_zero);
                        }

                        for (int i = 0; i < num_chunks; ++i) {
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

            }  // namespace components
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil

#endif  // CRYPTO3_BBF_COMPONENTS_EC_DOUBLE_ECDSA_HPP
