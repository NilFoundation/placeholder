//---------------------------------------------------------------------------//
// Copyright (c) 2024 Georgios Fotiadis <gfotiadis@nil.foundation>
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

#ifndef CRYPTO3_BBF_COMPONENTS_NEGATION_MOD_P_HPP
#define CRYPTO3_BBF_COMPONENTS_NEGATION_MOD_P_HPP

#include <functional>
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/bbf/components/algebra/fields/non_native/check_mod_p.hpp>
#include <nil/blueprint/bbf/components/detail/carry_on_addition.hpp>
#include <nil/blueprint/bbf/components/detail/choice_function.hpp>
#include <nil/blueprint/bbf/components/detail/range_check_multi.hpp>
#include <stdexcept>
#include <variant>

namespace nil {
    namespace blueprint {
        namespace bbf {
            namespace components {
                // Parameters: num_chunks = k, bit_size_chunk = b
                // Finding the negative y of integer x, modulo p and checking that x + y = 0 mod p 
                // Input: x[0], ..., x[k-1], p[0], ..., p[k-1], pp[0], ..., pp[k-1], 0 (expects zero constant as input) 
                // Output: y[0], ..., y[k-1]

                template<typename FieldType>
                struct negation_mod_p_raw_input {
                    using TYPE = typename FieldType::value_type;
                    std::vector<TYPE> x;
                    std::vector<TYPE> p;
                    std::vector<TYPE> pp;
                    TYPE zero;
                };

                template<typename FieldType, GenerationStage stage,
                         typename NonNativeFieldType>
                class negation_mod_p : public generic_component<FieldType, stage> {
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
                                                  negation_mod_p_raw_input<FieldType>,
                                                  std::tuple<>>::type;
                    using NonNativeIntegralExtendedVariant =
                        std::variant<nil::crypto3::multiprecision::big_uint<
                                         2 * crypto3::algebra::curves::pallas::
                                                 base_field_type::modulus_bits>,
                                     nil::crypto3::multiprecision::big_uint<
                                         2 * crypto3::algebra::curves::vesta::
                                                 base_field_type::modulus_bits>>;

                    template<typename T>
                    struct NonNativeFieldTypeIndex;

                    template<>
                    struct NonNativeFieldTypeIndex<
                        crypto3::algebra::curves::pallas::base_field_type> {
                        static constexpr std::size_t value = 0;
                    };

                    template<>
                    struct NonNativeFieldTypeIndex<
                        crypto3::algebra::curves::vesta::base_field_type> {
                        static constexpr std::size_t value = 1;
                    };

                  public:
                    std::vector<TYPE> inp_x;
                    std::vector<TYPE> inp_p;
                    std::vector<TYPE> inp_pp;
                    std::vector<TYPE> res;

                    static table_params get_minimal_requirements(
                        std::size_t num_chunks, std::size_t bit_size_chunk) {
                        std::size_t witness = 3 * num_chunks + 1;
                        constexpr std::size_t public_inputs = 1;
                        constexpr std::size_t constants = 0;
                        // rows = 4096-1 so that lookup table is not too hard to fit and
                        // padding doesn't inflate the table
                        constexpr std::size_t rows = 4095;
                        return {witness, public_inputs, constants, rows};
                    }

                    static std::tuple<std::vector<TYPE>, std::vector<TYPE>,
                                      std::vector<TYPE>, TYPE>
                    form_input(context_type &context_object, raw_input_type raw_input,
                               std::size_t num_chunks, std::size_t bit_size_chunk) {
                        std::vector<TYPE> input_x(num_chunks);
                        std::vector<TYPE> input_p(num_chunks);
                        std::vector<TYPE> input_pp(num_chunks);
                        TYPE input_zero;

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            for (std::size_t i = 0; i < num_chunks; i++) {
                                input_x[i] = raw_input.x[i];
                                input_p[i] = raw_input.p[i];
                                input_pp[i] = raw_input.pp[i];
                            }
                            input_zero = raw_input.zero;
                        }
                        for (std::size_t i = 0; i < num_chunks; i++) {
                            context_object.allocate(input_x[i], 0, i,
                                                    column_type::public_input);
                            context_object.allocate(input_p[i], 0, i + 1 * num_chunks,
                                                    column_type::public_input);
                            context_object.allocate(input_pp[i], 0, i + 2 * num_chunks,
                                                    column_type::public_input);
                        }
                        context_object.allocate(input_zero, 0, 3 * num_chunks,
                                                column_type::public_input);
                        return std::make_tuple(input_x, input_p, input_pp, input_zero);
                    }

                    negation_mod_p(context_type &context_object,
                                   std::vector<TYPE> input_x, std::vector<TYPE> input_p,
                                   std::vector<TYPE> input_pp, TYPE input_zero,
                                   std::size_t num_chunks, std::size_t bit_size_chunk,
                                   bool make_links = true)
                        : generic_component<FieldType, stage>(context_object) {
                        using integral_type = typename FieldType::integral_type;
                        using extended_integral_type =
                            typename std::variant_alternative_t<
                                NonNativeFieldTypeIndex<NonNativeFieldType>::value,
                                NonNativeIntegralExtendedVariant>;

                        using Carry_On_Addition =
                            typename bbf::components::carry_on_addition<FieldType, stage>;
                        using Choice_Function =
                            typename bbf::components::choice_function<FieldType, stage>;
                        using Check_Mod_P =
                            typename bbf::components::check_mod_p<FieldType, stage>;
                        using Range_Check =
                            typename bbf::components::range_check_multi<FieldType, stage>;

                        std::vector<TYPE> X(num_chunks);
                        std::vector<TYPE> Y(num_chunks);
                        std::vector<TYPE> P(num_chunks);
                        std::vector<TYPE> PP(num_chunks);
                        std::vector<TYPE> ZERO(num_chunks);
                        TYPE Q;

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            for (std::size_t i = 0; i < num_chunks; ++i) {
                                X[i] = input_x[i];
                                P[i] = input_p[i];
                                PP[i] = input_pp[i];
                                ZERO[i] = input_zero;
                            }

                            extended_integral_type x = 0, y = 0, p = 0, pow = 1;

                            // Populate x, p
                            for (std::size_t i = 0; i < num_chunks; ++i) {
                                x += extended_integral_type(integral_type(X[i].data)) *
                                     pow;
                                p += extended_integral_type(integral_type(P[i].data)) *
                                     pow;
                                pow <<= bit_size_chunk;
                            }
                            Q = (x == 0) ? 0 : 1;
                            y = (x == 0) ? 0 : p - x;  // if x = 0, then y = 0

                            extended_integral_type mask =
                                (extended_integral_type(1) << bit_size_chunk) - 1;
                            for (std::size_t i = 0; i < num_chunks; ++i) {
                                Y[i] = TYPE(y & mask);
                                y >>= bit_size_chunk;
                            }
                        }

                        for (std::size_t i = 0; i < num_chunks; ++i) {
                            allocate(X[i]);
                            allocate(Y[i]);
                            allocate(P[i]);
                            allocate(PP[i]);
                            allocate(ZERO[i]);
                        }
                        allocate(Q);

                        Choice_Function cf =
                            Choice_Function(context_object, Q, ZERO, P, num_chunks);

                        Carry_On_Addition ca = Carry_On_Addition(
                            context_object, X, Y, num_chunks, bit_size_chunk);

                        // x + y = 0 or p
                        for (std::size_t i = 0; i < num_chunks; i++) {
                            copy_constrain(ca.res_z[i], cf.res_z[i]);
                        }
                        copy_constrain(ca.res_c, ZERO[0]);

                        Range_Check rc =
                            Range_Check(context_object, Y, num_chunks, bit_size_chunk);

                        Check_Mod_P cm = Check_Mod_P(context_object, Y, PP, ZERO[0],
                                                     num_chunks, bit_size_chunk);

                        if (make_links) {
                            for (std::size_t i = 0; i < num_chunks; ++i) {
                                copy_constrain(X[i], input_x[i]);
                                copy_constrain(P[i], input_p[i]);
                                copy_constrain(PP[i], input_pp[i]);
                                copy_constrain(ZERO[i], input_zero);
                            }
                        }

                        for (int i = 0; i < num_chunks; ++i) {
                            inp_x.push_back(input_x[i]);
                            inp_p.push_back(input_p[i]);
                            inp_pp.push_back(input_pp[i]);
                        }
                        for (int i = 0; i < num_chunks; ++i) {
                            res.push_back(Y[i]);
                        }
                    }
                };

                template<typename FieldType, GenerationStage stage>
                class pallas_negation_mod_p
                    : public negation_mod_p<
                          FieldType, stage,
                          crypto3::algebra::curves::pallas::base_field_type> {
                    using Base =
                        negation_mod_p<FieldType, stage,
                                       crypto3::algebra::curves::pallas::base_field_type>;

                  public:
                    using Base::Base;
                };

                template<typename FieldType, GenerationStage stage>
                class vesta_negation_mod_p
                    : public negation_mod_p<
                          FieldType, stage,
                          crypto3::algebra::curves::vesta::base_field_type> {
                    using Base =
                        negation_mod_p<FieldType, stage,
                                       crypto3::algebra::curves::vesta::base_field_type>;

                  public:
                    using Base::Base;
                };

            }  // namespace components
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil

#endif  // CRYPTO3_BBF_COMPONENTS_NEGATION_MOD_P_HPP
