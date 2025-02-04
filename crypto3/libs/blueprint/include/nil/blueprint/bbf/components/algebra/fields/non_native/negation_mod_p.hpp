//---------------------------------------------------------------------------//
// Copyright (c) 2024 Georgios Fotiadis <gfotiadis@nil.foundation>
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
// @file Declaration of interfaces for negation function on mod p.
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

namespace nil {
    namespace blueprint {
        namespace bbf {
            namespace components {
                // Parameters: num_chunks = k, bit_size_chunk = b
                // Finding the negative r of integer x, modulo p and checking that x + r = 0 mod p 
                // Input: x[0], ..., x[k-1], p[0], ..., p[k-1], pp[0], ..., pp[k-1], 0[0], ..., 0[k-1] 
                // (expects zero vector constant as input) 
                // Output: r[0], ..., r[k-1]

                template<typename FieldType>
                struct negation_mod_p_raw_input {
                    using TYPE = typename FieldType::value_type;
                    std::vector<TYPE> x;
                    std::vector<TYPE> p;
                    std::vector<TYPE> pp;
                    std::vector<TYPE> zero;
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

                  public:
                    std::vector<TYPE> r;

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
                                      std::vector<TYPE>, std::vector<TYPE>>
                    form_input(context_type &context_object, raw_input_type raw_input,
                               std::size_t num_chunks, std::size_t bit_size_chunk) {
                        std::vector<TYPE> input_x(num_chunks);
                        std::vector<TYPE> input_p(num_chunks);
                        std::vector<TYPE> input_pp(num_chunks);
                        std::vector<TYPE> input_zero(num_chunks);

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            for (std::size_t i = 0; i < num_chunks; i++) {
                                input_x[i] = raw_input.x[i];
                                input_p[i] = raw_input.p[i];
                                input_pp[i] = raw_input.pp[i];
                                input_zero[i] = raw_input.zero[i];
                            }
                        }

                        for (std::size_t i = 0; i < num_chunks; i++) {
                            context_object.allocate(input_x[i], 0, i,
                                                    column_type::public_input);
                            context_object.allocate(input_p[i], 0, i + 1 * num_chunks,
                                                    column_type::public_input);
                            context_object.allocate(input_pp[i], 0, i + 2 * num_chunks,
                                                    column_type::public_input);
                            context_object.allocate(input_zero[i], 0, i + 3 * num_chunks,
                                                    column_type::public_input);
                        }

                        return std::make_tuple(input_x, input_p, input_pp, input_zero);
                    }

                    negation_mod_p(context_type &context_object,
                                   std::vector<TYPE> input_x, std::vector<TYPE> input_p,
                                   std::vector<TYPE> input_pp,
                                   std::vector<TYPE> input_zero, std::size_t num_chunks,
                                   std::size_t bit_size_chunk, bool make_links = true)
                        : generic_component<FieldType, stage>(context_object) {
                        using integral_type = typename FieldType::integral_type;
                        using extended_integral_type =
                            nil::crypto3::multiprecision::big_uint<
                                2 * NonNativeFieldType::modulus_bits>;

                        using Carry_On_Addition =
                            typename bbf::components::carry_on_addition<FieldType, stage>;
                        using Choice_Function =
                            typename bbf::components::choice_function<FieldType, stage>;
                        using Check_Mod_P =
                            typename bbf::components::check_mod_p<FieldType, stage>;
                        using Range_Check =
                            typename bbf::components::range_check_multi<FieldType, stage>;

                        std::vector<TYPE> R(num_chunks);
                        TYPE Q;

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            extended_integral_type x = 0, r = 0, p = 0, pow = 1;

                            // Populate x, p
                            for (std::size_t i = 0; i < num_chunks; ++i) {
                                x += extended_integral_type(
                                         integral_type(input_x[i].data)) *
                                     pow;
                                p += extended_integral_type(
                                         integral_type(input_p[i].data)) *
                                     pow;
                                pow <<= bit_size_chunk;
                            }
                            Q = (x == 0) ? 0 : 1;
                            r = (x == 0) ? 0 : p - x;  // if x = 0, then r = 0

                            extended_integral_type mask =
                                (extended_integral_type(1) << bit_size_chunk) - 1;
                            for (std::size_t i = 0; i < num_chunks; ++i) {
                                R[i] = TYPE(r & mask);
                                r >>= bit_size_chunk;
                            }
                        }
                        allocate(Q);
                        for (std::size_t i = 0; i < num_chunks; ++i) {
                            allocate(R[i]);
                        }

                        Choice_Function cf = Choice_Function(
                            context_object, Q, input_zero, input_p, num_chunks);

                        Carry_On_Addition ca = Carry_On_Addition(
                            context_object, input_x, R, num_chunks, bit_size_chunk);

                        // x + r = 0 or p
                        for (std::size_t i = 0; i < num_chunks; i++) {
                            copy_constrain(ca.r[i], cf.r[i]);
                        }
                        copy_constrain(ca.c, input_zero[0]);

                        Range_Check rc =
                            Range_Check(context_object, R, num_chunks, bit_size_chunk);

                        Check_Mod_P cm =
                            Check_Mod_P(context_object, R, input_pp, input_zero[0],
                                        num_chunks, bit_size_chunk);

                        for (int i = 0; i < num_chunks; ++i) {
                            r.push_back(R[i]);
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
