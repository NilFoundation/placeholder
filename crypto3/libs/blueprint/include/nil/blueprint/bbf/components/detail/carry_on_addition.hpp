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
// @file Declaration of interfaces for PLONK component wrapping the BBF-component
// interface
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BBF_COMPONENTS_CARRY_ON_ADDITION_HPP
#define CRYPTO3_BBF_COMPONENTS_CARRY_ON_ADDITION_HPP

#include <functional>
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            namespace components {

                template<typename FieldType>
                struct carry_on_addition_raw_input {
                    using TYPE = typename FieldType::value_type;
                    std::vector<TYPE> x;
                    std::vector<TYPE> y;
                };

                template<typename FieldType, GenerationStage stage>
                class carry_on_addition : public generic_component<FieldType, stage> {
                    using generic_component<FieldType, stage>::allocate;
                    using generic_component<FieldType, stage>::copy_constrain;
                    using generic_component<FieldType, stage>::constrain;
                    using generic_component<FieldType, stage>::lookup;

                  public:
                    using typename generic_component<FieldType, stage>::TYPE;
                    using typename generic_component<FieldType, stage>::context_type;
                    using typename generic_component<FieldType, stage>::table_params;
                    using raw_input_type =
                        typename std::conditional<stage == GenerationStage::ASSIGNMENT,
                                                  carry_on_addition_raw_input<FieldType>,
                                                  std::tuple<>>::type;

                  public:
                    std::vector<TYPE> r;
                    TYPE c;

                    static table_params get_minimal_requirements(
                        std::size_t num_chunks, std::size_t bit_size_chunk) {
                        std::size_t witness = 2;
                        constexpr std::size_t public_inputs = 1;
                        constexpr std::size_t constants = 0;
                        std::size_t rows = 3 * num_chunks + 1;
                        return {witness, public_inputs, constants, rows};
                    }

                    static std::tuple<std::vector<TYPE>, std::vector<TYPE>> form_input(
                        context_type &context_object, raw_input_type raw_input,
                        std::size_t num_chunks, std::size_t bit_size_chunk) {
                        std::vector<TYPE> input_x(num_chunks);
                        std::vector<TYPE> input_y(num_chunks);
                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            for (std::size_t i = 0; i < num_chunks; ++i) {
                                input_x[i] = raw_input.x[i];
                                input_y[i] = raw_input.y[i];
                            }
                        }
                        for (std::size_t i = 0; i < num_chunks; ++i) {
                            context_object.allocate(input_x[i], 0, i,
                                                    column_type::public_input);
                            context_object.allocate(input_y[i], 0, i + num_chunks,
                                                    column_type::public_input);
                        }
                        return std::make_tuple(input_x, input_y);
                    }

                    carry_on_addition(context_type &context_object,
                                      std::vector<TYPE> input_x,
                                      std::vector<TYPE> input_y, std::size_t num_chunks,
                                      std::size_t bit_size_chunk, bool make_links = true)
                        : generic_component<FieldType, stage>(context_object) {
                        using integral_type = typename FieldType::integral_type;

                        TYPE X[num_chunks], Y[num_chunks], C[num_chunks], R[num_chunks];
                        integral_type BASE = integral_type(1) << bit_size_chunk;

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            for (std::size_t i = 0; i < num_chunks; i++) {
                                X[i] = input_x[i];
                                Y[i] = input_y[i];
                            }
                        }

                        for (std::size_t i = 0; i < num_chunks; i++) {
                            allocate(X[i]);
                            allocate(Y[i]);
                            if (make_links) {
                                copy_constrain(X[i], input_x[i]);
                                copy_constrain(Y[i], input_y[i]);
                            }
                            R[i] = X[i] + Y[i];
                            if (i > 0) {
                                R[i] += C[i - 1];
                            }
                            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                                C[i] = (R[i] >= BASE);
                            }
                            allocate(C[i]);
                            constrain(C[i] * (1 - C[i]));

                            R[i] -= TYPE(BASE) * C[i];
                            allocate(R[i]);
                        }

                        for (int i = 0; i < num_chunks; ++i) {
                            r.push_back(R[i]);
                        }
                        c = C[num_chunks - 1];
                    }
                };

            }  // namespace components
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil

#endif  // CRYPTO3_BBF_COMPONENTS_CARRY_ON_ADDITION_HPP
