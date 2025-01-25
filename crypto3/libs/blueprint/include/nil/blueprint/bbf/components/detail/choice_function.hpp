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
// @file Declaration of interfaces for PLONK BBF choice_function component class
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_PLONK_BBF_CHOICE_FUNCTION_COMPONENT_HPP
#define CRYPTO3_BLUEPRINT_PLONK_BBF_CHOICE_FUNCTION_COMPONENT_HPP

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
                struct choice_function_raw_input {
                    using TYPE = typename FieldType::value_type;
                    TYPE q;
                    std::vector<TYPE> x;
                    std::vector<TYPE> y;
                };

                template<typename FieldType, GenerationStage stage>
                class choice_function : public generic_component<FieldType, stage> {
                    using generic_component<FieldType, stage>::allocate;
                    using generic_component<FieldType, stage>::copy_constrain;
                    using generic_component<FieldType, stage>::constrain;

                  public:
                    using typename generic_component<FieldType, stage>::TYPE;
                    using typename generic_component<FieldType, stage>::context_type;
                    using typename generic_component<FieldType, stage>::table_params;
                    using raw_input_type =
                        typename std::conditional<stage == GenerationStage::ASSIGNMENT,
                                                  choice_function_raw_input<FieldType>,
                                                  std::tuple<>>::type;

                  public:
                    TYPE inp_q;
                    std::vector<TYPE> inp_x, inp_y, res_r;

                    static table_params get_minimal_requirements(std::size_t num_chunks) {
                        std::size_t witness = num_chunks + 1;
                        constexpr std::size_t public_inputs = 1;
                        constexpr std::size_t constants = 0;
                        std::size_t rows = 3 * num_chunks + 1;
                        return {witness, public_inputs, constants, rows};
                    }

                    static std::tuple<TYPE, std::vector<TYPE>, std::vector<TYPE>>
                    form_input(context_type &context_object, raw_input_type raw_input,
                               std::size_t num_chunks) {
                        TYPE input_q;
                        std::vector<TYPE> input_x(num_chunks);
                        std::vector<TYPE> input_y(num_chunks);
                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            for (std::size_t i = 0; i < num_chunks; ++i) {
                                input_q = raw_input.q;
                                input_x[i] = raw_input.x[i];
                                input_y[i] = raw_input.y[i];
                            }
                        }
                        context_object.allocate(input_q, 0, 0, column_type::public_input);
                        for (std::size_t i = 0; i < num_chunks; ++i) {
                            context_object.allocate(input_x[i], 0, i + 1,
                                                    column_type::public_input);
                            context_object.allocate(input_y[i], 0, i + num_chunks + 1,
                                                    column_type::public_input);
                        }
                        return std::make_tuple(input_q, input_x, input_y);
                    }

                    choice_function(context_type &context_object, TYPE input_q,
                                    std::vector<TYPE> input_x, std::vector<TYPE> input_y,
                                    std::size_t num_chunks, bool make_links = true)
                        : generic_component<FieldType, stage>(context_object) {
                        TYPE Q, X[num_chunks], Y[num_chunks], Z[num_chunks];

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            Q = input_q;
                            for (std::size_t i = 0; i < num_chunks; i++) {
                                X[i] = input_x[i];
                                Y[i] = input_y[i];
                            }
                        }

                        allocate(Q);
                        constrain(Q * (1 - Q));
                        for (std::size_t i = 0; i < num_chunks; i++) {
                            allocate(X[i]);
                            allocate(Y[i]);
                            Z[i] = (1 - Q) * X[i] + Q * Y[i];
                            allocate(Z[i]);
                        }

                        if (make_links) {
                            copy_constrain(Q, input_q);
                            for (std::size_t i = 0; i < num_chunks; i++) {
                                copy_constrain(X[i], input_x[i]);
                                copy_constrain(Y[i], input_y[i]);
                            }
                        }

                        inp_q = input_q;
                        for (std::size_t i = 0; i < num_chunks; i++) {
                            inp_x.push_back(X[i]);
                            inp_y.push_back(Y[i]);
                            res_r.push_back(Z[i]);
                        }
                    };
                };
            }  // namespace components
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil

#endif  // CRYPTO3_BLUEPRINT_PLONK_BBF_CHOICE_FUNCTION_COMPONENT_HPP
