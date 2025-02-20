//---------------------------------------------------------------------------//
// Copyright (c) 2023 Alexey Yashunsky <a.yashunsky@nil.foundation>
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
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
// @file Declaration of interfaces for FRI verification array swapping component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_BBF_COMPONENTS_HASHES_POSEIDON_PLONK_HPP
#define CRYPTO3_BLUEPRINT_BBF_COMPONENTS_HASHES_POSEIDON_PLONK_HPP

#include <functional>
#include <nil/blueprint/bbf/components/hashes/poseidon/plonk/poseidon_constants.hpp>
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            namespace components {
                template<typename FieldType, GenerationStage stage>
                class flexible_poseidon : public generic_component<FieldType, stage> {
                    using generic_component<FieldType, stage>::allocate;
                    using generic_component<FieldType, stage>::copy_constrain;
                    using generic_component<FieldType, stage>::constrain;

                    using component_type = generic_component<FieldType, stage>;
                    constexpr static const std::size_t total_rounds_amount =
                        nil::blueprint::bbf::components::detail::poseidon_constants<
                            FieldType>::total_rounds_amount;
                    constexpr static const std::size_t full_rounds_amount =
                        nil::blueprint::bbf::components::detail::poseidon_constants<
                            FieldType>::full_rounds_amount;
                    constexpr static const std::size_t partial_rounds_amount =
                        nil::blueprint::bbf::components::detail::poseidon_constants<
                            FieldType>::partial_rounds_amount;
                    constexpr static const std::size_t state_size =
                        nil::blueprint::bbf::components::detail::poseidon_constants<
                            FieldType>::state_size;
                    constexpr static const std::size_t sbox_alpha =
                        nil::blueprint::bbf::components::detail::poseidon_constants<
                            FieldType>::sbox_alpha;
                    constexpr static const std::size_t pasta_version =
                        nil::blueprint::bbf::components::detail::poseidon_constants<
                            FieldType>::pasta_version;

                    constexpr static const std::array<
                        std::array<typename FieldType::value_type, state_size>, state_size>
                        mds = nil::blueprint::bbf::components::detail::poseidon_constants<
                            FieldType>::mds;
                    constexpr static const std::array<
                        std::array<typename FieldType::value_type, state_size>, total_rounds_amount>
                        round_constant =
                            nil::blueprint::bbf::components::detail::poseidon_constants<
                                FieldType>::round_constant;

                  public:
                    using typename generic_component<FieldType, stage>::TYPE;
                    using typename generic_component<FieldType, stage>::context_type;
                    using typename generic_component<FieldType,stage>::table_params;

                    struct input_type {
                        std::vector<TYPE> state;
                    };
/*
                  public:
                    static nil::crypto3::zk::snark::plonk_table_description<FieldType>
                    get_table_description(std::size_t witness) {
                        constexpr std::size_t total_cells = (total_rounds_amount + 2) * state_size;
                        constexpr std::size_t public_inputs = 1;
                        constexpr std::size_t constants = 0;
                        std::size_t selectors = (total_cells + witness - 1) / witness;
                        nil::crypto3::zk::snark::plonk_table_description<FieldType> desc(
                            witness, public_inputs, constants, selectors);
                        desc.usable_rows_amount = selectors;
                        return desc;
                    }
*/
                  public:
                    TYPE input[state_size];
                    TYPE res[state_size];

                    static table_params get_minimal_requirements() {
                        constexpr std::size_t witness = 10;
                        constexpr std::size_t total_cells = (total_rounds_amount + 2) * state_size;
                        constexpr std::size_t public_inputs = 1;
                        constexpr std::size_t constants = 0;
                        std::size_t rows = (total_cells + witness - 1) / witness;
                        return {witness, public_inputs, constants, rows};
                    }

                    static void allocate_public_inputs(
                            context_type& ctx, input_type& input) {
                       if constexpr (stage == GenerationStage::ASSIGNMENT) {
                          assert(input.state.size() == state_size);
                       } else {
                          input.state.resize(state_size);
                       }

                       for (std::size_t i = 0; i < state_size; i++) {
                           ctx.allocate(input.state[i], 0, i,
                                        column_type::public_input);
                       }
                    }

                    flexible_poseidon(context_type &context_object,
                                      const input_type &input,
                                      bool make_links = true)
                        : generic_component<FieldType, stage>(context_object) {
                        TYPE X[total_rounds_amount + 1][state_size];
//                        TYPE W[(total_rounds_amount + 1) * state_size];

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            X[0][0] = input.state[0];
                            X[0][1] = input.state[1];
                            X[0][2] = input.state[2];
                        }

                        allocate(X[0][0]);
                        allocate(X[0][1]);
                        allocate(X[0][2]);
/*
                        allocate(input.state[0]);
                        allocate(input.state[1]);
                        allocate(input.state[2]);
*/
                        if (make_links) {
                            copy_constrain(X[0][0], input.state[0]);
                            copy_constrain(X[0][1], input.state[1]);
                            copy_constrain(X[0][2], input.state[2]);
                        }

                        static_assert(state_size == 3);

                        // Pasta version
                        if (pasta_version) {
                            // First full rounds
                            for (std::size_t i = 0; i < full_rounds_amount / 2; i++) {
                                for (std::size_t j = 0; j < state_size; j++) {
                                    X[i + 1][j] = X[i][0].pow(sbox_alpha) * mds[j][0] +
                                                  X[i][1].pow(sbox_alpha) * mds[j][1] +
                                                  X[i][2].pow(sbox_alpha) * mds[j][2] +
                                                  round_constant[i][j];
                                    allocate(X[i + 1][j]);
                                }
                            }

                            // Middle partial rounds
                            for (std::size_t i = full_rounds_amount / 2;
                                 i < partial_rounds_amount + full_rounds_amount / 2; i++) {
                                for (std::size_t j = 0; j < state_size; j++) {
                                    X[i + 1][j] = X[i][0].pow(sbox_alpha) * mds[j][0] +
                                                  X[i][1] * mds[j][1] + X[i][2] * mds[j][2] +
                                                  round_constant[i][j];
                                    allocate(X[i + 1][j]);
                                }
                            }

                            // Last full rounds
                            for (std::size_t i = partial_rounds_amount + full_rounds_amount / 2;
                                 i < total_rounds_amount; i++) {
                                for (std::size_t j = 0; j < state_size; j++) {
                                    X[i + 1][j] = X[i][0].pow(sbox_alpha) * mds[j][0] +
                                                  X[i][1].pow(sbox_alpha) * mds[j][1] +
                                                  X[i][2].pow(sbox_alpha) * mds[j][2] +
                                                  round_constant[i][j];
                                    allocate(X[i + 1][j]);
                                }
                            }
                        } else {
                            // Version with original constants
                            // First full rounds
                            for (std::size_t i = 0; i < full_rounds_amount / 2; i++) {
                                for (std::size_t j = 0; j < state_size; j++) {
                                    X[i + 1][j] = (X[i][0] + round_constant[i][0]).pow(sbox_alpha) *
                                                      mds[j][0] +
                                                  (X[i][1] + round_constant[i][1]).pow(sbox_alpha) *
                                                      mds[j][1] +
                                                  (X[i][2] + round_constant[i][2]).pow(sbox_alpha) *
                                                      mds[j][2];
                                    allocate(X[i + 1][j]);
                                }
                            }
                            // Middle partial rounds
                            for (std::size_t i = full_rounds_amount / 2;
                                 i < partial_rounds_amount + full_rounds_amount / 2; i++) {
                                for (std::size_t j = 0; j < state_size; j++) {
                                    X[i + 1][j] = (X[i][0] + round_constant[i][0]).pow(sbox_alpha) *
                                                      mds[j][0] +
                                                  (X[i][1] + round_constant[i][1]) * mds[j][1] +
                                                  (X[i][2] + round_constant[i][2]) * mds[j][2];
                                    allocate(X[i + 1][j]);
                                }
                            }
                            // Final full rounds
                            for (std::size_t i = partial_rounds_amount + full_rounds_amount / 2;
                                 i < total_rounds_amount; i++) {
                                for (std::size_t j = 0; j < state_size; j++) {
                                    X[i + 1][j] = (X[i][0] + round_constant[i][0]).pow(sbox_alpha) *
                                                      mds[j][0] +
                                                  (X[i][1] + round_constant[i][1]).pow(sbox_alpha) *
                                                      mds[j][1] +
                                                  (X[i][2] + round_constant[i][2]).pow(sbox_alpha) *
                                                      mds[j][2];
                                    allocate(X[i + 1][j]);
                                }
                            }
                        }
                        this->input[0] = X[0][0];
                        this->input[1] = X[0][1];
                        this->input[2] = X[0][2];
                        res[0] = X[total_rounds_amount][0];
                        res[1] = X[total_rounds_amount][1];
                        res[2] = X[total_rounds_amount][2];
                    }
                };

            }  // namespace components
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil

#endif  // CRYPTO3_BLUEPRINT_BBF_COMPONENTS_HASHES_POSEIDON_PLONK_HPP
