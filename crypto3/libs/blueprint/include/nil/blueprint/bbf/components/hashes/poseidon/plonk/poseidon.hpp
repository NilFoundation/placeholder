//---------------------------------------------------------------------------//
// Copyright (c) 2023 Alexey Yashunsky <a.yashunsky@nil.foundation>
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

namespace nil {
    namespace blueprint {
        namespace bbf {
            namespace components {

                template<typename FieldType, GenerationStage stage>
                class flexible_poseidon : public generic_component<FieldType, stage> {
                    using typename generic_component<FieldType, stage>::context_type;
                    using generic_component<FieldType, stage>::allocate;
                    using generic_component<FieldType, stage>::copy_constrain;
                    using generic_component<FieldType, stage>::constrain;

                    using component_type = generic_component<FieldType, stage>;

                    constexpr static const std::uint32_t state_size = 3;
                    constexpr static const std::uint32_t rounds_amount = 55;
                    constexpr static const std::size_t sbox_alpha = 7;
                    constexpr static const std::array<
                        std::array<typename FieldType::value_type, state_size>, state_size>
                        mds = detail::poseidon_constants<FieldType, state_size, rounds_amount>::mds;
                    constexpr static const std::array<
                        std::array<typename FieldType::value_type, state_size>, rounds_amount>
                        round_constant = detail::poseidon_constants<FieldType, state_size,
                                                                    rounds_amount>::round_constant;

                  public:
                    using typename generic_component<FieldType, stage>::TYPE;

                  public:
                    TYPE input[state_size];
                    TYPE res[state_size];

                    flexible_poseidon(context_type &context_object,
                                      std::array<TYPE, state_size> input_state,
                                      bool make_links = true)
                        : generic_component<FieldType, stage>(context_object) {
                        TYPE X[rounds_amount + 1][state_size];
                        TYPE W[(rounds_amount + 1) * state_size];

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            X[0][0] = input_state[0];
                            X[0][1] = input_state[1];
                            X[0][2] = input_state[2];
                        }

                        if (make_links) {
                            copy_constrain(X[0][0], input_state[0]);
                            copy_constrain(X[0][1], input_state[1]);
                            copy_constrain(X[0][2], input_state[2]);
                        }

                        W[0] = X[0][0];
                        W[1] = X[0][1];
                        W[2] = X[0][2];

                        allocate(W[0]);
                        allocate(W[1]);
                        allocate(W[2]);

                        static_assert(state_size == 3);
                        for (std::size_t i = 0; i < rounds_amount; i++) {
                            for (std::size_t j = 0; j < state_size; j++) {
                                X[i + 1][j] = X[i][0].pow(sbox_alpha) * mds[j][0] +
                                              X[i][1].pow(sbox_alpha) * mds[j][1] +
                                              X[i][2].pow(sbox_alpha) * mds[j][2] +
                                              round_constant[i][j];
                                W[(i + 1) * 3 + j] = X[i + 1][j];
                                allocate(W[(i + 1) * 3 + j]);
                            }
                        }
                        input[0] = X[0][0];
                        input[1] = X[0][1];
                        input[2] = X[0][2];
                        res[0] = X[rounds_amount][0];
                        res[1] = X[rounds_amount][1];
                        res[2] = X[rounds_amount][2];
                    }
                };

            }  // namespace components
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil

#endif  // CRYPTO3_BLUEPRINT_BBF_COMPONENTS_HASHES_POSEIDON_PLONK_HPP
