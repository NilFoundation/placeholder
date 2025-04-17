//---------------------------------------------------------------------------//
// Copyright (c) 2025 Dmitrii Tabalin <dtabalin@nil.foundation>
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

#pragma once

#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/bbf/components/hashes/keccak/keccak_round.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {

            template<typename FieldType, GenerationStage stage>
            class keccak_round_bench : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;

              public:
                using typename generic_component<FieldType, stage>::TYPE;
                using typename generic_component<FieldType, stage>::table_params;
                using value_type = typename FieldType::value_type;
                using integral_type = typename FieldType::integral_type;
                using keccak_round_instance = keccak_round<FieldType, stage>;

                struct input_type {
                    std::vector<std::array<TYPE, 25>> inner_state;
                    std::vector<std::array<TYPE, 17>> padded_message_chunk;
                };

                static constexpr value_type calculate_sparse(const integral_type &value) {
                    integral_type result = 0;
                    integral_type power = 1;
                    integral_type val = value;
                    while (val > 0) {
                        result += (val & 1) * power;
                        power <<= 3;
                        val >>= 1;
                    }
                    return value_type(result);
                }

                static constexpr std::array<value_type, 24> round_constants = {
                    calculate_sparse(1),
                    calculate_sparse(0x8082),
                    calculate_sparse(0x800000000000808a),
                    calculate_sparse(0x8000000080008000),
                    calculate_sparse(0x808b),
                    calculate_sparse(0x80000001),
                    calculate_sparse(0x8000000080008081),
                    calculate_sparse(0x8000000000008009),
                    calculate_sparse(0x8a),
                    calculate_sparse(0x88),
                    calculate_sparse(0x80008009),
                    calculate_sparse(0x8000000a),
                    calculate_sparse(0x8000808b),
                    calculate_sparse(0x800000000000008b),
                    calculate_sparse(0x8000000000008089),
                    calculate_sparse(0x8000000000008003),
                    calculate_sparse(0x8000000000008002),
                    calculate_sparse(0x8000000000000080),
                    calculate_sparse(0x800a),
                    calculate_sparse(0x800000008000000a),
                    calculate_sparse(0x8000000080008081),
                    calculate_sparse(0x8000000000008080),
                    calculate_sparse(0x80000001),
                    calculate_sparse(0x8000000080008008)
                };

                static table_params get_minimal_requirements(
                    const std::size_t expansion_factor,
                    const std::size_t blocks
                ) {
                    const std::size_t witness = 15 * expansion_factor;
                    const std::size_t public_inputs = 1;
                    const std::size_t constants = 1;
                    const std::size_t rows = std::max<std::size_t>((291 + 23 * 257) * blocks + 24, 72000);
                    return {witness, public_inputs, constants, rows};
                }

                static void allocate_public_inputs(
                    context_type &context_object, input_type &input,
                    const std::size_t expansion_factor, const std::size_t blocks
                ) {
                    if (input.inner_state.size() == 0) {
                        // we are called from generate_constraints with empty input
                        // mod the input to correct the sizes
                        input.inner_state.resize(expansion_factor);
                        input.padded_message_chunk.resize(expansion_factor);
                    } else {
                        check_input_size(expansion_factor, input);
                    }
                    std::size_t row = 0;
                    for (std::size_t lane = 0; lane < expansion_factor; lane++) {
                        for (auto &state : input.inner_state[lane]) {
                            context_object.allocate(
                                state, 0, row, column_type::public_input
                            );
                            row++;
                        }
                        for (auto &chunk : input.padded_message_chunk[lane]) {
                            context_object.allocate(
                                chunk, 0, row, column_type::public_input
                            );
                            row++;
                        }
                    }
                }

                static std::vector<std::size_t> get_columns_for_lane(const std::size_t lane) {
                    std::vector<std::size_t> columns = {
                        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14
                    };
                    std::transform(columns.begin(), columns.end(), columns.begin(), [lane](std::size_t i) {
                        return i + 15 * lane;
                    });
                    return columns;
                }

                static void check_input_size(const std::size_t expansion_factor, const input_type &input) {
                    if (input.inner_state.size() != expansion_factor) {
                        throw std::invalid_argument("inner_state size must be equal to expansion factor");
                    }
                    if (input.padded_message_chunk.size() != expansion_factor) {
                        throw std::invalid_argument("padded_message_chunk size must be equal to expansion factor");
                    }
                }

                keccak_round_bench(
                    context_type &context_object, input_type input,
                    const std::size_t expansion_factor, const std::size_t blocks
                ) : generic_component<FieldType, stage>(context_object)
                {
                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        check_input_size(expansion_factor, input);
                    }
                    const std::size_t avg_fill_len = blocks / expansion_factor;
                    const std::size_t rem_fill_len = blocks % expansion_factor;
                    std::size_t start_row = 0;
                    // skip the first few rows to allocate the round constants
                    std::array<TYPE, 24> round_constants_array;
                    for (std::size_t i = 0; i < round_constants.size(); i++) {
                        round_constants_array[i] = round_constants[i];
                        allocate(round_constants_array[i], 0, start_row, column_type::constant);
                        start_row++;
                    }
                    for (std::size_t lane = 0; lane < expansion_factor; lane++) {
                        const auto columns = get_columns_for_lane(lane);
                        const std::size_t blocks_to_fill =
                            lane == 0 ? (avg_fill_len + rem_fill_len) : avg_fill_len;
                        std::size_t row = start_row;
                        auto cur_state = input.inner_state[lane];
                        auto cur_message = input.padded_message_chunk[lane];
                        for (std::size_t block = 0; block < blocks_to_fill; block++) {
                            for (std::size_t permutation = 0; permutation < 2; permutation++) {
                                // simulate the worst-case scenario for performance
                                // (out of those i could implement quickly)
                                const bool should_xor_with_message = permutation == 0;
                                const bool make_links = block != 0;
                                const std::size_t row_offset = should_xor_with_message ? 291 : 257;
                                context_type ct = context_object.subcontext(
                                    columns, row, row + row_offset
                                );
                                const typename keccak_round_instance::input_type round_input(
                                    cur_state, cur_message, round_constants_array[permutation]
                                );
                                keccak_round_instance keccak_round_instance(
                                    ct, round_input, should_xor_with_message, make_links
                                );
                                for (std::size_t i = 0; i < cur_state.size(); i++) {
                                    cur_state[i] = keccak_round_instance.inner_state[i];
                                }
                                row += row_offset;
                            }
                        }
                    }
                };
            };
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil
