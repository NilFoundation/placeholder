//---------------------------------------------------------------------------//
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
#pragma once

#include <nil/crypto3/bench/scoped_profiler.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/log_table.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            template<typename FieldType, GenerationStage stage>
            class tx_log : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;

              public:
                using typename generic_component<FieldType, stage>::table_params;
                using typename generic_component<FieldType, stage>::TYPE;

                using LogTable = log_table<FieldType, stage>;
                using KeccakTable = keccak_table<FieldType, stage>;

                struct input_type {
                    TYPE rlc_challenge;

                    LogTable::input_type logs;
                    KeccakTable::private_input_type keccak_buffers;
                };

                using value = typename FieldType::value_type;
                using integral_type = typename FieldType::integral_type;

                static constexpr std::size_t filter_chunks_amount = 256;
                static constexpr std::size_t filter_bit_per_chunk = 8;

                static table_params get_minimal_requirements(
                    std::size_t max_zkevm_rows, std::size_t max_keccak_blocks) {
                    return {.witnesses = LogTable::get_witness_amount() +
                                         KeccakTable::get_witness_amount() + 116 +
                                         2 * filter_bit_per_chunk + filter_chunks_amount +
                                         1,
                            .public_inputs = 1,
                            .constants = 1,
                            .rows = std::max(max_zkevm_rows, max_keccak_blocks)};
                }

                static void allocate_public_inputs(context_type &context,
                                                   input_type &input,
                                                   std::size_t max_zkevm_rows,
                                                   std::size_t max_keccak_blocks) {
                    context.allocate(input.rlc_challenge, 0, 0,
                                     column_type::public_input);
                }

                tx_log(context_type &context_object, const input_type &input,
                       std::size_t max_zkevm_rows, std::size_t max_keccak_blocks)
                    : generic_component<FieldType, stage>(context_object) {
                    std::vector<std::size_t> log_lookup_area;
                    std::vector<std::size_t> keccak_lookup_area;
                    std::size_t current_column = 0;
                    for (std::size_t i = 0; i < LogTable::get_witness_amount(); i++)
                        log_lookup_area.push_back(current_column++);
                    for (std::size_t i = 0; i < KeccakTable::get_witness_amount(); i++)
                        keccak_lookup_area.push_back(current_column++);

                    context_type log_ct =
                        context_object.subcontext(log_lookup_area, 0, max_zkevm_rows);
                    context_type keccak_ct = context_object.subcontext(
                        keccak_lookup_area, 0, max_keccak_blocks);

                    LogTable l_t = LogTable(log_ct, input.logs, max_zkevm_rows);
                    KeccakTable k_t = KeccakTable(
                        keccak_ct, {input.rlc_challenge, input.keccak_buffers},
                        max_keccak_blocks);

                    const std::vector<TYPE> &id = l_t.id;
                    const std::vector<TYPE> &address = l_t.address;
                    const std::vector<TYPE> &log_index = l_t.index;
                    const std::vector<std::vector<TYPE>> &topics = l_t.topics;
                    const std::vector<std::vector<TYPE>> &previous_filter =
                        l_t.previous_filter;
                    const std::vector<std::vector<TYPE>> &current_filter =
                        l_t.current_filter;

                    // Allocated cells
                    std::vector<std::vector<TYPE>> selector(max_zkevm_rows,
                                                            std::vector<TYPE>(5));
                    std::vector<TYPE> is_zero_index(max_zkevm_rows);
                    std::vector<std::vector<TYPE>> hash_hi(max_zkevm_rows,
                                                           std::vector<TYPE>(5));
                    std::vector<std::vector<TYPE>> hash_lo(max_zkevm_rows,
                                                           std::vector<TYPE>(5));

                    std::vector<std::vector<std::vector<TYPE>>> hash_hi_chunks(
                        max_zkevm_rows,
                        std::vector<std::vector<TYPE>>(5, std::vector<TYPE>(8)));

                    std::vector<std::vector<TYPE>> index(max_zkevm_rows,
                                                         std::vector<TYPE>(15));
                    std::vector<std::vector<TYPE>> chunks_remainder(
                        max_zkevm_rows, std::vector<TYPE>(15));
                    std::vector<std::vector<TYPE>> byte_pos(max_zkevm_rows,
                                                            std::vector<TYPE>(15));
                    std::vector<std::vector<TYPE>> bit_pos(max_zkevm_rows,
                                                           std::vector<TYPE>(15));
                    std::vector<std::vector<std::vector<TYPE>>> index_chunk(
                        max_zkevm_rows, std::vector<std::vector<TYPE>>(
                                            15, std::vector<TYPE>(filter_chunks_amount)));

                    std::vector<std::vector<TYPE>> address_index_bit_selector(
                        max_zkevm_rows, std::vector<TYPE>(filter_bit_per_chunk));
                    std::vector<std::vector<TYPE>> transition_chunk_bits(
                        max_zkevm_rows, std::vector<TYPE>(filter_bit_per_chunk));
                    std::vector<TYPE> address_index_selector(max_zkevm_rows);

                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        auto logs = input.logs;
                        std::cout << "LOG trace.size = " << logs.size() << std::endl;
                        auto set_values =
                            [&](std::vector<uint8_t> buffer,
                                std::vector<std::vector<std::vector<TYPE>>>
                                    &hash_hi_chunks,
                                std::vector<std::vector<TYPE>> &index,
                                std::vector<std::vector<TYPE>> &chunks_remainder,
                                std::vector<std::vector<TYPE>> &byte_pos,
                                std::vector<std::vector<TYPE>> &bit_pos,
                                std::vector<std::vector<std::vector<TYPE>>> &index_chunk,
                                size_t row, size_t column) {
                                auto hash = zkevm_keccak_hash(buffer);
                                hash_hi[row][column] = w_hi<FieldType>(hash);
                                hash_lo[row][column] = w_lo<FieldType>(hash);

                                hash_hi_chunks[row][column] =
                                    zkevm_word_to_field_element_flexible<FieldType>(
                                        zkevm_word_type(hash_hi[row][column].data.base()),
                                        8);
                                std::size_t k = 0;
                                for (std::size_t j = column * 3; j < (column + 1) * 3;
                                     j++) {
                                    index[row][j] =
                                    //7-j not good, j is scalling too fast
                                        hash_hi_chunks[row][column][7 - k].data.base() &
                                        0x7FF;
                                    chunks_remainder[row][j] =
                                        (hash_hi_chunks[row][column][7 - k].data.base() >>
                                         11) &
                                        0x1F;
                                    byte_pos[row][j] =
                                        (2047 - index[row][j].data.base()) / 8;
                                    bit_pos[row][j] =
                                        7 - ((2047 - index[row][j].data.base()) % 8);
                                    k++;
                                }
                            };

                        for (std::size_t i = 0; i < logs.size(); i++) {
                            is_zero_index[i] = logs[i].index.is_zero();

                            std::vector<uint8_t> address_buffer(20);
                            for (std::size_t j = 0; j < 20; j++) {
                                address_buffer[19 - j] = uint8_t(
                                    logs[i].address >> (8 * j) & 0xFF);  // Big-endian
                            }

                            set_values(address_buffer, hash_hi_chunks, index,
                                       chunks_remainder, byte_pos, bit_pos, index_chunk,
                                       i, 0);

                            // auto byte_pos = int(address_byte_pos[i][0].data.base());
                            // auto byte_value =
                            //     integral_type(previous_filter[i][byte_pos].data);
                            // auto bit_index = 1 <<
                            // int(address_bit_pos[i][0].data.base());
                            // address_index_selector[i] =
                            //     !(byte_value == (byte_value | bit_index));
                            // for (std::size_t j = 0; j < filter_chunks_amount; j++) {
                            //     address_index_chunk[i][j] =
                            //         (j == address_byte_pos[i][0].data.base())
                            //             ? 1 << int(address_bit_pos[i][0].data.base())
                            //             : 0;
                            // }
                            // Constrain how we got address_index_chunk
                            // auto filter_chunk = byte_value;
                            // for (std::size_t j = 0; j < filter_bit_per_chunk; j++) {
                            //     address_index_bit_selector[i][j] =
                            //         j == address_bit_pos[i][0].data.base() ? 1 : 0;
                            //     transition_chunk_bits[i][j] = filter_chunk % 2;
                            //     filter_chunk /= 2;
                            // }
                            // for (std::size_t j = 0; j < filter_chunks_amount; j++) {
                            //     TYPE temp_chunk = previous_filter[i][j];
                            //     TYPE transition_sum;
                            //     int pow = 1;
                            //     for (std::size_t k = 0; k < 8; k++) {
                            //         temp_chunk -= transition_chunk_bits[i][k] *
                            //                       address_index_bit_selector[i][k] *
                            //                       pow;
                            //         transition_sum += transition_chunk_bits[i][k] *
                            //         pow; pow *= 2;
                            //     }

                            // }
                            selector[i][0] = 1;
                            for (std::size_t j = 0; j < logs[i].topics.size(); j++) {
                                selector[i][j + 1] = 1;
                                std::vector<uint8_t> topics_buffer(32);
                                for (std::size_t k = 0; k < 32; k++) {
                                    topics_buffer[31 - k] =
                                        uint8_t(logs[i].topics[j] >> (8 * j) &
                                                0xFF);  // Big-endian
                                }
                                set_values(topics_buffer, hash_hi_chunks, index,
                                           chunks_remainder, byte_pos, bit_pos,
                                           index_chunk, i, j + 1);
                            }
                        }
                    }

                    for (std::size_t i = 0; i < max_zkevm_rows; i++) {
                        if (i % 20 == 0) std::cout << ".";
                        std::cout.flush();
                        std::size_t cur_column = LogTable::get_witness_amount() +
                                                 KeccakTable::get_witness_amount();
                        allocate(is_zero_index[i], cur_column++, i);

                        for (std::size_t j = 0; j < 5; j++) {
                            allocate(selector[i][j], cur_column++, i);
                        }

                        for (std::size_t j = 0; j < 5; j++) {
                            allocate(hash_hi[i][j], cur_column++, i);
                            allocate(hash_lo[i][j], cur_column++, i);
                            for (std::size_t k = 0; k < 8; k++) {
                                allocate(hash_hi_chunks[i][j][k], cur_column++, i);
                            }
                        }
                        for (std::size_t j = 0; j < 15; j++) {
                            allocate(index[i][j], cur_column++, i);
                            allocate(chunks_remainder[i][j], cur_column++, i);
                            allocate(byte_pos[i][j], cur_column++, i);
                            allocate(bit_pos[i][j], cur_column++, i);
                        }
                    }

                    // for (std::size_t j = 0; j < filter_chunks_amount; j++) {
                    //     allocate(address_index_chunk[i][j], cur_column++, i);
                    // }
                    // for (std::size_t j = 0; j < filter_bit_per_chunk; j++) {
                    //     allocate(address_index_bit_selector[i][j], cur_column++,
                    //     i);
                    // }
                    // for (std::size_t j = 0; j < filter_bit_per_chunk; j++) {
                    //     allocate(transition_chunk_bits[i][j], cur_column++, i);
                    // }
                    // allocate(address_index_selector[i], cur_column++, i);

                    std::cout << std::endl;

                    if constexpr (stage == GenerationStage::CONSTRAINTS) {
                        // first index is 0
                        constrain(log_index[0]);

                        std::vector<TYPE> every_row_constraints;
                        std::vector<TYPE> non_first_row_constraints;
                        std::vector<TYPE> chunked_16_lookups;

                        for (std::size_t j = 0; j < filter_chunks_amount; j++) {
                            constrain(previous_filter[0][j]);
                            // last filter should be the block's filter
                            // constrain on selector
                            non_first_row_constraints.push_back(context_object.relativize(
                                ((previous_filter[1][j] - current_filter[0][j]) *
                                 selector[1][0]),
                                -1));
                        }

                        every_row_constraints.push_back(context_object.relativize(
                            is_zero_index[1] * (is_zero_index[1] - 1), -1));
                        every_row_constraints.push_back(context_object.relativize(
                            is_zero_index[1] * log_index[1], -1));

                        chunked_16_lookups.push_back(
                            context_object.relativize(log_index[1], -1));
                        chunked_16_lookups.push_back(
                            context_object.relativize(id[1], -1));

                        // if index is not 0:
                        //  index = prev_index + 1
                        non_first_row_constraints.push_back(context_object.relativize(
                            log_index[1] * (log_index[1] - log_index[0] - 1), -1));
                        // id = prev_id
                        non_first_row_constraints.push_back(context_object.relativize(
                            log_index[1] * (id[1] - id[0]), -1));

                        // if index is 0:
                        //  id > prev_id
                        chunked_16_lookups.push_back(context_object.relativize(
                            is_zero_index[1] * (id[1] - id[0] - 1), -1));

                        // filter constraints
                        for (std::size_t j = 0; j < 5; j++) {
                            for (std::size_t k = 0; k < 3; k++) {
                                // first constraint failing
                                every_row_constraints.push_back(context_object.relativize(
                                    (hash_hi_chunks[1][j][7 - k] - index[1][3 * j + k] -
                                     chunks_remainder[1][3 * j + k] * 2048) *
                                        selector[1][j],
                                    -1));
                                every_row_constraints.push_back(context_object.relativize(
                                    (2047 - index[1][3 * j + k] -
                                     byte_pos[1][3 * j + k] * 8 + bit_pos[1][3 * j + k] -
                                     7) *
                                        selector[1][j],
                                    -1));
                            }
                        }

                        // for (std::size_t j = 0; j < filter_chunks_amount; j++) {
                        //     every_row_constraints.push_back(context_object.relativize(
                        //         current_filter[1][j] - previous_filter[1][j] -
                        //             address_index_chunk[1][j] *
                        //             address_index_selector[1],
                        //         -1));

                        //     TYPE temp_chunk = previous_filter[1][j];
                        //     // cascading temp_chunk
                        //     // 2nd loop, we add to temp_chunk previous bits
                        //     TYPE transition_sum;
                        //     int pow = 1;
                        //     for (std::size_t k = 0; k < 8; k++) {
                        //         temp_chunk -= transition_chunk_bits[1][k] *
                        //                       address_index_bit_selector[1][k] * pow;
                        //         transition_sum += transition_chunk_bits[1][k] * pow;
                        //         pow *= 2;
                        //     }
                        //     every_row_constraints.push_back(context_object.relativize(
                        //         (1 - address_index_selector[1]) * temp_chunk *
                        //             address_index_chunk[1][j],
                        //         -1));
                        //     // case 1: wrong chunk address_index_chunk
                        //     // is 0 case 2: index is not in filter
                        //     address_index_selector
                        //     // is 1 case 3: index is in filter            temp_chunk is
                        //     0
                        //     every_row_constraints.push_back(context_object.relativize(
                        //         address_index_chunk[1][j] *
                        //             (transition_sum - previous_filter[1][j]),
                        //         -1));  // transition_sum = previous_filter if
                        //                // address_index_chunk
                        // }

                        {
                            PROFILE_SCOPE("Log circuit constraints row definition")
                            std::vector<std::size_t> every_row;
                            std::vector<std::size_t> non_first_row;
                            for (std::size_t i = 0; i < max_zkevm_rows; i++) {
                                every_row.push_back(i);
                                if (i != 0) non_first_row.push_back(i);
                            }
                            for (auto &constraint : every_row_constraints) {
                                context_object.relative_constrain(constraint, 0,
                                                                  max_zkevm_rows - 1);
                            }
                            for (auto &constraint : chunked_16_lookups) {
                                std::vector<TYPE> tmp = {constraint};
                                context_object.relative_lookup(tmp, "chunk_16_bits/full",
                                                               0, max_zkevm_rows - 1);
                            }
                            for (auto &constraint : non_first_row_constraints) {
                                context_object.relative_constrain(constraint, 1,
                                                                  max_zkevm_rows - 1);
                            }
                        }
                    }
                    std::cout << std::endl;
                }
            };
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil
