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

                static constexpr std::size_t filter_chunks_amount = 128;
                static constexpr std::size_t filter_bit_per_chunk = 16;
                constexpr static const value two_16 = 65536;

                static table_params get_minimal_requirements(
                    std::size_t max_log_rows, std::size_t max_keccak_blocks) {
                    return {.witnesses = LogTable::get_witness_amount() +
                                         KeccakTable::get_witness_amount() + 21 +
                                         filter_chunks_amount + 2 * filter_bit_per_chunk,
                            .public_inputs = 1,
                            .constants = 1,
                            .rows = std::max(max_log_rows, max_keccak_blocks)};
                }

                static void allocate_public_inputs(context_type &context,
                                                   input_type &input,
                                                   std::size_t max_log_rows,
                                                   std::size_t max_keccak_blocks) {
                    context.allocate(input.rlc_challenge, 0, 0,
                                     column_type::public_input);
                }

                tx_log(context_type &context_object, const input_type &input,
                       std::size_t max_log_rows, std::size_t max_keccak_blocks)
                    : generic_component<FieldType, stage>(context_object) {
                    std::vector<std::size_t> log_lookup_area;
                    std::vector<std::size_t> keccak_lookup_area;
                    std::size_t current_column = 0;
                    for (std::size_t i = 0; i < LogTable::get_witness_amount(); i++)
                        log_lookup_area.push_back(current_column++);
                    for (std::size_t i = 0; i < KeccakTable::get_witness_amount(); i++)
                        keccak_lookup_area.push_back(current_column++);

                    context_type log_ct =
                        context_object.subcontext(log_lookup_area, 0, max_log_rows);
                    context_type keccak_ct = context_object.subcontext(
                        keccak_lookup_area, 0, max_keccak_blocks);

                    LogTable l_t = LogTable(log_ct, input.logs, max_log_rows);
                    KeccakTable k_t = KeccakTable(
                        keccak_ct, {input.rlc_challenge, input.keccak_buffers},
                        max_keccak_blocks);

                    const std::vector<TYPE> &id = l_t.id;
                    const std::vector<TYPE> &log_index = l_t.log_index;
                    const std::vector<TYPE> &value = l_t.value;
                    const std::vector<TYPE> &type = l_t.type;
                    const std::vector<TYPE> &indice = l_t.indice;
                    const std::vector<TYPE> &is_last = l_t.is_last;
                    const std::vector<std::vector<TYPE>> &previous_filter =
                        l_t.previous_filter;
                    const std::vector<std::vector<TYPE>> &current_filter =
                        l_t.current_filter;

                    // Allocated cells
                    std::vector<TYPE> selector(max_log_rows);
                    std::vector<TYPE> is_zero_index(max_log_rows);
                    std::vector<TYPE> is_zero_type(max_log_rows);
                    std::vector<TYPE> is_zero_indice(max_log_rows);
                    std::vector<TYPE> indice_is_2(max_log_rows);
                    std::vector<TYPE> hash_hi(max_log_rows);
                    std::vector<TYPE> hash_lo(max_log_rows);

                    std::vector<std::vector<TYPE>> hash_hi_chunks(max_log_rows,
                                                                  std::vector<TYPE>(8));
                    std::vector<TYPE> indice_chunk(max_log_rows);
                    std::vector<TYPE> index(max_log_rows);
                    std::vector<TYPE> index_selector(max_log_rows);
                    std::vector<TYPE> chunks_remainder(max_log_rows);
                    std::vector<TYPE> byte_pos(max_log_rows);
                    std::vector<TYPE> bit_pos(max_log_rows);

                    std::vector<std::vector<TYPE>> index_chunk(
                        max_log_rows, std::vector<TYPE>(filter_chunks_amount));
                    std::vector<std::vector<TYPE>> index_bit_selector(
                        max_log_rows, std::vector<TYPE>(filter_bit_per_chunk));
                    std::vector<std::vector<TYPE>> transition_chunk_bits(
                        max_log_rows, std::vector<TYPE>(filter_bit_per_chunk));

                    // need to add lookup for has value
                    // make sure each allocated value is constrained
                    // make sure transition constraints make sense
                    // add log row variable instead of copying it
                    

                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        for (std::size_t i = 0; i < max_log_rows; i++) {
                            if (value[i].is_zero()) {
                                break;
                            }
                            selector[i] = 1;
                            is_zero_index[i] = log_index[i].is_zero();
                            is_zero_indice[i] = indice[i].is_zero();
                            is_zero_type[i] = type[i].is_zero();
                            indice_is_2[i] = indice[i] == 2;

                            auto buf_number = type[i] == 0 ? 20 : 32;

                            std::vector<uint8_t> buffer(buf_number);
                            for (std::size_t j = 0; j < buf_number; j++) {
                                buffer[19 - j] =
                                    uint8_t(value[i].to_integral() >> (8 * j) &
                                            0xFF);  // Big-endian
                            }

                            auto hash = zkevm_keccak_hash(buffer);
                            hash_hi[i] = w_hi<FieldType>(hash);
                            hash_lo[i] = w_lo<FieldType>(hash);

                            hash_hi_chunks[i] =
                                zkevm_word_to_field_element_flexible<FieldType>(
                                    zkevm_word_type(hash_hi[i].to_integral()), 8);
                            index[i] = hash_hi_chunks[i][7 - int(indice[i].to_integral())]
                                           .to_integral() &
                                       0x7FF;
                            chunks_remainder[i] =
                                (hash_hi_chunks[i][7 - int(indice[i].to_integral())]
                                     .to_integral() >>
                                 11) &
                                0x1F;
                            byte_pos[i] =
                                (2047 - index[i].to_integral()) / filter_bit_per_chunk;
                            bit_pos[i] = 15 - ((2047 - index[i].to_integral()) %
                                               filter_bit_per_chunk);
                            indice_chunk[i] =
                                hash_hi_chunks[i][7 - int(indice[i].to_integral())];

                            for (std::size_t j = 0; j < filter_chunks_amount; j++) {
                                auto new_chunk = previous_filter[i][j];

                                index_chunk[i][j] =
                                    (j == byte_pos[i].to_integral())
                                        ? 1 << int(bit_pos[i].to_integral())
                                        : 0;
                                if (index_chunk[i][j] != 0) {
                                    auto bit_index = 1 << int(bit_pos[i].to_integral());
                                    index_selector[i] =
                                        !(new_chunk ==
                                          (new_chunk.to_integral() | bit_index));
                                    auto temp_chunk = new_chunk.to_integral();

                                    // why inside the j loop?
                                    // we assign the value too many times
                                    for (std::size_t k = 0; k < filter_bit_per_chunk;
                                         k++) {
                                        index_bit_selector[i][k] =
                                            k == bit_pos[i].to_integral() ? 0 : 1;
                                        transition_chunk_bits[i][k] = temp_chunk % 2;
                                        temp_chunk /= 2;
                                    }
                                }
                            }

                            if (i != 0) {
                                // std::cout << "is_last:" << is_last[i - 1] << std::endl;
                                // std::cout << "is_zero_type:" << is_zero_type[i]
                                //           << std::endl;
                                // std::cout << "type: " << type[i] << std::endl;
                                // std::cout << "constrain: "
                                //           << is_last[i - 1] * (1 - is_zero_type[i])
                                //           << std::endl;
                            }
                        }
                    }

                    for (std::size_t i = 0; i < max_log_rows; i++) {
                        if (i % 20 == 0) std::cout << ".";
                        std::cout.flush();
                        std::size_t cur_column = LogTable::get_witness_amount() +
                                                 KeccakTable::get_witness_amount();
                        allocate(is_zero_index[i], cur_column++, i);
                        allocate(is_zero_indice[i], cur_column++, i);
                        allocate(is_zero_type[i], cur_column++, i);
                        allocate(selector[i], cur_column++, i);
                        allocate(index_selector[i], cur_column++, i);
                        allocate(indice_is_2[i], cur_column++, i);

                        allocate(hash_hi[i], cur_column++, i);
                        allocate(hash_lo[i], cur_column++, i);
                        for (std::size_t k = 0; k < 8; k++) {
                            allocate(hash_hi_chunks[i][k], cur_column++, i);
                        }
                        allocate(indice_chunk[i], cur_column++, i);
                        allocate(index[i], cur_column++, i);
                        allocate(chunks_remainder[i], cur_column++, i);
                        allocate(byte_pos[i], cur_column++, i);
                        allocate(bit_pos[i], cur_column++, i);

                        for (std::size_t k = 0; k < filter_chunks_amount; k++) {
                            allocate(index_chunk[i][k], cur_column++, i);
                        }

                        for (std::size_t k = 0; k < filter_bit_per_chunk; k++) {
                            allocate(index_bit_selector[i][k], cur_column++, i);
                            allocate(transition_chunk_bits[i][k], cur_column++, i);
                        }
                    }

                    std::cout << std::endl;

                    if constexpr (stage == GenerationStage::CONSTRAINTS) {
                        // first index is 0
                        constrain(log_index[0]);
                        std::vector<TYPE> every_row_constraints;
                        std::vector<TYPE> non_first_row_constraints;
                        std::vector<TYPE> chunked_16_lookups;
                        std::vector<TYPE> non_first_row_lookups;

                        const std::vector<TYPE> &id = l_t.id;
                        const std::vector<TYPE> &log_index = l_t.log_index;
                        const std::vector<TYPE> &value = l_t.value;
                        const std::vector<TYPE> &type = l_t.type;
                        const std::vector<TYPE> &indice = l_t.indice;
                        const std::vector<TYPE> &is_last = l_t.is_last;

                        // CONSTRAINS FOR ORDER

                        for (std::size_t j = 0; j < filter_chunks_amount; j++) {
                            constrain(previous_filter[0][j]);  // First filter is empty
                            non_first_row_constraints.push_back(context_object.relativize(
                                (previous_filter[1][j] - current_filter[0][j]) *
                                    selector[1],
                                -1));  // Previous_filter = current_filer of previous row
                        }

                        every_row_constraints.push_back(context_object.relativize(
                            is_zero_index[1] * (is_zero_index[1] - 1), -1));
                        every_row_constraints.push_back(context_object.relativize(
                            is_zero_indice[1] * (is_zero_indice[1] - 1), -1));
                        every_row_constraints.push_back(context_object.relativize(
                            is_zero_type[1] * (is_zero_type[1] - 1), -1));
                        every_row_constraints.push_back(context_object.relativize(
                            is_zero_index[1] * log_index[1], -1));
                        every_row_constraints.push_back(
                            context_object.relativize(is_zero_type[1] * type[1], -1));
                        every_row_constraints.push_back(
                            context_object.relativize(is_zero_indice[1] * indice[1], -1));
                        every_row_constraints.push_back(
                            context_object.relativize(is_last[1] * (is_last[1] - 1), -1));

                        chunked_16_lookups.push_back(
                            context_object.relativize(log_index[1], -1));
                        chunked_16_lookups.push_back(
                            context_object.relativize(id[1], -1));

                        chunked_16_lookups.push_back(
                            context_object.relativize(type[1], -1));
                        chunked_16_lookups.push_back(
                            context_object.relativize(indice[1], -1));
                        chunked_16_lookups.push_back(context_object.relativize(
                            type[1] + two_16 - 5, -1));  // 0 to 4
                        chunked_16_lookups.push_back(context_object.relativize(
                            indice[1] + two_16 - 3, -1));  // 0 to 2

                        constrain(type[0]);    // first type is address
                        constrain(indice[0]);  // first indice is 0
                        constrain(is_last[0]);

                        // indice is increasing by 1 if indice is not 0
                        non_first_row_constraints.push_back(context_object.relativize(
                            (indice[1] - indice[0] - 1) * indice[1], -1));
                        // if indice is 0, last indice is 2
                        non_first_row_constraints.push_back(context_object.relativize(
                            (indice[0] - 2) * is_zero_indice[1], -1));
                        // type is the same if indice is not 0
                        non_first_row_constraints.push_back(context_object.relativize(
                            (type[1] - type[0]) * indice[1], -1));
                        // type is increasing by 1 if last indice is 2 and not last
                        non_first_row_constraints.push_back(context_object.relativize(
                            (type[1] - type[0] - 1) * indice_is_2[0] * (1 - is_last[0]),
                            -1));
                        // if is_last and indice 2, next_type is 0
                        non_first_row_constraints.push_back(context_object.relativize(
                            is_last[0] * indice_is_2[0] * type[1], -1));

                        every_row_constraints.push_back(context_object.relativize(
                            indice_is_2[1] * (indice[1] - 2), -1));
                        every_row_constraints.push_back(context_object.relativize(
                            (indice_is_2[1] - 1) * (indice[1] - 1) * indice[1], -1));

                        // if not last
                        // id = prev_id
                        non_first_row_constraints.push_back(context_object.relativize(
                            (1 - is_last[0]) * (id[1] - id[0]), -1));

                        // if last and next log_index is 0
                        //  id > prev_id
                        non_first_row_lookups.push_back(context_object.relativize(
                            is_last[0] * (id[1] - id[0] - 1) * (1 - log_index[1]) *
                                selector[1],
                            -1));

                        // if is_last next type and indice are 0
                        non_first_row_constraints.push_back(
                            context_object.relativize(is_last[0] * type[1], -1));
                        non_first_row_constraints.push_back(
                            context_object.relativize(is_last[0] * indice[1], -1));

                        // CONSTRAINS FOR FILTER TRANSITION

                        every_row_constraints.push_back(context_object.relativize(
                            (indice_chunk[1] - index[1] - chunks_remainder[1] * 2048) *
                                selector[1],
                            -1));
                        every_row_constraints.push_back(context_object.relativize(
                            (2047 - index[1] - byte_pos[1] * filter_bit_per_chunk +
                             bit_pos[1] - 15) *
                                selector[1],
                            -1));

                        for (std::size_t j = 0; j < filter_chunks_amount; j++) {
                            auto new_chunk = previous_filter[1][j];

                            auto old_chunk = new_chunk;

                            new_chunk += index_chunk[1][j] * index_selector[1];

                            TYPE transition_sum;
                            int pow = 1;
                            auto temp_chunk = old_chunk;
                            for (std::size_t k = 0; k < filter_bit_per_chunk; k++) {
                                temp_chunk -= transition_chunk_bits[1][k] *
                                              index_bit_selector[1][k] * pow;
                                transition_sum += transition_chunk_bits[1][k] * pow;
                                pow *= 2;
                            }

                            every_row_constraints.push_back(context_object.relativize(
                                (1 - index_selector[1]) *
                                    (temp_chunk - index_chunk[1][j]) * index_chunk[1][j],
                                -1));

                            every_row_constraints.push_back(context_object.relativize(
                                index_chunk[1][j] * (transition_sum - old_chunk),
                                -1));  // transition_sum = old_chunk if
                                       // address_index_chunk

                            // every_row_constraints.push_back(context_object.relativize(
                            //     current_filter[1][j] - new_chunk, -1));
                        }

                        {
                            PROFILE_SCOPE("Log circuit constraints row definition")
                            std::vector<std::size_t> every_row;
                            std::vector<std::size_t> non_first_row;
                            for (std::size_t i = 0; i < max_log_rows; i++) {
                                every_row.push_back(i);
                                if (i != 0) non_first_row.push_back(i);
                            }
                            for (auto &constraint : every_row_constraints) {
                                context_object.relative_constrain(constraint, 0,
                                                                  max_log_rows - 1);
                            }
                            for (auto &constraint : chunked_16_lookups) {
                                std::vector<TYPE> tmp = {constraint};
                                context_object.relative_lookup(tmp, "chunk_16_bits/full",
                                                               0, max_log_rows - 1);
                            }
                            for (auto &constraint : non_first_row_lookups) {
                                std::vector<TYPE> tmp = {constraint};
                                context_object.relative_lookup(tmp, "chunk_16_bits/full",
                                                               1, max_log_rows - 1);
                            }
                            for (auto &constraint : non_first_row_constraints) {
                                context_object.relative_constrain(constraint, 1,
                                                                  max_log_rows - 1);
                            }
                        }
                    }
                    std::cout << std::endl;
                }
            };
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil
