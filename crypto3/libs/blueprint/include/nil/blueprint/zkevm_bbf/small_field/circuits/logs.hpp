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

#include <nil/blueprint/bbf/components/hashes/keccak/util.hpp>
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/subcomponents/rw_8.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/tables/keccak.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/tables/log.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/tables/log_filter.hpp>

namespace nil::blueprint::bbf::zkevm_small_field {
    template<typename FieldType, GenerationStage stage>
    class logs : public generic_component<FieldType, stage> {
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
        using LogFilterTable = log_filter_table<FieldType, stage>;
        using KeccakTable = zkevm_small_field::keccak_table<FieldType, stage>;
        using RWTable = rw_8<FieldType, stage>;
        using rw_tables_input_type =
            typename std::conditional<stage == GenerationStage::ASSIGNMENT,
                                      short_rw_operations_vector, std::nullptr_t>::type;

        struct input_type {
            TYPE rlc_challenge;

            LogTable::input_type filter_indices;
            KeccakTable::private_input_type keccak_buffers;
            rw_tables_input_type rw_trace;
        };

        using value = typename FieldType::value_type;
        using integral_type = typename FieldType::integral_type;

        static constexpr std::size_t filter_chunks_amount = 128;
        static constexpr std::size_t filter_bit_per_chunk = 16;
        static constexpr std::size_t buffer_size = 32;
        constexpr static const value two_16 = 65536;
        std::size_t max_filter_indices;
        std::size_t max_keccak_blocks;

        static table_params get_minimal_requirements(std::size_t max_filter_indices,
                                                     std::size_t max_keccak_blocks,
                                                     std::size_t max_rw_size,
                                                     std::size_t instances_rw_8) {
            return {
                .witnesses = LogTable::get_witness_amount() +
                             LogFilterTable::get_witness_amount() +
                             KeccakTable::get_witness_amount() +
                             RWTable::get_witness_amount() + 21 + filter_chunks_amount +
                             2 * filter_bit_per_chunk + buffer_size,
                .public_inputs = 1,
                .constants = 1,
                .rows = std::max({max_filter_indices + max_keccak_blocks + max_rw_size})};
        }

        static void allocate_public_inputs(context_type &context, input_type &input,
                                           std::size_t max_filter_indices,
                                           std::size_t max_keccak_blocks,
                                           std::size_t max_rw_size,
                                           std::size_t instances_rw_8) {
            context.allocate(input.rlc_challenge, 0, 0, column_type::public_input);
        }

        logs(context_type &context_object, const input_type &input,
             std::size_t max_filter_indices, std::size_t max_keccak_blocks,
             std::size_t max_rw_size, std::size_t instances_rw_8)
            : generic_component<FieldType, stage>(context_object) {
            std::vector<std::size_t> log_lookup_area;
            std::vector<std::size_t> log_filter_lookup_area;
            std::vector<std::size_t> keccak_lookup_area;
            std::vector<std::size_t> rw_lookup_area;

            std::size_t current_column = 0;

            for (std::size_t i = 0; i < LogTable::get_witness_amount(); i++)
                log_lookup_area.push_back(current_column++);
            for (std::size_t i = 0; i < LogFilterTable::get_witness_amount(); i++)
                log_filter_lookup_area.push_back(current_column++);
            for (std::size_t i = 0; i < KeccakTable::get_witness_amount(); i++)
                keccak_lookup_area.push_back(current_column++);
            for (std::size_t i = 0; i < RWTable::get_witness_amount(); i++)
                rw_lookup_area.push_back(current_column++);

            context_type log_ct =
                context_object.subcontext(log_lookup_area, 0, max_filter_indices);
            context_type log_ft_ct =
                context_object.subcontext(log_filter_lookup_area, 0, max_filter_indices);
            context_type keccak_ct =
                context_object.subcontext(keccak_lookup_area, 0, max_keccak_blocks);
            context_type rw_ct =
                context_object.subcontext(rw_lookup_area, 0, max_rw_size);

            LogTable l_t = LogTable(log_ct, input.filter_indices, max_filter_indices);
            LogFilterTable l_ft =
                LogFilterTable(log_ft_ct, input.filter_indices, max_filter_indices);
            KeccakTable keccak_t(keccak_ct, {input.rlc_challenge, input.keccak_buffers},
                                 max_keccak_blocks);
            RWTable r_t = RWTable(rw_ct, input.rw_trace, max_rw_size, instances_rw_8);

            const std::vector<TYPE> &selector = l_ft.selector;
            const std::vector<TYPE> &block_id = l_ft.block_id;
            const std::vector<TYPE> &tx_id = l_ft.tx_id;
            const std::vector<TYPE> &log_index = l_ft.log_index;
            const std::vector<std::vector<TYPE>> &value = l_ft.value;
            const std::vector<TYPE> &type = l_ft.type;
            const std::vector<TYPE> &indice_0 = l_ft.indice_0;
            const std::vector<TYPE> &indice_1 = l_ft.indice_1;
            const std::vector<TYPE> &indice_2 = l_ft.indice_2;
            const std::vector<TYPE> &is_last = l_ft.is_last;
            const std::vector<TYPE> &is_block = l_ft.is_block;
            const std::vector<TYPE> &is_block_const = l_ft.is_block_const;
            const std::vector<TYPE> &is_final = l_ft.is_final;
            const std::vector<TYPE> &rw_id = l_ft.rw_id;
            const std::vector<std::vector<TYPE>> &hash = l_ft.hash;
            const std::vector<std::vector<TYPE>> &buffer = l_ft.buffer;
            const std::vector<std::vector<TYPE>> &current_filter = l_ft.current_filter;

            // Allocated cells
            // tx_id is different
            std::vector<TYPE> tx_id_diff(max_filter_indices);
            std::vector<TYPE> tx_id_diff_and_not_block(max_filter_indices);
            // block_id is different
            std::vector<TYPE> block_diff(max_filter_indices);
            // Hash chunk corresponding to the indice
            std::vector<TYPE> indice_chunk(max_filter_indices);
            // Low 11 bits of the indice chunk
            // This is the value applied to the previous filter
            std::vector<TYPE> index(max_filter_indices);
            // 1 if the index was not in the previous filter
            std::vector<TYPE> index_selector(max_filter_indices);
            // Hi 5 bits of the indice chunk
            std::vector<TYPE> indice_remainder(max_filter_indices);
            // Chunk position of the index
            std::vector<TYPE> chunk_pos(max_filter_indices);
            // Bit position of the index
            std::vector<TYPE> bit_pos(max_filter_indices);
            // 0 for every chunk except the chunk at chunk_pos
            // chunk = bit at chunk_pos
            std::vector<std::vector<TYPE>> bit_chunk(
                max_filter_indices, std::vector<TYPE>(filter_chunks_amount));
            // 1 for every position except at bit_pos
            std::vector<std::vector<TYPE>> bit_selector_inv(
                max_filter_indices, std::vector<TYPE>(filter_bit_per_chunk));
            // Previous filter chunk corresponding to the bit_chunk
            std::vector<std::vector<TYPE>> transition_chunk_bits(
                max_filter_indices, std::vector<TYPE>(filter_bit_per_chunk));
            // For keccak
            std::vector<std::vector<TYPE>> value_rlc(max_filter_indices,
                                                     std::vector<TYPE>(buffer_size));
            std::vector<TYPE> rlc_challenge(max_filter_indices);

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                for (std::size_t i = 0; i < input.filter_indices.size(); i++) {
                    TYPE RLC = buffer_size;
                    for (std::size_t j = 0; j < buffer_size; j++) {
                        RLC *= input.rlc_challenge;
                        RLC += input.filter_indices[i].buffer[j];
                        value_rlc[i][j] = RLC;
                    }
                    rlc_challenge[i] = input.rlc_challenge;
                    zkevm_word_type zero_hash = zkevm_keccak_hash({});

                    uint16_t word =
                        int(hash[i][15].to_integral()) * int(indice_0[i].to_integral()) +
                        int(hash[i][14].to_integral()) * int(indice_1[i].to_integral()) +
                        int(hash[i][13].to_integral()) * int(indice_2[i].to_integral());

                    index[i] = word & 0x7FF;
                    indice_remainder[i] = word >> 11 & 0x1F;
                    auto bit_index = 2047 - index[i].to_integral();
                    chunk_pos[i] = bit_index / filter_bit_per_chunk;
                    bit_pos[i] = 15 - bit_index % filter_bit_per_chunk;
                    indice_chunk[i] = word;

                    for (std::size_t j = 0; j < filter_chunks_amount; j++) {
                        if (i > 1) {
                            block_diff[i] = (block_id[i] != block_id[i - 2]);
                            tx_id_diff[i] = (tx_id[i] != tx_id[i - 2]);
                            tx_id_diff_and_not_block[i] =
                                tx_id_diff[i] * (1 - is_block[i]);
                        }

                        // new_chunk = previous filter or 0 if
                        // the transaction changed or the block changed
                        int new_chunk = (i < 2) ? 0
                                                : int((current_filter[i - 2][j] *
                                                       (1 - tx_id_diff_and_not_block[i]) *
                                                       (1 - block_diff[i]))
                                                          .to_integral());
                        // bit_chunk = 0 except at chunk_position where
                        // bit_chunk = index value
                        bit_chunk[i][j] = (j == chunk_pos[i].to_integral())
                                              ? 1 << int(bit_pos[i].to_integral())
                                              : 0;
                        // bit_chunk = 0 if is_final
                        if (is_final[i] == TYPE(1)) {
                            bit_chunk[i][j] = 0;
                        }

                        // definition of values for bit_chunk
                        if (bit_chunk[i][j] != 0) {
                            auto bit_index = 1 << int(bit_pos[i].to_integral());
                            index_selector[i] = !(new_chunk == (new_chunk | bit_index));

                            for (std::size_t k = 0; k < filter_bit_per_chunk; k++) {
                                bit_selector_inv[i][k] =
                                    k == bit_pos[i].to_integral() ? 0 : 1;
                                transition_chunk_bits[i][k] = new_chunk % 2;
                                new_chunk /= 2;
                            }
                        }
                    }
                }
            }
            for (std::size_t i = 0; i < max_filter_indices; i++) {
                if (i % 20 == 0) std::cout << ".";
                std::cout.flush();
                std::size_t cur_column = LogTable::get_witness_amount() +
                                         LogFilterTable::get_witness_amount() +
                                         KeccakTable::get_witness_amount() +
                                         RWTable::get_witness_amount();

                allocate(rlc_challenge[i], cur_column++, i);
                for (std::size_t j = 0; j < buffer_size; j++) {
                    allocate(value_rlc[i][j], cur_column++, i);
                }
                allocate(block_diff[i], cur_column++, i);
                allocate(tx_id_diff[i], cur_column++, i);
                allocate(tx_id_diff_and_not_block[i], cur_column++, i);
                allocate(index_selector[i], cur_column++, i);

                allocate(indice_chunk[i], cur_column++, i);
                allocate(index[i], cur_column++, i);
                allocate(indice_remainder[i], cur_column++, i);
                allocate(chunk_pos[i], cur_column++, i);
                allocate(bit_pos[i], cur_column++, i);

                for (std::size_t j = 0; j < filter_chunks_amount; j++) {
                    allocate(bit_chunk[i][j], cur_column++, i);
                }

                for (std::size_t j = 0; j < filter_bit_per_chunk; j++) {
                    allocate(bit_selector_inv[i][j], cur_column++, i);
                    allocate(transition_chunk_bits[i][j], cur_column++, i);
                }
            }

            std::cout << std::endl;

            static const auto zerohash = zkevm_keccak_hash({});
            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                std::vector<TYPE> frc;    // First 2 rows constraints
                std::vector<TYPE> erc;    // every row constraints
                std::vector<TYPE> nfrc1;  // non first rows constraints
                std::vector<TYPE> nfrc;   // non-first 2 rows constraints
                std::vector<TYPE> erl;    // every row 16 lookup
                std::vector<TYPE> nfrl;   // non-first 2 rows lookups

                // Binary constraints
                erc.push_back(is_last[1] * (is_last[1] - 1));
                erc.push_back(is_final[1] * (is_final[1] - 1));
                erc.push_back(tx_id_diff[1] * (tx_id_diff[1] - 1));
                erc.push_back(block_diff[1] * (block_diff[1] - 1));
                erc.push_back(tx_id_diff_and_not_block[1] *
                              (tx_id_diff_and_not_block[1] - 1));
                erc.push_back(selector[1] * (selector[1] - 1));
                erc.push_back(index_selector[1] * (1 - index_selector[1]));
                erc.push_back(indice_0[1] * (indice_0[1] - 1));
                erc.push_back(indice_1[1] * (indice_1[1] - 1));
                erc.push_back(indice_2[1] * (indice_2[1] - 1));

                for (std::size_t j = 0; j < filter_bit_per_chunk; j++) {
                    erc.push_back(bit_selector_inv[1][j] * (1 - bit_selector_inv[1][j]));
                    erc.push_back(transition_chunk_bits[1][j] *
                                  (1 - transition_chunk_bits[1][j]));
                }

                // Following rows have same values
                nfrc1.push_back((block_id[0] - block_id[1]) * is_block_const[1]);
                nfrc1.push_back((tx_id[0] - tx_id[1]) * is_block_const[1]);
                nfrc1.push_back((log_index[0] - log_index[1]) * is_block_const[1]);
                for (std::size_t j = 0; j < 16; j++) {
                    nfrc1.push_back((value[0][j] - value[1][j]) * is_block_const[1]);
                    nfrc1.push_back((hash[0][j] - hash[1][j]) * is_block_const[1]);
                }
                nfrc1.push_back((type[0] - type[1]) * is_block_const[1]);
                nfrc1.push_back((indice_0[0] - indice_0[1]) * is_block_const[1]);
                nfrc1.push_back((indice_1[0] - indice_1[1]) * is_block_const[1]);
                nfrc1.push_back((indice_2[0] - indice_2[1]) * is_block_const[1]);
                nfrc1.push_back((is_last[0] - is_last[1]) * is_block_const[1]);
                nfrc1.push_back((is_final[0] - is_final[1]) * is_block_const[1]);

                // // Range lookups
                erl.push_back(type[1]);
                erl.push_back(type[1] + two_16 - 5);  // 0 to 4

                // First row constraints
                frc.push_back(log_index[1]);  // first index is 0
                frc.push_back(type[1]);       // first type is address
                frc.push_back((indice_0[1] - 1) *
                              (1 - is_final[1]));  // first indice is 0
                frc.push_back(is_last[1]);

                // is_last = 0 else selector = 0
                erc.push_back(is_final[1] * selector[1]);

                // CONSTRAINTS FOR ORDERING:
                // Odd row for block and even row for tx
                constrain(is_block[0]);
                constrain(is_block[1] - 1);
                erc.push_back((is_block[1] - is_block_const[1]) *
                              (selector[1] + is_final[1]));
                // id differences
                nfrc.push_back((1 - block_diff[2]) * (block_id[0] - block_id[2]) *
                               (selector[2] + is_final[2]));
                nfrc.push_back((1 - tx_id_diff[2]) * (tx_id[0] - tx_id[2]) *
                               (selector[2] + is_final[2]));
                // if diff, id[2]>id[0]
                nfrl.push_back((block_id[2] - block_id[0] - 1) * block_diff[2]);
                nfrl.push_back((tx_id[2] - tx_id[0] - 1) * tx_id_diff[2]);

                // rw_id is increasing if is_last and same block
                nfrl.push_back((rw_id[2] - rw_id[0] - 1) * (1 - block_diff[2]) *
                               (selector[2] + is_final[2]) * is_last[0]);
                // rw_id is increasing if is_final and same block
                nfrl.push_back((rw_id[2] - rw_id[0] - 1) * (1 - block_diff[2]) *
                               (selector[2] + is_final[2]) * is_final[0]);
                // rw_id is the same if not is_last and selector
                nfrc.push_back((rw_id[2] - rw_id[0]) * (1 - is_last[0]) * selector[0] *
                               selector[2]);

                // Constraints if no final row (nullified if is_final)
                // only 1 indice active
                erc.push_back((1 - indice_0[1] - indice_1[1] - indice_2[1]) *
                              selector[1]);
                // indices are following each other if there is no final row
                nfrc.push_back((indice_0[0] - indice_1[2]) * selector[0]);
                nfrc.push_back((indice_1[0] - indice_2[2]));
                nfrc.push_back((indice_2[0] - indice_0[2]) * selector[2] * selector[0]);

                // type is the same if indice is not 0
                nfrc.push_back((type[2] - type[0]) * (1 - indice_0[2]) * selector[2]);
                // type is increasing by 1 if last indice is 2 and not last
                nfrc.push_back((type[2] - type[0] - 1) * indice_2[0] * (1 - is_last[0]));
                // if is_last and indice 2, next_type is 0
                nfrc.push_back(is_last[0] * indice_2[0] * type[2]);
                // log_index is increasing for same tx_id and block_id after
                // is_last and not final
                nfrc.push_back(is_last[0] * (log_index[0] + 1 - log_index[2]) *
                               selector[2]);

                // if block_diff, first row constraints:
                erc.push_back(block_diff[1] * log_index[1]);
                erc.push_back(block_diff[1] * type[1]);
                erc.push_back(block_diff[1] * (indice_0[1] - 1) * selector[1]);
                erc.push_back(block_diff[1] * is_last[1]);

                // id tx_diff, first row constraints:
                erc.push_back(tx_id_diff[1] * log_index[1]);
                erc.push_back(tx_id_diff[1] * type[1]);
                erc.push_back(tx_id_diff[1] * (indice_0[1] - 1) * selector[1]);
                erc.push_back(tx_id_diff[1] * is_last[1]);

                // if is_last next type and indice are 0
                nfrc.push_back(is_last[0] * type[2]);
                nfrc.push_back((is_last[0] * (indice_0[2] - 1)) * selector[2]);

                // Composite constraint
                nfrc.push_back(tx_id_diff_and_not_block[2] -
                               tx_id_diff[2] * (1 - is_block[2]));

                // Constraints ordering with final row
                // is_final -> prev is is_final or is_last and same log_index
                nfrc.push_back(is_final[2] * selector[0] * (log_index[2] - log_index[0]));
                nfrc.push_back(is_final[2] * selector[0] * (1 - is_last[0]));

                // is_final and prev not final -> is_last, same tx_id, same
                // log_index
                nfrc.push_back(is_final[2] * selector[0] * (1 - is_last[0]));
                nfrc.push_back(is_final[2] * selector[0] * tx_id_diff[0]);
                nfrc.push_back(is_final[2] * selector[0] * (log_index[2] - log_index[0]));
                // prev_is_final -> tx_id_diff (unless different block)
                nfrc.push_back(is_final[0] * (1 - tx_id_diff[2]) * (1 - block_diff[2]) *
                               (is_final[2] + selector[2]));
                // prev_is_final and !cur_final -> log_index 0, type 0, indice0
                nfrc.push_back(is_final[0] * selector[2] * log_index[2]);
                nfrc.push_back(is_final[0] * selector[2] * type[2]);
                nfrc.push_back(is_final[0] * selector[2] * (1 - indice_0[2]));

                // different tx_id -> prev is_final
                nfrc.push_back(tx_id_diff[2] * selector[0]);

                // CONSTRAINS FOR FILTER TRANSITION
                // indice chunk = index + remainder
                erc.push_back((indice_chunk[1] - index[1] - indice_remainder[1] * 2048) *
                              selector[1]);

                // decomposition of index in chunk_pos and bit_pos
                erc.push_back((2047 - index[1] - chunk_pos[1] * filter_bit_per_chunk +
                               bit_pos[1] - 15) *
                              selector[1]);

                // indice_chunk = indice x of the hash
                erc.push_back(indice_chunk[1] - hash[1][15] * indice_0[1] -
                              hash[1][14] * indice_1[1] - hash[1][13] * indice_2[1]);

                for (std::size_t j = 0; j < filter_chunks_amount; j++) {
                    TYPE transition_sum;
                    int pow = 1;
                    auto temp_chunk = current_filter[0][j] *
                                      (1 - tx_id_diff_and_not_block[2]) *
                                      (1 - block_diff[2]);
                    auto old_chunk = temp_chunk;
                    // temp_chunk = 0 if
                    //   tx_filter and last id is different
                    //   block_id is different

                    TYPE bit_chunk_sum = 0;

                    // The loop removes all bits of temp_chunk except the
                    // bit_index
                    for (std::size_t k = 0; k < filter_bit_per_chunk; k++) {
                        temp_chunk -=
                            transition_chunk_bits[2][k] * bit_selector_inv[2][k] * pow;
                        transition_sum += transition_chunk_bits[2][k] * pow;
                        bit_chunk_sum += (1 - bit_selector_inv[2][k]) * pow;
                        pow *= 2;
                    }

                    // If temp_chunk is 0, the index was not in the
                    // previous_filter -> index_selector is 1
                    // If temp_chunk is not 0, it is equal to bit_chunk

                    // temp_chunk is 0 when is_final because all indices are 0

                    nfrc.push_back((1 - index_selector[2]) *
                                   (temp_chunk - bit_chunk[2][j]) * bit_chunk[2][j]);

                    // transition_sum = previous_chunk if address_bit_chunk
                    nfrc.push_back(bit_chunk[2][j] * (transition_sum - old_chunk));

                    nfrc.push_back((current_filter[2][j] - old_chunk -
                                    bit_chunk[2][j] * index_selector[2]) *
                                   selector[2]);

                    // // if bit_chunk !=0, bit_chunk_sum = bit_chunk
                    // nfrc.push_back((bit_chunk_sum - bit_chunk[2][j]) *
                    // bit_chunk[2][j]);
                }

                // first row constrain for the filter
                for (std::size_t j = 0; j < filter_chunks_amount; j++) {
                    TYPE transition_sum;
                    int pow = 1;
                    TYPE temp_chunk = 0;

                    for (std::size_t k = 0; k < filter_bit_per_chunk; k++) {
                        temp_chunk -=
                            transition_chunk_bits[1][k] * bit_selector_inv[1][k] * pow;
                        transition_sum += transition_chunk_bits[1][k] * pow;
                        pow *= 2;
                    }
                    frc.push_back((1 - index_selector[1]) *
                                  (temp_chunk - bit_chunk[1][j]) * bit_chunk[1][j]);

                    frc.push_back(bit_chunk[1][j] * transition_sum);

                    frc.push_back(current_filter[1][j] -
                                  bit_chunk[1][j] * index_selector[1]);
                }
                // RLC constraints
                for (std::size_t j = 0; j < buffer_size; j++) {
                    TYPE prev_rlc = j == 0 ? buffer_size : value_rlc[1][j - 1];
                    erc.push_back(prev_rlc * rlc_challenge[1] + buffer[1][j] -
                                  value_rlc[1][j]);
                }
                // Same rlc challenge for each row
                nfrc.push_back((rlc_challenge[2] - rlc_challenge[0]) * selector[2]);

                {
                    PROFILE_SCOPE("Log circuit constraints row definition")

                    for (auto &constr : erc) {
                        context_object.relative_constrain(
                            context_object.relativize(constr, -1), 0,
                            max_filter_indices - 1);
                    }
                    for (auto &constr : erl) {
                        std::vector<TYPE> tmp = {context_object.relativize(constr, -1)};
                        context_object.relative_lookup(tmp, "chunk_16_bits/full", 0,
                                                       max_filter_indices - 1);
                    }
                    for (auto &constr : nfrl) {
                        std::vector<TYPE> tmp = {context_object.relativize(constr, -1)};
                        context_object.relative_lookup(tmp, "chunk_16_bits/full", 2,
                                                       max_filter_indices - 1);
                    }
                    for (auto &constr : nfrc) {
                        context_object.relative_constrain(
                            context_object.relativize(constr, -1), 2,
                            max_filter_indices - 1);
                    }

                    for (auto &constr : frc) {
                        context_object.relative_constrain(
                            context_object.relativize(constr, -1), 0, 1);
                    }

                    zkevm_word_type zero_hash = zkevm_keccak_hash({});
                    auto zero_hash_chunks = w_to_16(zero_hash);

                    std::vector<TYPE> tmp = {value_rlc[1][buffer_size - 1] * selector[1]};
                    for (std::size_t i = 0; i < 16; i++) {
                        tmp.push_back(hash[1][15 - i] * selector[1] +
                                      zero_hash_chunks[i] * (1 - selector[1]));
                    }
                    context_object.relative_lookup(context_object.relativize(tmp, -1),
                                                   "keccak_table", 0, max_filter_indices);

                    tmp = {selector[1], block_id[1], tx_id[1],    log_index[1],
                           type[1],     indice_0[1], indice_1[1], indice_2[1],
                           is_last[1],  is_block[1], is_final[1], rw_id[1]};
                    for (std::size_t i = 0; i < 16; i++) {
                        tmp.push_back(value[1][i]);
                    }
                    context_object.relative_lookup(context_object.relativize(tmp, -1),
                                                   "zkevm_log_opcode", 0,
                                                   max_filter_indices);

                    tmp = {l_t.selector[1],  l_t.block_id[1], l_t.tx_id[1],
                           l_t.log_index[1], l_t.type[1],     l_t.indice_0[1],
                           l_t.indice_1[1],  l_t.indice_2[1], l_t.is_last[1],
                           l_t.is_block[1],  l_t.is_final[1], l_t.rw_id[1]};
                    for (std::size_t i = 0; i < 16; i++) {
                        tmp.push_back(l_t.value[1][i]);
                    }
                    context_object.relative_lookup(context_object.relativize(tmp, -1),
                                                   "zkevm_log_order", 0,
                                                   max_filter_indices);
                    tmp = {{TYPE(std::size_t(rw_operation_type::log_index)) * selector[1],
                            rw_id[1] * selector[1]}};
                    context_object.relative_lookup(context_object.relativize(tmp, -1),
                                                   "zkevm_rw_8_log", 0,
                                                   max_filter_indices);
                }
            }
            std::cout << std::endl;
        }
    };
}  // namespace nil::blueprint::bbf::zkevm_small_field
