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

#include <nil/blueprint/bbf/components/hashes/keccak/keccak_dynamic.hpp>
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/keccak_table.hpp>
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
                using KeccakDynamic = typename bbf::keccak_dynamic<FieldType, stage>;

                // TODO
                // Currently a lot of duplicate hash
                // Should we do a new keccak table?
                // Need keccak small field and other lookup table small field
                //
                // Can probably remove block_id if we prove block individually
                // Currently test data has trace from different block

                struct input_type {
                    TYPE rlc_challenge;

                    LogTable::input_type filter_indices;
                    KeccakTable::private_input_type keccak_buffers;
                };

                using value = typename FieldType::value_type;
                using integral_type = typename FieldType::integral_type;

                static constexpr std::size_t filter_chunks_amount = 128;
                static constexpr std::size_t filter_bit_per_chunk = 16;
                constexpr static const value two_16 = 65536;

                static table_params get_minimal_requirements(
                    std::size_t max_filter_indices, std::size_t max_keccak_blocks) {
                    return {.witnesses =
                                LogTable::get_witness_amount() +
                                KeccakTable::get_witness_amount() +
                                KeccakDynamic::get_minimal_requirements(max_keccak_blocks)
                                    .witnesses +
                                19 + filter_chunks_amount + 2 * filter_bit_per_chunk,
                            .public_inputs = 1,
                            .constants = 1,
                            .rows = std::max({max_filter_indices, max_keccak_blocks,
                                              KeccakDynamic::get_minimal_requirements(
                                                  max_keccak_blocks)
                                                  .rows})};
                }

                static void allocate_public_inputs(context_type &context,
                                                   input_type &input,
                                                   std::size_t max_filter_indices,
                                                   std::size_t max_keccak_blocks) {
                    context.allocate(input.rlc_challenge, 0, 0,
                                     column_type::public_input);
                }

                tx_log(context_type &context_object, const input_type &input,
                       std::size_t max_filter_indices, std::size_t max_keccak_blocks)
                    : generic_component<FieldType, stage>(context_object) {
                    std::vector<std::size_t> log_lookup_area;
                    std::vector<std::size_t> keccak_lookup_area;
                    std::vector<std::size_t> keccak_dynamic_lookup_area;

                    std::size_t current_column = 0;
                    std::size_t dynamic_rows =
                        KeccakDynamic::get_minimal_requirements(max_keccak_blocks).rows;
                    for (std::size_t i = 0; i < LogTable::get_witness_amount(); i++)
                        log_lookup_area.push_back(current_column++);
                    for (std::size_t i = 0; i < KeccakTable::get_witness_amount(); i++)
                        keccak_lookup_area.push_back(current_column++);
                    for (std::size_t i = 0;
                         i < KeccakDynamic::get_minimal_requirements(max_keccak_blocks)
                                 .witnesses;
                         i++) {
                        keccak_dynamic_lookup_area.push_back(current_column++);
                    }

                    context_type log_ct =
                        context_object.subcontext(log_lookup_area, 1, max_filter_indices);
                    context_type keccak_ct = context_object.subcontext(
                        keccak_lookup_area, 1 + max_filter_indices,
                        max_filter_indices + dynamic_rows + 1);
                    context_type keccak_dynamic_ct = context_object.subcontext(
                        keccak_dynamic_lookup_area, 1 + max_filter_indices,
                        max_filter_indices + dynamic_rows + 1);

                    typename KeccakDynamic::input_type input_dynamic;
                    typename KeccakTable::input_type input_keccak_table;
                    TYPE rlc_challenge;

                    LogTable l_t =
                        LogTable(log_ct, input.filter_indices, max_filter_indices);

                    const std::vector<TYPE> &selector = l_t.selector;
                    const std::vector<TYPE> &block_id = l_t.block_id;
                    const std::vector<TYPE> &tx_id = l_t.tx_id;
                    const std::vector<TYPE> &log_index = l_t.log_index;
                    const std::vector<std::vector<TYPE>> &value = l_t.value;
                    const std::vector<TYPE> &type = l_t.type;
                    const std::vector<TYPE> &indice_0 = l_t.indice_0;
                    const std::vector<TYPE> &indice_1 = l_t.indice_1;
                    const std::vector<TYPE> &indice_2 = l_t.indice_2;
                    const std::vector<TYPE> &is_last = l_t.is_last;
                    const std::vector<TYPE> &is_block = l_t.is_block;
                    const std::vector<TYPE> &is_block_const = l_t.is_block_const;
                    const std::vector<std::vector<TYPE>> &hash = l_t.hash;
                    const std::vector<std::vector<TYPE>> &current_filter =
                        l_t.current_filter;

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

                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        for (std::size_t i = 0; i < input.filter_indices.size(); i++) {
                            TYPE hi = w_hi<FieldType>(input.filter_indices[i].hash);
                            TYPE lo = w_lo<FieldType>(input.filter_indices[i].hash);
                            std::pair<TYPE, TYPE> pair_values = {hi, lo};
                            input_dynamic.input.emplace_back(
                                input.filter_indices[i].buffer, pair_values);

                            uint16_t word = int(hash[i][15].to_integral()) *
                                                int(indice_0[i].to_integral()) +
                                            int(hash[i][14].to_integral()) *
                                                int(indice_1[i].to_integral()) +
                                            int(hash[i][13].to_integral()) *
                                                int(indice_2[i].to_integral());

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
                                int new_chunk =
                                    (i < 2) ? 0
                                            : int((current_filter[i - 2][j] *
                                                   (1 - tx_id_diff_and_not_block[i]) *
                                                   (1 - block_diff[i]))
                                                      .to_integral());
                                // bit_chunk = 0 except at chunk_position where
                                // bit_chunk = index value
                                bit_chunk[i][j] = (j == chunk_pos[i].to_integral())
                                                      ? 1 << int(bit_pos[i].to_integral())
                                                      : 0;

                                // definition of values for bit_chunk
                                if (bit_chunk[i][j] != 0) {
                                    auto bit_index = 1 << int(bit_pos[i].to_integral());
                                    index_selector[i] =
                                        !(new_chunk == (new_chunk | bit_index));

                                    for (std::size_t k = 0; k < filter_bit_per_chunk;
                                         k++) {
                                        bit_selector_inv[i][k] =
                                            k == bit_pos[i].to_integral() ? 0 : 1;
                                        transition_chunk_bits[i][k] = new_chunk % 2;
                                        new_chunk /= 2;
                                    }
                                }
                            }
                        }
                    }

                    // allocate(rlc_challenge, 0, 0);
                    // rlc_challenge = input.rlc_challenge;
                    // input_dynamic.rlc_challenge = rlc_challenge;

                    // input_keccak_table.rlc_challenge = rlc_challenge;
                    // input_keccak_table.private_input = input.keccak_buffers;

                    // KeccakTable k_t =
                    //     KeccakTable(keccak_ct, input_keccak_table, max_keccak_blocks);

                    // KeccakDynamic k_d = KeccakDynamic(keccak_dynamic_ct, input_dynamic,
                    //                                   max_keccak_blocks);

                    for (std::size_t i = 0; i < max_filter_indices; i++) {
                        if (i % 20 == 0) std::cout << ".";
                        std::cout.flush();
                        std::size_t cur_column = LogTable::get_witness_amount() +
                                                 KeccakTable::get_witness_amount() + 1;
                        allocate(block_diff[i], cur_column++, i);
                        allocate(tx_id_diff[i], cur_column++, i);
                        allocate(tx_id_diff_and_not_block[i], cur_column++, i);
                        allocate(index_selector[i], cur_column++, i);

                        allocate(indice_chunk[i], cur_column++, i);
                        allocate(index[i], cur_column++, i);
                        allocate(indice_remainder[i], cur_column++, i);
                        allocate(chunk_pos[i], cur_column++, i);
                        allocate(bit_pos[i], cur_column++, i);

                        for (std::size_t k = 0; k < filter_chunks_amount; k++) {
                            allocate(bit_chunk[i][k], cur_column++, i);
                        }

                        for (std::size_t k = 0; k < filter_bit_per_chunk; k++) {
                            allocate(bit_selector_inv[i][k], cur_column++, i);
                            allocate(transition_chunk_bits[i][k], cur_column++, i);
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
                            erc.push_back(bit_selector_inv[1][j] *
                                          (1 - bit_selector_inv[1][j]));
                            erc.push_back(transition_chunk_bits[1][j] *
                                          (1 - transition_chunk_bits[1][j]));
                        }

                        // If selector 0, fields for unique id are 0
                        // erc.push_back((1 - selector[1]) *
                        //               (block_id[1] + tx_id[1] + value_hi[1] +
                        //                value_lo[1] + log_index[1]));

                        // Following rows have same values
                        nfrc1.push_back((block_id[0] - block_id[1]) * is_block_const[1]);
                        nfrc1.push_back((tx_id[0] - tx_id[1]) * is_block_const[1]);
                        nfrc1.push_back((log_index[0] - log_index[1]) *
                                        is_block_const[1]);
                        for (std::size_t j = 0; j < 16; j++) {
                            nfrc1.push_back((value[0][j] - value[1][j]) *
                                            is_block_const[1]);
                            nfrc1.push_back((hash[0][j] - hash[1][j]) *
                                            is_block_const[1]);
                        }
                        nfrc1.push_back((type[0] - type[1]) * is_block_const[1]);
                        nfrc1.push_back((indice_0[0] - indice_0[1]) * is_block_const[1]);
                        nfrc1.push_back((indice_1[0] - indice_1[1]) * is_block_const[1]);
                        nfrc1.push_back((indice_2[0] - indice_2[1]) * is_block_const[1]);
                        nfrc1.push_back((is_last[0] - is_last[1]) * is_block_const[1]);

                        // Range lookups
                        erl.push_back(type[1]);
                        erl.push_back(type[1] + two_16 - 5);  // 0 to 4

                        // First row constraints
                        frc.push_back(log_index[1]);     // first index is 0
                        frc.push_back(type[1]);          // first type is address
                        frc.push_back(indice_0[1] - 1);  // first indice is 0
                        frc.push_back(is_last[1]);

                        // CONSTRAINTS FOR ORDERING:

                        // Odd row for block and even row for tx
                        // constrain(is_block[0]);
                        // constrain(is_block[1] - 1);
                        // nfrc.push_back((is_block[2] - is_block[0]) * selector[2]);
                        erc.push_back((is_block[1] - is_block_const[1]) * selector[1]);

                        // id differences
                        nfrc.push_back((1 - block_diff[2]) * (block_id[0] - block_id[2]) *
                                       selector[2]);
                        nfrc.push_back((1 - tx_id_diff[2]) * (tx_id[0] - tx_id[2]) *
                                       selector[2]);
                        // if diff, id[2]>id[0]
                        nfrl.push_back((block_id[2] - block_id[0] - 1) * block_diff[2]);
                        nfrl.push_back((tx_id[2] - tx_id[0] - 1) * tx_id_diff[2]);

                        // only 1 indice active
                        erc.push_back((1 - indice_0[1] - indice_1[1] - indice_2[1]) *
                                      selector[1]);
                        // indices are following each other in a loop
                        nfrc.push_back(indice_0[0] - indice_1[2]);
                        nfrc.push_back(indice_1[0] - indice_2[2]);
                        nfrc.push_back((indice_2[0] - indice_0[2]) * selector[2]);

                        // type is the same if indice is not 0
                        nfrc.push_back((type[2] - type[0]) * (1 - indice_0[2]) *
                                       selector[2]);
                        // type is increasing by 1 if last indice is 2 and not last
                        nfrc.push_back((type[2] - type[0] - 1) * indice_2[0] *
                                       (1 - is_last[0]));
                        // if is_last and indice 2, next_type is 0
                        nfrc.push_back(is_last[0] * indice_2[0] * type[2]);

                        // if not last -> id = prev_id
                        nfrc.push_back((1 - is_last[0]) * (tx_id[2] - tx_id[0]));

                        // if prev last and log_index 0 and same block ->
                        //  id > prev_id
                        nfrl.push_back(is_last[0] * (tx_id[2] - tx_id[0] - 1) *
                                       (1 - log_index[2]) * selector[2] *
                                       (1 - block_diff[2]));

                        // if block_diff, first row constraints:
                        erc.push_back(block_diff[1] * log_index[1]);
                        erc.push_back(block_diff[1] * type[1]);
                        erc.push_back(block_diff[1] * (indice_0[1] - 1));
                        erc.push_back(block_diff[1] * is_last[1]);

                        // if is_last next type and indice are 0
                        nfrc.push_back(is_last[0] * type[2]);
                        nfrc.push_back((is_last[0] * (indice_0[2] - 1)) * selector[2]);

                        // Composite constraint
                        nfrc.push_back(tx_id_diff_and_not_block[2] -
                                       tx_id_diff[2] * (1 - is_block[2]));

                        // CONSTRAINS FOR FILTER TRANSITION
                        // indice chunk = index + remainder
                        erc.push_back(
                            (indice_chunk[1] - index[1] - indice_remainder[1] * 2048) *
                            selector[1]);

                        // decomposition of index in chunk_pos and bit_pos
                        erc.push_back((2047 - index[1] -
                                       chunk_pos[1] * filter_bit_per_chunk + bit_pos[1] -
                                       15) *
                                      selector[1]);

                        // indice_chunk = indice x of the hash
                        erc.push_back(indice_chunk[1] - hash[1][15] * indice_0[1] -
                                      hash[1][14] * indice_1[1] -
                                      hash[1][13] * indice_2[1]);

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
                                temp_chunk -= transition_chunk_bits[2][k] *
                                              bit_selector_inv[2][k] * pow;
                                transition_sum += transition_chunk_bits[2][k] * pow;
                                bit_chunk_sum += (1 - bit_selector_inv[2][k]) * pow;
                                pow *= 2;
                            }

                            // If temp_chunk is 0, the index was not in the
                            // previous_filter -> index_selector is 1
                            // If temp_chunk is not 0, it is equal to bit_chunk

                            nfrc.push_back((1 - index_selector[2]) *
                                           (temp_chunk - bit_chunk[2][j]) *
                                           bit_chunk[2][j]);

                            // transition_sum = previous_chunk if address_bit_chunk
                            nfrc.push_back(bit_chunk[2][j] *
                                           (transition_sum - old_chunk));

                            nfrc.push_back((current_filter[2][j] - old_chunk -
                                            bit_chunk[2][j] * index_selector[2]) *
                                           selector[2]);

                            // if bit_chunk !=0, bit_chunk_sum = bit_chunk
                            nfrc.push_back((bit_chunk_sum - bit_chunk[2][j]) *
                                           bit_chunk[2][j]);
                        }

                        // first row constrain for the filter
                        for (std::size_t j = 0; j < filter_chunks_amount; j++) {
                            TYPE transition_sum;
                            int pow = 1;
                            TYPE temp_chunk = 0;

                            for (std::size_t k = 0; k < filter_bit_per_chunk; k++) {
                                temp_chunk -= transition_chunk_bits[1][k] *
                                              bit_selector_inv[1][k] * pow;
                                transition_sum += transition_chunk_bits[1][k] * pow;
                                pow *= 2;
                            }
                            frc.push_back((1 - index_selector[1]) *
                                          (temp_chunk - bit_chunk[1][j]) *
                                          bit_chunk[1][j]);

                            frc.push_back(bit_chunk[1][j] * transition_sum);

                            frc.push_back(current_filter[1][j] -
                                          bit_chunk[1][j] * index_selector[1]);
                        }

                        // std::vector<TYPE> tmp;
                        // for (std::size_t i = 0; i < max_keccak_blocks; i++) {
                        //     tmp = {TYPE(1), k_t.RLC[i], k_t.hash_hi[i], k_t.hash_lo[i],
                        //            k_t.is_last[i]};
                        //     lookup(tmp, "keccak_dynamic");
                        //     tmp = {k_d.m[i].h.is_last, k_d.m[i].h.RLC,
                        //     k_d.m[i].h.hash_hi,
                        //            k_d.m[i].h.hash_lo};
                        //     lookup(tmp, "keccak_table");
                        // }

                        {
                            PROFILE_SCOPE("Log circuit constraints row definition")

                            for (auto &constr : erc) {
                                context_object.relative_constrain(
                                    context_object.relativize(constr, -1), 0,
                                    max_filter_indices - 1);
                            }
                            for (auto &constr : erl) {
                                std::vector<TYPE> tmp = {
                                    context_object.relativize(constr, -1)};
                                context_object.relative_lookup(tmp, "chunk_16_bits/full",
                                                               0, max_filter_indices - 1);
                            }
                            for (auto &constr : nfrl) {
                                std::vector<TYPE> tmp = {
                                    context_object.relativize(constr, -1)};
                                context_object.relative_lookup(tmp, "chunk_16_bits/full",
                                                               2, max_filter_indices - 1);
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
                        }
                    }
                    std::cout << std::endl;
                }
            };
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil
