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

#include <nil/blueprint/zkevm_bbf/types/log.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_word.hpp>

namespace nil::blueprint::bbf::zkevm_small_field {
    template<typename FieldType, GenerationStage stage>
    class log_table : public generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

      public:
        using typename generic_component<FieldType, stage>::TYPE;
        using input_type = typename std::conditional<stage == GenerationStage::ASSIGNMENT,
                                                     std::vector<zkevm_filter_indices>,
                                                     std::nullptr_t>::type;
        using integral_type = typename FieldType::integral_type;
        static constexpr std::size_t filter_chunks_amount = 128;
        static constexpr std::size_t buffer_size = 32;

        // The Bloom filter consists of 2048 bits
        // Each address and topic do 3 bitwise OR operation on a single bit (turn
        // a bit on if it is off)

        // The bit corresponds to the value of the 11 low
        // bits of the top 2, 4 and 6 bytes of the hash

        // Each row of the table
        // corresponds to an indice of the hash (3 indice by hash)

        // Each log operation produces between 6 and 30 rows depending on the
        // number of topics. (doubled for tx filter and block filter)

        // Each log indice is duplicated, once to modify the tx_filter, and once
        // to modify the block_filter.

        // Both filters are labeled current_filter
        // Even rows are tx_filter and odd rows are block_filter

        //  Each tx add an additionnal 2 rows, that give the final filter after
        //  the tx. At that row values such as value, hash, type, log_index will
        //  be unconstrained because they will not be used.

      public:
        // 1 when the row is produced by a log
        // 0 when the row is the final row of a tx
        std::vector<TYPE> selector;

        std::vector<TYPE> block_id;            // block index
        std::vector<TYPE> tx_id;               // transaction index
        std::vector<TYPE> log_index;           // log index
        std::vector<std::vector<TYPE>> value;  // address or topic
        std::vector<TYPE> type;                // 0: address, or x: topic x
        std::vector<TYPE> indice_0;            // Each value has 3 indices
        std::vector<TYPE> indice_1;            // Indice column is 0
        std::vector<TYPE> indice_2;            // For all except current indice
        // last indice of a log_index (can have up to 15)
        std::vector<TYPE> is_last;
        std::vector<TYPE> is_block;  // 0: tx_filter, 1: block filter
        // 1 if final row of a tx. Only the filter is used in that row
        std::vector<TYPE> is_final;
        std::vector<TYPE> rw_id;  // rw counter

        static std::size_t get_witness_amount() { return 28; }

        // LOG OPCODE verifies the right topics are included
        static std::vector<TYPE> log_opcode_lookup(TYPE block_id, TYPE tx_id, TYPE index,
                                                   TYPE type, TYPE is_last, TYPE rw_id,
                                                   std::vector<TYPE> value) {
            std::vector<TYPE> result = {};
            result.push_back(1);  // selector
            result.push_back(block_id);
            result.push_back(tx_id);
            result.push_back(index);
            for (std::size_t i = 0; i < 16; i++) {
                result.push_back(value[i]);
            }
            result.push_back(type);
            result.push_back(TYPE(0));  // indice_0
            result.push_back(TYPE(0));  // indice_1
            result.push_back(TYPE(1));  // indice_2
            result.push_back(is_last);  // is_last
            result.push_back(TYPE(0));  // is_block
            result.push_back(TYPE(0));  // is_final
            result.push_back(rw_id);    // rw_id

            return result;
        }

        // END TX OPCODE verifies tx filter is included and the number of logs
        static std::vector<TYPE> log_tx_lookup(TYPE block_id, TYPE tx_id,
                                               TYPE log_index) {
            std::vector<TYPE> result = {
                block_id,
                tx_id,  // transaction_id
                log_index,
                TYPE(1),  // is_block
                TYPE(1)   // is_final
            };
            return result;
        }

        log_table(context_type& context_object, const input_type& input,
                  std::size_t max_filter_indices)
            : generic_component<FieldType, stage>(context_object),
              selector(max_filter_indices),
              block_id(max_filter_indices),
              tx_id(max_filter_indices),
              log_index(max_filter_indices),
              value(max_filter_indices, std::vector<TYPE>(16)),
              type(max_filter_indices),
              indice_0(max_filter_indices),
              indice_1(max_filter_indices),
              indice_2(max_filter_indices),
              is_last(max_filter_indices),
              is_block(max_filter_indices),
              is_final(max_filter_indices),
              rw_id(max_filter_indices) {
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                auto filter_indices = input;
                auto print_log_bloom = [](const std::vector<TYPE>& bloom) -> std::string {
                    std::stringstream ss;
                    ss << "0x" << std::hex << std::setfill('0');
                    for (const auto& byte : bloom) {
                        ss << std::setw(4) << (unsigned int)(byte.to_integral() & 0xFFFF);
                    }
                    return ss.str();
                };
                for (std::size_t i = 0; i < filter_indices.size(); i++) {
                    selector[i] = filter_indices[i].is_final ? 0 : 1;
                    block_id[i] = filter_indices[i].block_id;
                    tx_id[i] = filter_indices[i].tx_id;
                    log_index[i] = filter_indices[i].index;
                    value[i] =
                        zkevm_word_to_field_element<FieldType>(filter_indices[i].value);
                    type[i] = filter_indices[i].type;
                    if (!filter_indices[i].is_final) {
                        indice_0[i] = filter_indices[i].indice == 0;
                        indice_1[i] = filter_indices[i].indice == 1;
                        indice_2[i] = filter_indices[i].indice == 2;
                    }
                    is_last[i] = filter_indices[i].is_last;
                    is_block[i] = filter_indices[i].is_block;
                    is_final[i] = filter_indices[i].is_final;
                    rw_id[i] = filter_indices[i].rw_id;
                }
            }

            for (std::size_t i = 0; i < max_filter_indices; i++) {
                allocate(selector[i], 0, i);
                allocate(block_id[i], 1, i);
                allocate(tx_id[i], 2, i);
                allocate(log_index[i], 3, i);
                allocate(type[i], 4, i);
                allocate(indice_0[i], 5, i);
                allocate(indice_1[i], 6, i);
                allocate(indice_2[i], 7, i);
                allocate(is_last[i], 8, i);
                allocate(is_block[i], 9, i);
                allocate(is_final[i], 10, i);
                allocate(rw_id[i], 11, i);
                for (std::size_t j = 0; j < 16; j++) {
                    allocate(value[i][j], 12 + j, i);
                }
            }
            std::vector<std::size_t> tx_indices(28);
            std::iota(tx_indices.begin(), tx_indices.end(), 0);
            lookup_table("zkevm_log_opcode", tx_indices, 0, max_filter_indices);

            lookup_table("zkevm_log_tx", std::vector<std::size_t>({1, 2, 3, 9, 10}), 0,
                         max_filter_indices);

            lookup_table("zkevm_log_rw", std::vector<std::size_t>({11}), 0,
                         max_filter_indices);
        }
    };
}  // namespace nil::blueprint::bbf::zkevm_small_field
