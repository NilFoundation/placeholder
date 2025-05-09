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

namespace nil {
    namespace blueprint {
        namespace bbf {
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
                using input_type =
                    typename std::conditional<stage == GenerationStage::ASSIGNMENT,
                                              std::vector<zkevm_filter_indices>,
                                              std::nullptr_t>::type;
                using integral_type = typename FieldType::integral_type;
                static constexpr std::size_t filter_chunks_amount = 128;

                // The Bloom filter consists of 2048 bits
                // Each address and topic do 3 bitwise OR operation on a single bit (turn
                // a bit on if it is off) The bit corresponds to the value of the 11 low
                // bits of the top 2, 4 and 6 bytes of the hash Each row of the table
                // corresponds to an indice of the hash (3 indice by hash) Each log
                // operation produces between 3 and 15 rows depending on the number of
                // topics

              public:
                zkevm_keccak_buffers keccaks;

                std::vector<TYPE> block_id;
                std::vector<TYPE> tx_id;      // transaction index
                std::vector<TYPE> log_index;  // log index
                std::vector<TYPE> value_hi;   // address or topic x
                std::vector<TYPE> value_lo;   // address or topic x
                std::vector<TYPE> type;       // 0: address, or x: topic x
                std::vector<TYPE> indice;     // each value has 3 indices
                // last indice of a log_index (can have up to 15)
                std::vector<TYPE> is_last;
                std::vector<TYPE> is_block;  // 0: tx_filter, 1: block filter
                std::vector<std::vector<TYPE>> current_filter;

                static std::size_t get_witness_amount() { return 137; }

                static std::vector<TYPE> log_lookup(TYPE block_id, TYPE tx_id, TYPE index,
                                                    TYPE value_hi, TYPE value_lo,
                                                    TYPE type, TYPE is_block) {
                    std::vector<TYPE> result = {
                        block_id,
                        tx_id,     // transaction_id
                        index,     // log_index
                        value_hi,  // value_hi
                        value_lo,  // value_lo
                        type,      // type
                        TYPE(2),   // indice
                        TYPE(1),   // is_last
                        is_block   // is_block
                    };
                    return result;
                }

                log_table(context_type& context_object, const input_type& input,
                          std::size_t max_filter_indices)
                    : generic_component<FieldType, stage>(context_object),
                      block_id(max_filter_indices),
                      tx_id(max_filter_indices),
                      log_index(max_filter_indices),
                      value_hi(max_filter_indices),
                      value_lo(max_filter_indices),
                      type(max_filter_indices),
                      indice(max_filter_indices),
                      is_last(max_filter_indices),
                      is_block(max_filter_indices),
                      current_filter(max_filter_indices,
                                     std::vector<TYPE>(filter_chunks_amount)) {
                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        auto filter_indices = input;
                        auto print_log_bloom =
                            [](const std::vector<TYPE>& bloom) -> std::string {
                            std::stringstream ss;
                            ss << "0x" << std::hex << std::setfill('0');
                            for (const auto& byte : bloom) {
                                ss << std::setw(4)
                                   << (unsigned int)(byte.to_integral() & 0xFFFF);
                            }
                            return ss.str();
                        };
                        for (std::size_t i = 0; i < filter_indices.size(); i++) {
                            block_id[i] = filter_indices[i].block_id;
                            tx_id[i] = filter_indices[i].tx_id;
                            log_index[i] = filter_indices[i].index;
                            value_hi[i] = w_hi<FieldType>(filter_indices[i].value);
                            value_lo[i] = w_lo<FieldType>(filter_indices[i].value);
                            type[i] = filter_indices[i].type;
                            indice[i] = filter_indices[i].indice;
                            is_last[i] = filter_indices[i].is_last;
                            is_block[i] = filter_indices[i].is_block;
                            for (std::size_t j = 0; j < filter_chunks_amount; j++) {
                                current_filter[i][j] = filter_indices[i].filter[j];
                            }

                            print_log_bloom(current_filter[i]);
                        }
                    }

                    for (std::size_t i = 0; i < max_filter_indices; i++) {
                        allocate(block_id[i], 0, i);
                        allocate(tx_id[i], 1, i);
                        allocate(log_index[i], 2, i);
                        allocate(value_hi[i], 3, i);
                        allocate(value_lo[i], 4, i);
                        allocate(type[i], 5, i);
                        allocate(indice[i], 6, i);
                        allocate(is_last[i], 7, i);
                        allocate(is_block[i], 8, i);
                        for (std::size_t j = 0; j < filter_chunks_amount; j++) {
                            allocate(current_filter[i][j], 9 + j, i);
                        }
                    }
                    lookup_table("zkevm_logs",
                                 std::vector<std::size_t>({0, 1, 2, 3, 4, 5, 6, 7, 8}), 0,
                                 max_filter_indices);
                    std::vector<std::size_t> indices(137);
                    std::iota(indices.begin(), indices.end(), 0);
                    lookup_table("zkevm_logs_filters", indices, 0, max_filter_indices);
                }
            };
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil
