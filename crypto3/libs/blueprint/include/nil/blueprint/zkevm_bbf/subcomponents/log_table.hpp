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
                // a bit on if it is off)

                // The bit corresponds to the value of the 11 low
                // bits of the top 2, 4 and 6 bytes of the hash

                // Each row of the table
                // corresponds to an indice of the hash (3 indice by hash)

                // Each log operation produces between 3 and 15 rows depending on the
                // number of topics

                // Each log indice is duplicated, once to modify the tx_filter, and once
                // to modify the block_filter.

                // Both filters are labeled current_filter
                // Even rows are tx_filter and odd rows are block_filter

              public:
                std::vector<TYPE> selector;   // 0 when outside the assigned cells
                std::vector<TYPE> block_id;   // block index
                std::vector<TYPE> tx_id;      // transaction index
                std::vector<TYPE> log_index;  // log index
                std::vector<std::vector<TYPE>> value;  // address or topic x
                std::vector<TYPE> type;                // 0: address, or x: topic x
                std::vector<TYPE> indice_0;            // Each value has 3 indices
                std::vector<TYPE> indice_1;            // Indice column is 0
                std::vector<TYPE> indice_2;            // For all except current indice
                // last indice of a log_index (can have up to 15)
                std::vector<TYPE> is_last;
                std::vector<TYPE> is_block;  // 0: tx_filter, 1: block filter
                std::vector<TYPE> is_block_const;
                std::vector<std::vector<TYPE>> hash;  // hash of value
                std::vector<std::vector<TYPE>> current_filter;

                static std::size_t get_witness_amount() { return 170; }

                static std::vector<TYPE> log_tx_lookup(
                    TYPE block_id, TYPE tx_id, TYPE index,
                    std::vector<std::vector<TYPE>> value, TYPE type) {
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
                    result.push_back(TYPE(1));  // is_last
                    result.push_back(TYPE(0));  // is_block

                    return result;
                }

                static std::vector<TYPE> log_block_lookup(TYPE block_id, TYPE tx_id) {
                    std::vector<TYPE> result = {
                        TYPE(1),  // selector
                        block_id,
                        tx_id,    // transaction_id
                        TYPE(0),  // indice_0
                        TYPE(0),  // indice_1
                        TYPE(1),  // indice_2
                        TYPE(1),  // is_last
                        TYPE(1)   // is_block
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
                      is_block_const(max_filter_indices),
                      hash(max_filter_indices, std::vector<TYPE>(16)),
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
                            selector[i] = 1;
                            block_id[i] = filter_indices[i].block_id;
                            tx_id[i] = filter_indices[i].tx_id;
                            log_index[i] = filter_indices[i].index;
                            value[i] = zkevm_word_to_field_element<FieldType>(
                                filter_indices[i].value);
                            type[i] = filter_indices[i].type;
                            indice_0[i] = filter_indices[i].indice == 0;
                            indice_1[i] = filter_indices[i].indice == 1;
                            indice_2[i] = filter_indices[i].indice == 2;
                            is_last[i] = filter_indices[i].is_last;
                            is_block[i] = filter_indices[i].is_block;
                            hash[i] = zkevm_word_to_field_element<FieldType>(
                                filter_indices[i].hash);
                            for (std::size_t j = 0; j < filter_chunks_amount; j++) {
                                current_filter[i][j] = filter_indices[i].filter[j];
                            }

                            print_log_bloom(current_filter[i]);
                        }
                    }

                    for (std::size_t i = 0; i < max_filter_indices; i++) {
                        is_block_const[i] = TYPE(i % 2);
                        context_object.allocate(is_block_const[i], 0, i,
                                                column_type::constant);
                        allocate(selector[i], 0, i);
                        allocate(block_id[i], 1, i);
                        allocate(tx_id[i], 2, i);
                        allocate(log_index[i], 3, i);
                        for (std::size_t j = 0; j < 16; j++) {
                            allocate(value[i][j], 4 + j, i);
                        }
                        allocate(type[i], 20, i);
                        allocate(indice_0[i], 21, i);
                        allocate(indice_1[i], 22, i);
                        allocate(indice_2[i], 23, i);
                        allocate(is_last[i], 24, i);
                        allocate(is_block[i], 25, i);
                        for (std::size_t j = 0; j < 16; j++) {
                            allocate(hash[i][j], 26 + j, i);
                        }
                        for (std::size_t j = 0; j < filter_chunks_amount; j++) {
                            allocate(current_filter[i][j], 42 + j, i);
                        }
                    }
                    std::vector<std::size_t> tx_indices(25);
                    std::iota(tx_indices.begin(), tx_indices.end(), 0);
                    lookup_table("zkevm_tx_logs", tx_indices, 0, max_filter_indices);
                    lookup_table("zkevm_block_logs",
                                 std::vector<std::size_t>({0, 1, 2, 21, 22, 23, 24, 25}),
                                 0, max_filter_indices);
                    std::vector<std::size_t> indices(170);
                    std::iota(indices.begin(), indices.end(), 0);
                    lookup_table("zkevm_logs_filters", indices, 0, max_filter_indices);
                }
            };
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil
