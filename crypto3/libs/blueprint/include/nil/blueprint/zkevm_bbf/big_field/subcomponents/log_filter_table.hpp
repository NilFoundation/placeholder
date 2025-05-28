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
            class log_filter_table : public generic_component<FieldType, stage> {
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

                std::vector<TYPE> block_id;   // block index
                std::vector<TYPE> tx_id;      // transaction index
                std::vector<TYPE> log_index;  // log index
                std::vector<TYPE> value_hi;   // address or topic x
                std::vector<TYPE> value_lo;   // address or topic x
                std::vector<TYPE> type;       // 0: address, or x: topic x
                std::vector<TYPE> indice_0;   // Each value has 3 indices
                std::vector<TYPE> indice_1;   // Indice column is 0
                std::vector<TYPE> indice_2;   // For all except current indice
                // last indice of a log_index (can have up to 15)
                std::vector<TYPE> is_last;
                std::vector<TYPE> is_block;  // 0: tx_filter, 1: block filter
                std::vector<TYPE> is_block_const;
                // 1 if final row of a tx. Only the filter is used in that row
                std::vector<TYPE> is_final;
                std::vector<TYPE> rw_id;
                std::vector<std::vector<TYPE>> hash;    // hash of value
                std::vector<TYPE> hash_hi;              // hash of value
                std::vector<TYPE> hash_lo;              // hash of value
                std::vector<std::vector<TYPE>> buffer;  // buffer of value
                std::vector<std::vector<TYPE>> current_filter;

                static std::size_t get_witness_amount() { return 192; }

                log_filter_table(context_type& context_object, const input_type& input,
                                 std::size_t max_filter_indices)
                    : generic_component<FieldType, stage>(context_object),
                      selector(max_filter_indices),
                      block_id(max_filter_indices),
                      tx_id(max_filter_indices),
                      log_index(max_filter_indices),
                      value_hi(max_filter_indices),
                      value_lo(max_filter_indices),
                      type(max_filter_indices),
                      indice_0(max_filter_indices),
                      indice_1(max_filter_indices),
                      indice_2(max_filter_indices),
                      is_last(max_filter_indices),
                      is_block(max_filter_indices),
                      is_block_const(max_filter_indices),
                      is_final(max_filter_indices),
                      rw_id(max_filter_indices),
                      hash_hi(max_filter_indices),
                      hash_lo(max_filter_indices),
                      hash(max_filter_indices, std::vector<TYPE>(16)),
                      buffer(max_filter_indices, std::vector<TYPE>(buffer_size)),
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
                            selector[i] = filter_indices[i].is_final ? 0 : 1;
                            block_id[i] = filter_indices[i].block_id;
                            tx_id[i] = filter_indices[i].tx_id;
                            log_index[i] = filter_indices[i].index;
                            value_hi[i] = w_hi<FieldType>(filter_indices[i].value);
                            value_lo[i] = w_lo<FieldType>(filter_indices[i].value);
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
                            hash_hi[i] = w_hi<FieldType>(filter_indices[i].hash);
                            hash_lo[i] = w_lo<FieldType>(filter_indices[i].hash);
                            hash[i] = zkevm_word_to_field_element<FieldType>(
                                filter_indices[i].hash);
                            for (std::size_t j = 0; j < filter_chunks_amount; j++) {
                                current_filter[i][j] = filter_indices[i].filter[j];
                            }
                            for (std::size_t j = 0; j < buffer_size; j++) {
                                buffer[i][j] = filter_indices[i].buffer[j];
                            }

                            if (is_final[i] == TYPE(1) && is_block[i] == TYPE(1)) {
                                // std::cout << print_log_bloom(current_filter[i])
                                //           << std::endl;
                            }
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
                        allocate(value_hi[i], 4, i);
                        allocate(value_lo[i], 5, i);
                        allocate(type[i], 6, i);
                        allocate(indice_0[i], 7, i);
                        allocate(indice_1[i], 8, i);
                        allocate(indice_2[i], 9, i);
                        allocate(is_last[i], 10, i);
                        allocate(is_block[i], 11, i);
                        allocate(is_final[i], 12, i);
                        allocate(rw_id[i], 13, i);
                        allocate(hash_hi[i], 14, i);
                        allocate(hash_lo[i], 15, i);
                        for (std::size_t j = 0; j < 16; j++) {
                            allocate(hash[i][j], 16 + j, i);
                        }
                        for (std::size_t j = 0; j < 32; j++) {
                            allocate(buffer[i][j], 32 + j, i);
                        }
                        for (std::size_t j = 0; j < filter_chunks_amount; j++) {
                            allocate(current_filter[i][j], 64 + j, i);
                        }
                    }
                    std::vector<std::size_t> tx_indices(14);
                    std::iota(tx_indices.begin(), tx_indices.end(), 0);
                    lookup_table("zkevm_log_order", tx_indices, 0, max_filter_indices);

                    std::vector<std::size_t> indices(192);
                    std::iota(indices.begin(), indices.end(), 0);
                    lookup_table("zkevm_log_filters", indices, 0, max_filter_indices);
                }
            };
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil
