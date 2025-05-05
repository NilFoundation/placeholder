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
                                              std::vector<zkevm_log>,
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

                std::vector<TYPE> id;         // transaction index
                std::vector<TYPE> log_index;  // log index
                std::vector<TYPE> value_hi;   // address or topic x
                std::vector<TYPE> value_lo;   // address or topic x
                std::vector<TYPE> type;       // 0: address, or x: topic x
                std::vector<TYPE> indice;     // each value has 3 indices
                // last indice of a log_index (can have up to 15)
                std::vector<TYPE> is_last;
                std::vector<std::vector<TYPE>> current_filter;

                static std::size_t get_witness_amount() { return 135; }
                // only current_filter?

                log_table(context_type& context_object, const input_type& input,
                          std::size_t max_log_indices)
                    : generic_component<FieldType, stage>(context_object),
                      id(max_log_indices),
                      log_index(max_log_indices),
                      value_hi(max_log_indices),
                      value_lo(max_log_indices),
                      type(max_log_indices),
                      indice(max_log_indices),
                      is_last(max_log_indices),
                      current_filter(max_log_indices,
                                     std::vector<TYPE>(filter_chunks_amount)) {
                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        auto logs = input;
                        std::size_t row = 0;
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

                        auto set_row = [&](TYPE t_id, TYPE log_i, TYPE val_hi,
                                           TYPE val_lo, TYPE t, TYPE last,
                                           const std::array<std::size_t, 16>& hash_bytes,
                                           std::vector<std::vector<TYPE>>& current_filter,
                                           size_t& row) {
                            for (int i = 0; i < 3; ++i) {
                                for (std::size_t j = 0; j < filter_chunks_amount; j++) {
                                    current_filter[row][j] =
                                        row == 0 ? 0 : current_filter[row - 1][j];
                                }

                                uint16_t word = hash_bytes[i];
                                uint16_t index = word & 0x7FF;
                                uint16_t bit_index = 2047 - index;
                                size_t byte_pos = bit_index / 16;
                                uint8_t bit_pos = 15 - (bit_index % 16);
                                auto current_value = current_filter[row][byte_pos];
                                auto new_value =
                                    current_value.to_integral() | (1 << bit_pos);
                                current_filter[row][byte_pos] = new_value;

                                id[row] = t_id;
                                log_index[row] = log_i;
                                value_hi[row] = val_hi;
                                value_lo[row] = val_lo;
                                type[row] = t;
                                indice[row] = i;
                                is_last[row] = last == 1 && i == 2;
                                std::cout << "current_filter:" << std::endl;
                                std::cout << print_log_bloom(current_filter[row])
                                          << std::endl;
                                std::cout << "row:" << row << std::endl;
                                row++;
                            }
                        };
                        for (auto& log : logs) {
                            std::vector<uint8_t> address_buffer(20);
                            for (std::size_t i = 0; i < 20; i++) {
                                address_buffer[19 - i] =
                                    uint8_t(log.address >> (8 * i) & 0xFF);  // Big-endian
                            }

                            auto address_hash = zkevm_keccak_hash(address_buffer);
                            auto hash_bytes = w_to_16(address_hash);

                            set_row(log.id, log.index, w_hi<FieldType>(log.address),
                                    w_lo<FieldType>(log.address), 0,
                                    log.topics.size() == 0, hash_bytes, current_filter,
                                    row);

                            for (std::size_t i = 0; i < log.topics.size(); i++) {
                                std::vector<uint8_t> topics_buffer(32);
                                for (std::size_t j = 0; j < 32; j++) {
                                    topics_buffer[31 - j] = uint8_t(
                                        log.topics[i] >> (8 * j) & 0xFF);  // Big-endian
                                }

                                auto topic_hash = zkevm_keccak_hash(topics_buffer);

                                auto topic_hash_bytes = w_to_16(topic_hash);
                                set_row(log.id, log.index, w_hi<FieldType>(log.topics[i]),
                                        w_lo<FieldType>(log.topics[i]), i + 1,
                                        (i == log.topics.size() - 1), topic_hash_bytes,
                                        current_filter, row);
                            }
                        }
                    }
                    for (std::size_t i = 0; i < max_log_indices; i++) {
                        allocate(id[i], 0, i);
                        allocate(log_index[i], 1, i);
                        allocate(value_hi[i], 2, i);
                        allocate(value_lo[i], 3, i);
                        allocate(type[i], 4, i);
                        allocate(indice[i], 5, i);
                        allocate(is_last[i], 6, i);
                        for (std::size_t j = 0; j < filter_chunks_amount; j++) {
                            allocate(current_filter[i][j], 7 + j, i);
                        }
                    }
                    std::vector<std::size_t> indices(135);
                    std::iota(indices.begin(), indices.end(), 0);
                    lookup_table("zkevm_logs", indices, 0, max_log_indices);
                }
            };
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil
