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
                static constexpr std::size_t filter_chunks_amount = 256;

              public:
                zkevm_keccak_buffers keccaks;

                std::vector<TYPE> id;     // transaction index
                std::vector<TYPE> index;  // log index
                std::vector<TYPE> address;
                // std::vector<TYPE> data; //log data
                std::vector<std::vector<TYPE>> topics;
                std::vector<std::vector<TYPE>> previous_filter;
                std::vector<std::vector<TYPE>> current_filter;

                static std::size_t get_witness_amount() { return 519; }
                // TODO
                // Indice calculation
                // Filter calculation
                // Make sure current filter is accurate
                // Lookup keccak hash

                // Lookup from log opcode
                // Block log table
                // Lookup from transaction opcode

                // Can we use something else than max_zkevm_rows
                // Table is big and mostly empty

                //  Line for last log of transaction?
                //  Lookup last log transaction in block log table
                //  Maybe not a new line, but a new column?
                // final -> 0 or 1

                //maybe previous filter not needed? -> yes for lookup

                //can we have more than 1 byte in each column?

                log_table(context_type& context_object, const input_type& input,
                          std::size_t max_zkevm_rows)
                    : generic_component<FieldType, stage>(context_object),
                      id(max_zkevm_rows),
                      index(max_zkevm_rows),
                      address(max_zkevm_rows),
                      // data(max_zkevm_rows),
                      topics(max_zkevm_rows, std::vector<TYPE>(4)),
                      previous_filter(
                          max_zkevm_rows,
                          std::vector<TYPE>(filter_chunks_amount)),  // can we use bigger chunks?
                      current_filter(max_zkevm_rows,
                                     std::vector<TYPE>(filter_chunks_amount))
                {
                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        auto logs = input;
                        std::size_t row = 0;
                        auto print_log_bloom = [](const std::vector<TYPE>& bloom) -> std::string {
                                std::stringstream ss;
                                ss << "0x" << std::hex << std::setfill('0');
                                for (const auto& byte : bloom) {
                                    ss << std::setw(2) << (unsigned int)(byte.data.base() & 0xFF);
                                }
                                return ss.str();
                            };

                        auto set_bloom_bits = [&](const std::array<std::uint8_t, 32>& hash_bytes,
                                                std::vector<std::vector<TYPE>>& current_filter,
                                                size_t row) {
                            for (int i = 0; i < 1; ++i) {
                            // for (int i = 0; i < 3; ++i) {
                                uint16_t word = (hash_bytes[2 * i] << 8) + hash_bytes[2 * i + 1];
                                uint16_t index = word & 0x7FF;
                                uint16_t bit_index = 2047 - index;
                                size_t byte_pos = bit_index / 8;
                                uint8_t bit_pos = 7 - (bit_index % 8);
                                auto current_value = current_filter[row][byte_pos];
                                // auto new_value = (integral_type(current_value.data) & 0xFF) | (1 << bit_pos);
                                auto new_value = integral_type(current_value.data) | (1 << bit_pos);
                                std::cout<<"word: " << word << std::endl;
                                std::cout << "table byte_pos: " << byte_pos << std::endl;
                                std::cout << "table bit_pos: " << int(bit_pos) << std::endl;
                                current_filter[row][byte_pos] = new_value;
                            }
                        };
                        for (auto& log : logs) {
                            id[row] = log.id;
                            index[row] = log.index;
                            address[row] = integral_type(log.address);
                            for (std::size_t i = 0; i < filter_chunks_amount; i++) {
                                previous_filter[row][i] =
                                    row == 0 ? 0 : current_filter[row - 1][i];
                                current_filter[row][i] = previous_filter[row][i];
                            }
                            std::vector<uint8_t> address_buffer(20);
                            for (std::size_t i = 0; i < 20; i++) {
                                address_buffer[19 - i] = uint8_t(log.address >> (8 * i) & 0xFF); // Big-endian
                            }

                            auto address_hash = zkevm_keccak_hash(address_buffer);
                            auto hash_bytes =
                                w_to_8(address_hash);  // Convert to 32-byte array
                            set_bloom_bits(hash_bytes, current_filter, row);

                            for (std::size_t i = 0; i < log.topics.size(); i++) {
                                topics[row][i] = log.topics[i];
                                std::vector<uint8_t> topics_buffer(32);
                                for (std::size_t j = 0; j < 32; j++) {
                                    topics_buffer[31 - j] = uint8_t(log.topics[i] >> (8 * j) & 0xFF); // Big-endian
                                }

                                auto topic_hash = zkevm_keccak_hash(topics_buffer);
                                auto topic_hash_bytes = w_to_8(topic_hash);
                                // set_bloom_bits(topic_hash_bytes, current_filter, row);
                            }
                            std::cout<<"previous_filter:"<<std::endl;
                            std::cout << print_log_bloom(previous_filter[row]) << std::endl;
                            std::cout<<"current_filter:"<<std::endl;
                            std::cout << print_log_bloom(current_filter[row]) << std::endl;
                            row++;
                        }
                    }
                    for (std::size_t i = 0; i < max_zkevm_rows; i++) {
                        allocate(id[i], 0, i);
                        allocate(index[i], 1, i);
                        allocate(address[i], 2, i);
                        allocate(topics[i][0], 3, i);
                        allocate(topics[i][1], 4, i);
                        allocate(topics[i][2], 5, i);
                        allocate(topics[i][3], 6, i);
                        for (std::size_t j = 0; j < filter_chunks_amount; j++) {
                            allocate(previous_filter[i][j], 7 + j, i);
                        }
                        for (std::size_t j = 0; j < filter_chunks_amount; j++) {
                            allocate(current_filter[i][j], 7 + filter_chunks_amount + j, i);
                        }
                    }
                    std::vector<std::size_t> indices(519);
                    std::iota(indices.begin(), indices.end(), 0);
                    lookup_table("zkevm_logs", indices, 0, max_zkevm_rows);
                    // lookup_table("zkevm_bloom_filter",std::vector<std::size_t>({0,1,2,3,4,5,6}),0,max_zkevm_rows);
                    // block_table
                }
            };
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil
