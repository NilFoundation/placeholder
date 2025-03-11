//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#include <utility>

#include <nil/blueprint/zkevm_bbf/types/hashed_buffers.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            template<typename FieldType, GenerationStage stage>
            class bytecode_table : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;

            public:
                using TYPE = typename generic_component<FieldType, stage>::TYPE;
                using input_type = std::conditional_t<
                    stage == GenerationStage::ASSIGNMENT, zkevm_keccak_buffers, std::monostate
                >;

                std::size_t max_bytecode_size;

                std::vector<TYPE> tag = std::vector<TYPE>(max_bytecode_size);       // 0: header, 1: executable bytes, 2: metadata
                std::vector<TYPE> index = std::vector<TYPE>(max_bytecode_size);     // Position in bytecode
                std::vector<TYPE> value = std::vector<TYPE>(max_bytecode_size);     // Byte value or total length
                std::vector<TYPE> is_opcode = std::vector<TYPE>(max_bytecode_size); // 1 if opcode, 0 otherwise
                std::vector<TYPE> hash_hi = std::vector<TYPE>(max_bytecode_size);   // High 128 bits of hash
                std::vector<TYPE> hash_lo = std::vector<TYPE>(max_bytecode_size);   // Low 128 bits of hash

                static std::size_t get_witness_amount() { return 6; }

                bytecode_table(context_type &context_object,
                               const input_type &input,
                               std::size_t max_bytecode_size_,
                               bool make_links = true)
                    : max_bytecode_size(max_bytecode_size_),
                      generic_component<FieldType, stage>(context_object) {

                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        auto bytecodes = input.get_data();
                        std::size_t cur = 0;

                        for (std::size_t i = 0; i < bytecodes.size(); i++) {
                            TYPE hash_hi_val = w_hi<FieldType>(bytecodes[i].second);
                            TYPE hash_lo_val = w_lo<FieldType>(bytecodes[i].second);
                            TYPE push_size = 0;
                            const auto &buffer = bytecodes[i].first;
                            std::size_t total_len = buffer.size();

                            // Compute metadata length from the last two bytes
                            std::size_t exec_boundary = total_len; // Default: all bytes executable
                            if (total_len >= 2) {
                                std::size_t meta_len = (buffer[total_len - 2] << 8) + buffer[total_len - 1];
                                if (meta_len + 2 <= total_len) {
                                    std::size_t boundary = total_len - meta_len - 2 - 1; // Byte before metadata
                                    if (boundary < total_len && (buffer[boundary] == 0x00 || buffer[boundary] == 0xfe || buffer[boundary] == 0xf3)) {
                                        exec_boundary = boundary + 1; // After stopping opcode
                                    }
                                }
                            }

                            // Header
                            BOOST_ASSERT(cur < max_bytecode_size);
                            tag[cur] = 0;
                            index[cur] = 0;
                            value[cur] = total_len;
                            is_opcode[cur] = 0;
                            hash_hi[cur] = hash_hi_val;
                            hash_lo[cur] = hash_lo_val;
                            cur++;

                            // Bytes
                            for (std::size_t j = 0; j < buffer.size(); j++, cur++) {
                                BOOST_ASSERT(cur < max_bytecode_size);
                                std::uint8_t byte = buffer[j];
                                value[cur] = byte;
                                hash_hi[cur] = hash_hi_val;
                                hash_lo[cur] = hash_lo_val;
                                index[cur] = j;

                                if (j < exec_boundary) { // Executable bytes
                                    tag[cur] = 1;
                                    if (push_size == 0) {
                                        is_opcode[cur] = 1;
                                        if (byte > 0x5f && byte < 0x80) {
                                            push_size = byte - 0x5f;
                                        }
                                    } else {
                                        is_opcode[cur] = 0;
                                        push_size--;
                                    }
                                } else { // Metadata bytes
                                    tag[cur] = 2;
                                    is_opcode[cur] = 0;
                                    push_size = 0; // Reset to avoid carry-over
                                }
                                //std::cout << cur << ". " << std::hex << std::size_t(byte) << " " << is_opcode[cur] << " " << push_size << std::dec << std::endl;
                            }
                        }
                    }

                    for (std::size_t i = 0; i < max_bytecode_size; i++) {
                        allocate(tag[i], 0, i);
                        allocate(index[i], 1, i);
                        allocate(value[i], 2, i);
                        allocate(is_opcode[i], 3, i);
                        allocate(hash_hi[i], 4, i);
                        allocate(hash_lo[i], 5, i);
                    }
                    lookup_table("zkevm_bytecode", std::vector<std::size_t>({0, 1, 2, 3, 4, 5}), 0, max_bytecode_size);
                }
            };
        }
    }
}