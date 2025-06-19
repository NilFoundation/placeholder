//---------------------------------------------------------------------------//
// Copyright (c) 2025 Elena Tatuzova <e.tatuzova@nil.foundation>
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

namespace nil::blueprint::bbf::zkevm_small_field{
    // Component for bytecode table

    template<typename FieldType, GenerationStage stage>
    class bytecode_table : public generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

        public:
        using typename generic_component<FieldType,stage>::TYPE;
        using input_type = std::conditional_t<
            stage == GenerationStage::ASSIGNMENT, zkevm_keccak_buffers, std::monostate
        >;

        std::size_t max_bytecode_size;   // Maximum possible  bytecodes sum length

        // interfaces for interaction with other components:
        std::vector<TYPE> tag;              // Row type: 0(padding), 1 (header), 2 (executable bytes), 3 (metadata)
        std::vector<TYPE> index;            // Position of the byte within the bytecode
        std::vector<TYPE> value;            // Byte value (for bytes) or total length (for header)
        std::vector<TYPE> is_opcode;        // Flags whether the byte is an opcode (1) or not (0)
        std::vector<TYPE> bytecode_id;      // Bytecode's unique identifier used by zkevm circuit
                                            // We use it to prevent 16-column bytecode hash repeitition

        static std::size_t get_witness_amount(){
            return 5;
        }

        bytecode_table(
            context_type &context_object,
            const input_type &input,
            std::size_t max_bytecode_size_
        ) :
            max_bytecode_size(max_bytecode_size_),
            tag(max_bytecode_size_),
            index(max_bytecode_size_),
            value(max_bytecode_size_),
            is_opcode(max_bytecode_size_),
            bytecode_id(max_bytecode_size_),
            generic_component<FieldType,stage>(context_object) {
            BOOST_LOG_TRIVIAL(trace) << "Small field bytecode table assignment";

            // If we're in assignment stage, prepare all the values
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                const auto &bytecodes = input.get_data();
                std::size_t cur = 0;

                for(std::size_t i = 0; i < bytecodes.size(); i++) {
                    TYPE push_size = 0;
                    std::size_t meta_len = 0;
                    const auto &buffer = bytecodes[i].first;
                    std::size_t total_len = buffer.size();

                    // Determine the boundary between executable bytes and metadata
                    std::size_t exec_boundary = total_len;  // Default: all bytes are executable
                    if (total_len >= 2) {
                        // Metadata length is encoded in the last two bytes
                        meta_len = (buffer[total_len - 2] << 8) + buffer[total_len - 1];
                        if (meta_len + 2 <= total_len) {
                            std::size_t boundary = total_len - meta_len - 2 - 1;  // Byte before metadata
                            // Check for stopping opcodes (STOP, INVALID, RETURN) that will
                            // confirm the length of the metadata
                            if (boundary < total_len &&
                                (buffer[boundary] == 0x00 || buffer[boundary] == 0xfe ||
                                buffer[boundary] == 0xf3)
                            ) {
                                exec_boundary = boundary + 1;  // Set boundary after the stopping opcode
                            }
                        }
                    }
                    BOOST_LOG_TRIVIAL(trace) << "Bytecode " << i << " size = " << total_len;
                    BOOST_LOG_TRIVIAL(trace) << "Executable bytes boundary: " << exec_boundary;

                    // Header
                    BOOST_ASSERT(cur < max_bytecode_size);
                    tag[cur] = 1;
                    index[cur] = 0;
                    value[cur] = total_len;
                    is_opcode[cur] = 0;
                    bytecode_id[cur] = i + 1;
                    cur++;

                    // Bytes
                    for(std::size_t j = 0; j < buffer.size(); j++, cur++){
                        BOOST_ASSERT(cur < max_bytecode_size);
                        auto byte = buffer[j];
                        value[cur] = byte;
                        index[cur] = j;
                        bytecode_id[cur] = i + 1;
                        if (j < exec_boundary) {
                            tag[cur] = 2;
                            if (push_size == 0) {
                                is_opcode[cur] = 1;
                                // Check for PUSH opcodes (0x60 to 0x7f) and set push_size
                                if (byte > 0x5f && byte < 0x80) {
                                    push_size = byte - 0x5f;
                                }
                            } else {  // In a PUSH operation
                                is_opcode[cur] = 0;
                                push_size--;
                            }
                        } else {  // Metadata bytes
                            tag[cur] = 3;
                            is_opcode[cur] = 0;
                            push_size = 0;
                        }
                    }
                }
            }
            // allocate everything. NB: this replaces the map from the original component
            for(std::size_t i = 0; i < max_bytecode_size; i++) {
                allocate(tag[i], 0, i);
                allocate(index[i], 1, i);
                allocate(value[i], 2, i);
                allocate(is_opcode[i], 3, i);
                allocate(bytecode_id[i], 4, i);
            }
            // declare dynamic lookup table
            lookup_table("zkevm_bytecode",std::vector<std::size_t>({0,1,2,3,4}), 0, max_bytecode_size);
            lookup_table("zkevm_bytecode_copy",std::vector<std::size_t>({1,2,4}), 0, max_bytecode_size);
        };
    };
}