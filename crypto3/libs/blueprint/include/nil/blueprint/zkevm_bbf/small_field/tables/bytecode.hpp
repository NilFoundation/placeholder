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

#include "nil/blueprint/zkevm_bbf/types/opcode_enum.hpp"
#include "nil/blueprint/zkevm_bbf/types/hashed_buffers.hpp"

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

    size_t max_bytecode_size;   // Maximum possible  bytecodes sum length

    // interfaces for interaction with other components:
    std::vector<TYPE> tag;              // Row type: 0(padding), 1 (header), 2 (executable bytes), 3 (metadata)
    std::vector<TYPE> index;            // Position of the byte within the bytecode
    std::vector<TYPE> value;            // Byte value (for bytes) or total length (for header)
    std::vector<TYPE> is_opcode;        // Flags whether the byte is an opcode (1) or not (0)
    std::vector<TYPE> bytecode_id;      // Bytecode's unique identifier used by zkevm circuit
                                        // We use it to prevent 16-column bytecode hash repeitition

    static size_t get_witness_amount() {
        return 5;
    }

    bytecode_table(
            context_type &context_object,
            const input_type &input,
            size_t max_bytecode_size_)
        : max_bytecode_size(max_bytecode_size_),
          tag(max_bytecode_size_),
          index(max_bytecode_size_),
          value(max_bytecode_size_),
          is_opcode(max_bytecode_size_),
          bytecode_id(max_bytecode_size_),
          generic_component<FieldType,stage>(context_object) {

        if constexpr (stage == GenerationStage::ASSIGNMENT) {
            const auto &bytecodes = input.get_data();

            size_t row = 1;
            size_t current_index = 0;
            size_t push_size = 0;

            for (size_t i = 0; i < bytecodes.size(); ++i) {
                const auto &buffer = bytecodes[i].first;
                BOOST_ASSERT(row + 1 + buffer.size() < max_bytecode_size);

                // Header
                tag[row] = 0;
                index[row] = current_index = 0;
                value[row] = 0;
                is_opcode[row] = 0;
                bytecode_id[row] = i + 1;
                ++row;

                size_t push_size = 0;
                while (current_index < buffer.size()) {
                    auto byte = buffer[current_index];
                    value[row] = byte;
                    index[row] = current_index;;
                    bytecode_id[row] = i + 1;
                    tag[row] = 1;

                    if (push_size == 0) {
                        is_opcode[row] = 1;

                        // Check for PUSH opcodes (0x60 to 0x7f) and set push_size
                        if (byte >= 0x60 && byte <= 0x7f)
                            push_size = byte - 0x5f;
                    } else {  // In a PUSH operation
                        is_opcode[row] = 0;
                        --push_size;
                    }

                    ++current_index, ++row;
                }

                // Add potentially accessed implicit zero bytes
                BOOST_ASSERT(row + push_size + 1 < max_bytecode_size);

                while (push_size > 0) { // missing push arguments
                    BOOST_ASSERT(row < max_bytecode_size);
                    tag[row] = 1;
                    index[row] = current_index;
                    value[row] = 0;
                    is_opcode[row] = 0;
                    bytecode_id[row] = i + 1;

                    ++current_index, ++row, --push_size;
                }

                // Add implicit STOP instruction
                tag[row] = 1;
                index[row] = current_index;
                value[row] = 0;
                is_opcode[row] = 1;
                bytecode_id[row] = i + 1;
                ++current_index, ++row;
            }

            while (row < max_bytecode_size) {
                tag[row] = 1;
                index[row] = current_index;
                value[row] = 0;
                is_opcode[row] = 1;
                bytecode_id[row] = bytecodes.size();
                ++current_index, ++row;
            }
        }

        // allocate everything. NB: this replaces the map from the original component
        for (size_t i = 0; i < max_bytecode_size; ++i) {
            allocate(tag[i], 0, i);
            allocate(index[i], 1, i);
            allocate(value[i], 2, i);
            allocate(is_opcode[i], 3, i);
            allocate(bytecode_id[i], 4, i);
        }

        lookup_table("zkevm_bytecode", {0,1,2,3,4}, 0, max_bytecode_size);
        lookup_table("zkevm_bytecode_copy", {1,2,4}, 0, max_bytecode_size);
    };
};

}
