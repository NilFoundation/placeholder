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

#include <nil/blueprint/zkevm_bbf/types/hashed_buffers.hpp>
#include <utility>

namespace nil {
namespace blueprint {
namespace bbf {
// Input: zkevm_keccak_buffers
// Output: zkevm_bytecode lookup table, contains 6 columns:
//  tag, index, value, is_opcode, hash_hi, hash_lo
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
  using input_type = std::conditional_t<stage == GenerationStage::ASSIGNMENT,
                                        zkevm_keccak_buffers, std::monostate>;

  std::size_t max_bytecode_size;

  std::vector<TYPE> tag;    // Row type: 0 (header), 1 (executable bytes), 2 (metadata)
  std::vector<TYPE> index;  // Position of the byte within the bytecode
  std::vector<TYPE> value;  // Byte value (for bytes) or total length (for header)
  std::vector<TYPE> is_opcode;  // Flags whether the byte is an opcode (1) or not (0)
  std::vector<TYPE> hash_hi;    // High 128 bits of the bytecode's Keccak hash
  std::vector<TYPE> hash_lo;    // Low 128 bits of the bytecode's Keccak hash

  bytecode_table(context_type &context_object, const input_type &input,
                 std::size_t max_bytecode_size_, bool make_links = true)
      : max_bytecode_size(max_bytecode_size_),
        generic_component<FieldType, stage>(context_object),
        tag(max_bytecode_size),
        index(max_bytecode_size),
        value(max_bytecode_size),
        is_opcode(max_bytecode_size),
        hash_hi(max_bytecode_size),
        hash_lo(max_bytecode_size) {
    if constexpr (stage == GenerationStage::ASSIGNMENT) {
      auto bytecodes = input.get_data();  // bytecode buffers and their hashes
      std::size_t cur = 0;

      for (std::size_t i = 0; i < bytecodes.size(); i++) {
        TYPE hash_hi_val = w_hi<FieldType>(bytecodes[i].second);
        TYPE hash_lo_val = w_lo<FieldType>(bytecodes[i].second);
        TYPE push_size = 0;  // Tracks the number of bytes in a PUSH operation
        const auto &buffer = bytecodes[i].first;
        std::size_t total_len = buffer.size();

        // Determine the boundary between executable bytes and metadata
        std::size_t exec_boundary = total_len;  // Default: all bytes are executable
        if (total_len >= 2) {
          // Metadata length is encoded in the last two bytes
          std::size_t meta_len = (buffer[total_len - 2] << 8) + buffer[total_len - 1];
          if (meta_len + 2 <= total_len) {
            std::size_t boundary = total_len - meta_len - 2 - 1;  // Byte before metadata
            // Check for stopping opcodes (STOP, INVALID, RETURN) that will
            // confirm the length of the metadata
            if (boundary < total_len &&
                (buffer[boundary] == 0x00 || buffer[boundary] == 0xfe ||
                 buffer[boundary] == 0xf3)) {
              exec_boundary = boundary + 1;  // Set boundary after the stopping opcode
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

          if (j < exec_boundary) {
            tag[cur] = 1;
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
            tag[cur] = 2;
            is_opcode[cur] = 0;
            push_size = 0;
          }
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
    lookup_table("zkevm_bytecode", std::vector<std::size_t>({0, 1, 2, 3, 4, 5}), 0,
                 max_bytecode_size);
  }
  static std::size_t get_witness_amount() { return 6; }
};
}  // namespace bbf
}  // namespace blueprint
}  // namespace nil
