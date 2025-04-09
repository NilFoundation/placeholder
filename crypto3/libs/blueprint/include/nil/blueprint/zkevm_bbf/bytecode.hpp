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

#include <nil/blueprint/zkevm_bbf/subcomponents/bytecode_table.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/keccak_table.hpp>
#include <nil/blueprint/zkevm_bbf/types/hashed_buffers.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            // Input: zkevm_keccak_buffers, rlc_challenge
            // Integrates bytecode_table and keccak_table with additional constraints and
            // lookups to verify zkEVM bytecode properties.
            template<typename FieldType, GenerationStage stage>
            class bytecode : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;

                using BytecodeTable = bytecode_table<FieldType, stage>;
                using KeccakTable = keccak_table<FieldType, stage>;

              public:
                using typename generic_component<FieldType, stage>::table_params;
                using typename generic_component<FieldType, stage>::TYPE;

                struct input_type {
                    TYPE rlc_challenge;  // Random linear combination challenge
                    BytecodeTable::input_type bytecodes;  // Bytecode buffers with hashes
                    KeccakTable::private_input_type
                        keccak_buffers;  // Keccak-specific input
                };

                std::size_t max_bytecode_size;
                std::size_t max_keccak_blocks;

                static table_params get_minimal_requirements(
                    std::size_t max_bytecode_size, std::size_t max_keccak_blocks) {
                    return {.witnesses = 15,
                            .public_inputs = 1,
                            .constants = 10,
                            .rows = max_bytecode_size + max_keccak_blocks};
                }

                static void allocate_public_inputs(context_type &context,
                                                   input_type &input,
                                                   std::size_t max_bytecode_size,
                                                   std::size_t max_keccak_blocks) {
                    context.allocate(input.rlc_challenge, 0, 0,
                                     column_type::public_input);
                }

                bytecode(context_type &context_object, input_type input,
                         std::size_t max_bytecode_size_, std::size_t max_keccak_blocks_)
                    : max_bytecode_size(max_bytecode_size_),
                      max_keccak_blocks(max_keccak_blocks_),
                      generic_component<FieldType, stage>(context_object) {
                    std::vector<std::size_t> bytecode_lookup_area = {0, 1, 2, 3, 4, 5};
                    std::vector<std::size_t> keccak_lookup_area = {0, 1, 2, 3};
                    context_type bytecode_ct = context_object.subcontext(
                        bytecode_lookup_area, 0, max_bytecode_size);
                    context_type keccak_ct =
                        context_object.subcontext(keccak_lookup_area, max_bytecode_size,
                                                  max_bytecode_size + max_keccak_blocks);

                    BytecodeTable bc_t(bytecode_ct, input.bytecodes, max_bytecode_size);
                    KeccakTable(keccak_ct, {input.rlc_challenge, input.keccak_buffers},
                                max_keccak_blocks);

                    const std::vector<TYPE> &tag = bc_t.tag;
                    const std::vector<TYPE> &index = bc_t.index;
                    const std::vector<TYPE> &value = bc_t.value;
                    const std::vector<TYPE> &is_opcode = bc_t.is_opcode;
                    const std::vector<TYPE> &hash_hi = bc_t.hash_hi;
                    const std::vector<TYPE> &hash_lo = bc_t.hash_lo;
                    std::vector<TYPE> rlc_challenge(
                        max_bytecode_size);  // RLC challenge per row
                    std::vector<TYPE> push_size(
                        max_bytecode_size);  // Tracks PUSH operation size
                    std::vector<TYPE> length_left(
                        max_bytecode_size);  // Remaining length of bytecode
                    std::vector<TYPE> value_rlc(
                        max_bytecode_size);  // RLC of bytecode values
                    std::vector<TYPE> is_byte(
                        max_bytecode_size);  // Flags if row is a byte

                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        std::size_t cur = 0;
                        const auto &bytecodes = input.bytecodes.get_data();
                        for (std::size_t i = 0; i < bytecodes.size(); i++) {
                            TYPE push_size_value = 0;
                            auto buffer = bytecodes[i].first;
                            TYPE length_left_value = buffer.size();

                            // HEADER
                            rlc_challenge[cur] = input.rlc_challenge;
                            push_size[cur] = 0;
                            length_left[cur] = length_left_value;
                            value_rlc[cur] = length_left_value;
                            is_byte[cur] = tag[cur] * (3 - tag[cur]) * TYPE(2).inversed();
                            push_size_value = 0;
                            length_left_value--;
                            cur++;

                            // BYTES
                            for (std::size_t j = 0; j < bytecodes[i].first.size();
                                 j++, cur++) {
                                auto byte = buffer[j];
                                if (push_size_value == 0) {
                                    if (byte > 0x5f && byte < 0x80)
                                        push_size_value = byte - 0x5f;  // Set PUSH size
                                } else {
                                    push_size_value--;
                                }
                                is_byte[cur] =
                                    tag[cur] * (3 - tag[cur]) * TYPE(2).inversed();
                                push_size[cur] = push_size_value;
                                rlc_challenge[cur] = input.rlc_challenge;
                                length_left[cur] = length_left_value;
                                value_rlc[cur] =
                                    value_rlc[cur - 1] * input.rlc_challenge + byte;
                                length_left_value--;
                            }
                        }
                    }

                    // Allocate columns that are not part of  the bytecode_table
                    for (std::size_t i = 0; i < max_bytecode_size; i++) {
                        allocate(push_size[i], 6, i);
                        allocate(value_rlc[i], 7, i);
                        allocate(length_left[i], 8, i);
                        allocate(rlc_challenge[i], 9, i);
                        allocate(is_byte[i], 10, i);
                    }

                    static const auto zerohash = zkevm_keccak_hash({});
                    if constexpr (stage == GenerationStage::CONSTRAINTS) {
                        std::vector<TYPE> every;
                        std::vector<TYPE> non_first;
                        std::vector<TYPE> bytes;

                        // Every constraints
                        // 0. TAG is zeroes, one or two
                        every.push_back(context_object.relativize(
                            tag[0] * (tag[0] - 1) * (tag[0] - 2), -1));
                        // 1. INDEX for HEADER and unused bytes is zero
                        every.push_back(context_object.relativize(
                            (tag[0] - 2) * (tag[0] - 1) * index[0], -1));
                        // 4. In contract header length_left == contract length
                        every.push_back(context_object.relativize(
                            (tag[0] - 2) * (tag[0] - 1) * (length_left[0] - value[0]),
                            -1));
                        // 7. is_opcode is zeroes or ones
                        every.push_back(context_object.relativize(
                            is_opcode[0] * (is_opcode[0] - 1), -1));
                        // 8. is_opcode on HEADER are zeroes
                        every.push_back(context_object.relativize(
                            (tag[0] - 2) * (tag[0] - 1) * is_opcode[0], -1));
                        // 14. value_rlc for HEADERS == length_left
                        every.push_back(context_object.relativize(
                            (tag[0] - 2) * (tag[0] - 1) * (value_rlc[0] - length_left[0]),
                            -1));

                        // Non-first row constraints
                        // 2. INDEX for first contract byte is zero
                        non_first.push_back(context_object.relativize(
                            (tag[0] - 2) * (tag[0] - 1) * index[1], -1));
                        // 3. INDEX is incremented for all bytes
                        non_first.push_back(context_object.relativize(
                            tag[0] * tag[1] * (index[1] - index[0] - 1), -1));
                        // 5. In contract bytes each row decrement length_left
                        non_first.push_back(context_object.relativize(
                            tag[1] * (length_left[0] - length_left[1] - 1), -1));
                        // 6. Length_left is zero for last byte in the contract
                        non_first.push_back(context_object.relativize(
                            tag[0] * (tag[1] - 2) * (tag[1] - 1) * length_left[0], -1));
                        // 9. First is_opcode on BYTE after HEADER is 1
                        non_first.push_back(context_object.relativize(
                            (tag[1] - 2) * (tag[0] - 1) * tag[1] * (is_opcode[1] - 1),
                            -1));
                        // 10. PUSH_SIZE decreases for non-opcodes except metadata
                        non_first.push_back(context_object.relativize(
                            (tag[1] - 2) * tag[1] * (is_opcode[1] - 1) *
                                (push_size[0] - push_size[1] - 1),
                            -1));
                        // 11. before opcode push_size is always zero
                        non_first.push_back(
                            context_object.relativize(is_opcode[1] * push_size[0], -1));
                        // 12. for all bytes hash is similar to previous
                        non_first.push_back(context_object.relativize(
                            tag[1] * (hash_hi[0] - hash_hi[1]), -1));
                        // 13. for all bytes hash is similar to previous
                        non_first.push_back(context_object.relativize(
                            tag[1] * (hash_lo[0] - hash_lo[1]), -1));
                        // 15. for all bytes RLC is correct
                        non_first.push_back(context_object.relativize(
                            tag[1] * (value_rlc[1] - value_rlc[0] * rlc_challenge[1] -
                                      value[1]),
                            -1));
                        // 16. for each BYTEs rlc_challenge are similar
                        non_first.push_back(context_object.relativize(
                            tag[1] * (rlc_challenge[1] - rlc_challenge[0]), -1));

                        // Bytes constraint
                        // 17. rlc_challenge is similar for different contracts
                        bytes.push_back(context_object.relativize(
                            tag[2] * (rlc_challenge[1] - rlc_challenge[0]), -1));

                        // Apply constraints
                        for (std::size_t i = 0; i < every.size(); i++) {
                            context_object.relative_constrain(every[i], 0,
                                                              max_bytecode_size - 1);
                        }
                        for (std::size_t i = 0; i < non_first.size(); i++) {
                            context_object.relative_constrain(non_first[i], 1,
                                                              max_bytecode_size - 1);
                        }
                        for (std::size_t i = 0; i < bytes.size(); i++) {
                            context_object.relative_constrain(bytes[i], 1,
                                                              max_bytecode_size - 2);
                        }

                        // Lookups
                        std::vector<TYPE> tmp = {context_object.relativize(
                            tag[0] * value[0] * (2 - tag[0]), -1)};
                        context_object.relative_lookup(tmp, "byte_range_table/full", 0,
                                                       max_bytecode_size - 1);
                        tmp = {context_object.relativize(
                            std::vector<TYPE>({value[0] * is_opcode[0],
                                               push_size[0] * is_opcode[0],
                                               is_opcode[0]}),
                            -1)};
                        context_object.relative_lookup(tmp, "zkevm_opcodes/full", 0,
                                                       max_bytecode_size - 1);
                        tmp = {context_object.relativize(
                            std::vector<TYPE>(
                                {tag[1] + 1 - tag[1],
                                 is_byte[0] * (1 - is_byte[1]) * value_rlc[0],
                                 is_byte[0] * (1 - is_byte[1]) * hash_hi[0] +
                                     (1 - is_byte[0] * (1 - is_byte[1])) *
                                         w_hi<FieldType>(zerohash),
                                 is_byte[0] * (1 - is_byte[1]) * hash_lo[0] +
                                     (1 - is_byte[0] * (1 - is_byte[1])) *
                                         w_lo<FieldType>(zerohash)}),
                            -1)};
                        context_object.relative_lookup(tmp, "keccak_table", 1,
                                                       max_bytecode_size - 1);
                    }
                };
            };
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil
