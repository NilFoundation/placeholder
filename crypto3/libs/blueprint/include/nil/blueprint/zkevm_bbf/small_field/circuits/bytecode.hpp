//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#include <nil/blueprint/zkevm_bbf/types/opcode_enum.hpp>
#include <nil/blueprint/zkevm_bbf/types/hashed_buffers.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/tables/bytecode.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/tables/bytecode_hash.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/tables/keccak.hpp>

namespace nil::blueprint::bbf::zkevm_small_field{
    template<typename FieldType, GenerationStage stage>
    class bytecode : public generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

        using BytecodeTable = bytecode_table<FieldType,stage>;
        using KeccakTable = keccak_table<FieldType,stage>;
        using BytecodeHashTable = bytecode_hash_table<FieldType, stage>;

    public:
        using typename generic_component<FieldType, stage>::table_params;
        using typename generic_component<FieldType,stage>::TYPE;

        struct input_type {
            TYPE rlc_challenge;

            BytecodeTable::input_type bytecodes;
            KeccakTable::private_input_type keccak_buffers;
        };

        std::size_t max_bytecode_size;
        std::size_t max_keccak_blocks;
        std::size_t max_bytecodes_amount;

        static table_params get_minimal_requirements(
            std::size_t max_bytecode_size,
            std::size_t max_keccak_blocks,
            std::size_t max_bytecodes_amount
        ) {
            BOOST_ASSERT(max_bytecode_size > max_keccak_blocks + max_bytecodes_amount);
            return {
                .witnesses = BytecodeTable::get_witness_amount() + std::max(KeccakTable::get_witness_amount(), BytecodeHashTable::get_witness_amount()) + 16,
                .public_inputs = 1,
                .constants = 10,
                .rows = max_bytecode_size
            };
        }

        static void allocate_public_inputs(
            context_type &context, input_type &input,
            std::size_t max_bytecode_size,
            std::size_t max_keccak_blocks,
            std::size_t max_bytecodes_amount
        ) {
            context.allocate(input.rlc_challenge, 0, 0, column_type::public_input);
        }

        bytecode(context_type &context_object,
            input_type input,
            std::size_t max_bytecode_size_,
            std::size_t max_keccak_blocks_,
            std::size_t max_bytecodes_amount_
        ) : max_bytecode_size(max_bytecode_size_),
            max_keccak_blocks(max_keccak_blocks_),
            max_bytecodes_amount(max_bytecodes_amount_),
            generic_component<FieldType,stage>(context_object)
        {
            BOOST_LOG_TRIVIAL(trace) << "Small field bytecode circuit assignment" << std::endl;

            std::size_t current_column = 0;
            std::vector<std::size_t> bytecode_lookup_area;
            for( std::size_t i = 0; i < BytecodeTable::get_witness_amount(); i++){
                bytecode_lookup_area.push_back(current_column++);
            }
            context_type bytecode_ct = context_object.subcontext(bytecode_lookup_area,0,max_bytecode_size);
            BytecodeTable bc_t(bytecode_ct, input.bytecodes, max_bytecode_size);

            std::size_t bytecode_hash_column = current_column;
            std::vector<std::size_t> bytecode_hash_lookup_area;
            for( std::size_t i = 0; i < BytecodeHashTable::get_witness_amount(); i++){
                bytecode_hash_lookup_area.push_back(bytecode_hash_column++);
            }
            context_type bytecode_hash_ct = context_object.subcontext(bytecode_hash_lookup_area,0,max_bytecodes_amount);
            BytecodeHashTable bytecode_hash_t(bytecode_hash_ct, input.bytecodes, max_bytecodes_amount);

            std::size_t keccak_column = current_column;
            std::vector<std::size_t> keccak_lookup_area;
            for( std::size_t i = 0; i < KeccakTable::get_witness_amount(); i++){
                keccak_lookup_area.push_back(keccak_column++);
            }
            context_type keccak_ct = context_object.subcontext(keccak_lookup_area,max_bytecodes_amount,max_keccak_blocks);
            KeccakTable keccak_t(keccak_ct, {input.rlc_challenge, input.keccak_buffers}, max_keccak_blocks);

            const std::vector<TYPE> &tag = bc_t.tag;
            const std::vector<TYPE> &index = bc_t.index;
            const std::vector<TYPE> &value = bc_t.value;
            const std::vector<TYPE> &is_opcode = bc_t.is_opcode;
            const std::vector<TYPE> &bytecode_id = bc_t.bytecode_id;
            std::vector<TYPE> rlc_challenge(max_bytecode_size);
            std::vector<TYPE> push_size(max_bytecode_size);
            std::vector<TYPE> length_left(max_bytecode_size);
            std::vector<TYPE> metadata_count(max_bytecode_size);
            std::vector<TYPE> value_rlc(max_bytecode_size);
            std::vector<TYPE> is_header(max_bytecode_size);
            std::vector<TYPE> is_executed(max_bytecode_size);
            std::vector<TYPE> is_metadata(max_bytecode_size);
            std::vector<TYPE> hash_value_rlc(max_bytecodes_amount);
            std::vector<TYPE> is_last_byte(max_bytecode_size);

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                const auto &bytecodes = input.bytecodes.get_data();
                std::size_t cur = 0;

                for(std::size_t i = 0; i < bytecodes.size(); i++) {
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
                                buffer[boundary] == 0xf3)
                            ) {
                                exec_boundary = boundary + 1;  // Set boundary after the stopping opcode
                            }
                        }
                    }
                    BOOST_LOG_TRIVIAL(trace) << "Bytecode " << i << " size = " << total_len;
                    BOOST_LOG_TRIVIAL(trace) << "Executable bytes boundary: " << exec_boundary;

                    // Header
                    length_left[cur] = total_len;
                    metadata_count[cur] = 0;
                    value_rlc[cur] = total_len;
                    is_header[cur] = 1;
                    rlc_challenge[cur] = input.rlc_challenge;
                    cur++;

                    // Bytes
                    std::size_t push_size_value = 0;
                    for(std::size_t j = 0; j < buffer.size(); j++, cur++){
                        length_left[cur] = length_left[cur - 1] - 1;
                        if( j < exec_boundary ){
                            metadata_count[cur] = 0;
                            is_executed[cur] = 1;
                        } else {
                            metadata_count[cur] = metadata_count[cur - 1] + 1;
                            is_metadata[cur] = 1;
                        }
                        auto byte = buffer[j];
                        if (push_size_value == 0) {
                            if (byte > 0x5f && byte < 0x80)  push_size_value = byte - 0x5f;  // Set PUSH size
                        } else {
                            push_size_value--;
                        }
                        push_size[cur] = push_size_value;
                        rlc_challenge[cur] = input.rlc_challenge;
                        value_rlc[cur] = value_rlc[cur - 1] * input.rlc_challenge + byte;
                        if( is_opcode[cur] == 1 )
                            BOOST_LOG_TRIVIAL(trace) << cur << ". " << std::hex << index[cur] << " " << opcode_from_number(byte);
                        else if (is_executed[cur] == 1)
                            BOOST_LOG_TRIVIAL(trace) << cur << ". " << std::hex << index[cur] << " Data  0x" << std::setw(2) << std::setfill('0') << std::size_t(byte) << std::dec;
                        else
                            BOOST_LOG_TRIVIAL(trace) << cur << ". " << std::hex << index[cur] << " Metadata 0x" << std::setw(2) << std::setfill('0') << std::size_t(byte) << std::dec;
                    }
                    is_last_byte[cur - 1] = 1;
                    hash_value_rlc[i] = value_rlc[cur - 1];
                 }
            }

            std::size_t is_last_byte_index = 0;
            std::size_t index_index = bytecode_lookup_area[1];
            std::size_t bytecode_id_index = bytecode_lookup_area[4];
            std::size_t value_rlc_index = bytecode_lookup_area[5];
            std::size_t last_column = 0;
            for( std::size_t i = 0; i < max_bytecode_size; i++ ){
                current_column = BytecodeTable::get_witness_amount() + std::max(KeccakTable::get_witness_amount(), BytecodeHashTable::get_witness_amount());
                allocate(length_left[i], current_column++, i);
                allocate(metadata_count[i], current_column++, i);
                value_rlc_index = current_column; allocate(value_rlc[i], current_column++, i);
                allocate(push_size[i], current_column++, i);
                allocate(rlc_challenge[i], current_column++, i);
                allocate(is_header[i], current_column++, i);
                allocate(is_executed[i], current_column++, i);
                allocate(is_metadata[i], current_column++, i);
                is_last_byte_index = current_column; allocate(is_last_byte[i], current_column++, i);
                last_column = current_column;
            }
            for( std::size_t i = 0; i < max_bytecodes_amount; i++ ){
                allocate(hash_value_rlc[i], last_column, i);
            }

            constrain(bytecode_id[0] - 1);
            constrain(is_header[0] - 1);
            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                std::vector<TYPE> every_row_constraints;
                std::vector<TYPE> non_first_row_constraints;

                // 0. Dynamic selectors may be only 0 or 1
                every_row_constraints.push_back(is_header[1] * (is_header[1] - 1));
                every_row_constraints.push_back(is_executed[1] * (is_executed[1] - 1));
                every_row_constraints.push_back(is_metadata[1] * (is_metadata[1] - 1));
                // 1. Only one of them may be 1 on a row
                TYPE is_filled = is_header[1] + is_executed[1] + is_metadata[1];
                TYPE is_padding = 1 - is_filled;
                every_row_constraints.push_back(is_filled * (is_filled -1));
                // 2. TAG is zeroes, one, two or three
                //      0 -- padding
                //      1 -- HEADER
                //      2 -- BYTE
                //      3 -- METADATA
                every_row_constraints.push_back(tag[1] - is_header[1] * 1 - is_executed[1] * 2 - is_metadata[1] * 3);
                // 3. For HEADER index is 0
                every_row_constraints.push_back(is_header[1] * index[1]);
                // 4. In contract header length_left == contract length
                every_row_constraints.push_back(is_header[1] * (length_left[1] - value[1]));
                // 5. is_opcode is zeroes or ones
                every_row_constraints.push_back(is_opcode[1] * (is_opcode[1] - 1));
                // 6. is_opcode on HEADER are zeroes
                every_row_constraints.push_back(is_header[1] * is_opcode[1]);
                // 7. value_rlc for HEADERS == length_left
                every_row_constraints.push_back(is_header[1] * (value_rlc[1] - length_left[1]));

                // 8. INDEX for first contract byte is zero
                non_first_row_constraints.push_back(is_header[0] * index[1]);
                // 9. INDEX is incremented for all bytes
                non_first_row_constraints.push_back((1 - is_header[0]) * (is_executed[1] + is_metadata[1]) * (index[1] - index[0] - 1));
                // 10. Length_left is zero for last byte in the contract
                non_first_row_constraints.push_back(is_last_byte[1] * length_left[1]);
                // 11. First is_opcode on BYTE after HEADER is 1
                non_first_row_constraints.push_back(is_header[0] * is_executed[1] * (is_opcode[1] - 1));
                // 12. PUSH_SIZE decreases for non-opcodes except metadata
                non_first_row_constraints.push_back(is_executed[1] * (1 - is_opcode[1]) * (push_size[0] - push_size[1] - 1)); // Append tag_selectors
                // 13. before opcode push_size is always zero
                non_first_row_constraints.push_back(is_opcode[1] * push_size[0]);
                // 14. for all bytes bytecode_id is similar to previous
                non_first_row_constraints.push_back((is_executed[1] + is_metadata[1]) * (bytecode_id[0] - bytecode_id[1]));
                // 15. for all bytes RLC is correct
                non_first_row_constraints.push_back((is_executed[1] + is_metadata[1]) * (value_rlc[1] - value_rlc[0] * rlc_challenge[1] - value[1]));
                // 16. for each BYTEs rlc_challenge are similar
                non_first_row_constraints.push_back(is_filled * (rlc_challenge[1] - rlc_challenge[0]));
                // 17. is_last_byte is correctly defined
                non_first_row_constraints.push_back(is_last_byte[0] - (is_header[1] + is_padding) * (is_metadata[0] + is_executed[0]));
                // 18. bytecode_id increased for each bytecode
                non_first_row_constraints.push_back(is_header[1] * (bytecode_id[1] - bytecode_id[0] - 1));
                // 19. After metadata is metadata or padding
                non_first_row_constraints.push_back(is_metadata[0] * (is_metadata[1] + is_padding - 1));
                // 20. If metadata, is_opcode = 0
                every_row_constraints.push_back(is_metadata[1] * is_opcode[1]);
                // 21. Metadata_count does not change if is_executed
                non_first_row_constraints.push_back((is_executed[1]) * (metadata_count[1] - metadata_count[0]));
                // 22. Metadata count inrement by 1 for metadata
                non_first_row_constraints.push_back(is_metadata[1] * (metadata_count[1] - metadata_count[0] - 1));
                // 24. Metadata count is equal to last 2 metadata bytes
                non_first_row_constraints.push_back(is_last_byte[1] * metadata_count[1] * (value[1] + value[0] * 256 - metadata_count[1] + 2));
                // 25 Length left decrease by 1 if not padding
                non_first_row_constraints.push_back((length_left[0] - length_left[1] - 1) * (is_executed[1] + is_metadata[1]));
                // 26. After padding is always padding
                every_row_constraints.push_back(is_padding * (is_header[2] + is_executed[2] + is_metadata[2]));
                // 27. Last is always padding
                constrain(is_header[max_bytecode_size - 1] + is_executed[max_bytecode_size - 1] + is_metadata[max_bytecode_size - 1]);

                // Lookup_table
                BOOST_LOG_TRIVIAL(trace) << "zkevm_bytecode_data_with_rlc "
                    << is_last_byte_index << " "
                    << bytecode_id_index << " "
                    << index_index << " "
                    << value_rlc_index;
                context_object.lookup_table("zkevm_bytecode_data_with_rlc", {
                    is_last_byte_index,
                    bytecode_id_index,
                    index_index,
                    value_rlc_index,
                }, 0, max_bytecode_size-1);

                for( auto& constraint: every_row_constraints){
                    context_object.relative_constrain(context_object.relativize(constraint, -1), 0, max_bytecode_size-1);
                }
                for( auto &constraint: non_first_row_constraints ){
                    context_object.relative_constrain(context_object.relativize(constraint, -1), 1, max_bytecode_size - 1);
                }
                // Lookups
                std::vector<TYPE> tmp = {(is_executed[1] + is_metadata[1]) * value[1]};
                context_object.relative_lookup(context_object.relativize(tmp, -1), "byte_range_table/full", 0,  max_bytecode_size);

                tmp = {
                    value[1] * is_opcode[1],
                    push_size[1] * is_opcode[1],
                    is_opcode[1]
                };
                context_object.relative_lookup(context_object.relativize(tmp, -1), "zkevm_opcodes/full", 0, max_bytecode_size);

                tmp = {
                    is_last_byte[1],
                    is_last_byte[1] * bytecode_id[1],
                    is_last_byte[1] * (index[1] + 1),
                };
                context_object.relative_lookup(context_object.relativize(tmp, -1), "zkevm_bytecode_hash", 0, max_bytecode_size);

                tmp = {
                    bytecode_hash_t.tag[1],
                    bytecode_hash_t.tag[1] * bytecode_hash_t.bytecode_id[1],
                    bytecode_hash_t.tag[1] * (bytecode_hash_t.bytecode_size[1] - 1),
                    bytecode_hash_t.tag[1] * hash_value_rlc[1],
                };
                context_object.relative_lookup(context_object.relativize(tmp, -1), "zkevm_bytecode_data_with_rlc", 0, max_bytecodes_amount-1);

                tmp = {
                    hash_value_rlc[1]
                };
                for( std::size_t i = 0; i < 16; i++){
                    tmp.push_back(bytecode_hash_t.bytecode_hash[1][i]);
                }
                context_object.relative_lookup(context_object.relativize(tmp, -1), "keccak_table", 0, max_bytecodes_amount-1);
            }
        };
    };
}