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

    size_t max_bytecode_size;
    size_t max_keccak_blocks;
    size_t max_bytecodes_amount;

    static table_params get_minimal_requirements(
            size_t max_bytecode_size,
            size_t max_keccak_blocks,
            size_t max_bytecodes_amount) {
        BOOST_ASSERT(max_bytecode_size > max_keccak_blocks + max_bytecodes_amount);
        return {
            .witnesses = BytecodeTable::get_witness_amount() + std::max(KeccakTable::get_witness_amount(), BytecodeHashTable::get_witness_amount()) + 16,
            .public_inputs = 1,
            .constants = 10,
            .rows = max_bytecode_size
        };
    }

    static void allocate_public_inputs(
            context_type &context,
            input_type &input,
            size_t max_bytecode_size,
            size_t max_keccak_blocks,
            size_t max_bytecodes_amount) {
        context.allocate(input.rlc_challenge, 0, 0, column_type::public_input);
    }

    bytecode(context_type &context_object, input_type input,
             size_t max_bytecode_size_, size_t max_keccak_blocks_,
             size_t max_bytecodes_amount_)
        : max_bytecode_size(max_bytecode_size_),
          max_keccak_blocks(max_keccak_blocks_),
          max_bytecodes_amount(max_bytecodes_amount_),
          generic_component<FieldType,stage>(context_object) {
        BOOST_LOG_TRIVIAL(trace) << "Small field bytecode circuit assignment" << std::endl;

        size_t current_column = 0;
        std::vector<size_t> bytecode_lookup_area;
        for (size_t i = 0; i < BytecodeTable::get_witness_amount(); ++i) {
            bytecode_lookup_area.push_back(current_column++);
        }
        context_type bytecode_ct = context_object.subcontext(bytecode_lookup_area,0,max_bytecode_size);
        BytecodeTable bc_t(bytecode_ct, input.bytecodes, max_bytecode_size);

        size_t bytecode_hash_column = current_column;
        std::vector<size_t> bytecode_hash_lookup_area;
        for (size_t i = 0; i < BytecodeHashTable::get_witness_amount(); ++i) {
            bytecode_hash_lookup_area.push_back(bytecode_hash_column++);
        }
        context_type bytecode_hash_ct = context_object.subcontext(bytecode_hash_lookup_area,0,max_bytecodes_amount);
        BytecodeHashTable bytecode_hash_t(bytecode_hash_ct, input.bytecodes, max_bytecodes_amount);

        size_t keccak_column = current_column;
        std::vector<size_t> keccak_lookup_area;
        for (size_t i = 0; i < KeccakTable::get_witness_amount(); ++i) {
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
        std::vector<TYPE> length(max_bytecode_size);
        std::vector<TYPE> push_size(max_bytecode_size);
        std::vector<TYPE> is_padding(max_bytecode_size);
        std::vector<TYPE> value_rlc(max_bytecode_size);
        std::vector<TYPE> hash_value_rlc(max_bytecodes_amount);
        std::vector<TYPE> is_last_byte(max_bytecode_size);

        if constexpr (stage == GenerationStage::ASSIGNMENT) {
            rlc_challenge.assign(max_bytecode_size, input.rlc_challenge);

            const auto &bytecodes = input.bytecodes.get_data();
            size_t row = 0;

            for (size_t i = 0; i < bytecodes.size(); ++i) {
                const auto &buffer = bytecodes[i].first;
                BOOST_LOG_TRIVIAL(trace) << "Bytecode " << i << " size = " << buffer.size();

                // Header
                length_left[row] = total_len;
                value_rlc[row] = total_len;
                is_header[row] = 1;
                ++row;

                // Bytes
                size_t push_size_value = 0;
                for(size_t j = 0; j < buffer.size(); j++, cur++){
                    length_left[cur] = length_left[cur - 1] - 1;
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
                        BOOST_LOG_TRIVIAL(trace) << cur << ". " << std::hex << index[cur] << " Data  0x" << std::setw(2) << std::setfill('0') << size_t(byte) << std::dec;
                    else
                        BOOST_LOG_TRIVIAL(trace) << cur << ". " << std::hex << index[cur] << " Metadata 0x" << std::setw(2) << std::setfill('0') << size_t(byte) << std::dec;
                }
                is_last_byte[cur - 1] = 1;
                hash_value_rlc[i] = value_rlc[cur - 1];
             }
        }

        size_t is_last_byte_index = 0;
        size_t index_index = bytecode_lookup_area[1];
        size_t bytecode_id_index = bytecode_lookup_area[4];
        size_t value_rlc_index = bytecode_lookup_area[5];
        size_t last_column = 0;
        for( size_t i = 0; i < max_bytecode_size; i++ ){
            current_column = BytecodeTable::get_witness_amount() + std::max(KeccakTable::get_witness_amount(), BytecodeHashTable::get_witness_amount());
            allocate(length_left[i], current_column++, i);
            value_rlc_index = current_column; allocate(value_rlc[i], current_column++, i);
            allocate(push_size[i], current_column++, i);
            allocate(rlc_challenge[i], current_column++, i);
            is_last_byte_index = current_column; allocate(is_last_byte[i], current_column++, i);
            last_column = current_column;
        }
        for( size_t i = 0; i < max_bytecodes_amount; i++ ){
            allocate(hash_value_rlc[i], last_column, i);
        }

        if constexpr (stage == GenerationStage::CONSTRAINTS) {
            TYPE zero_constant = 0;
            TYPE one_constant = 1;
            allocate(zero_constant, 0, 0, column_type::constant);
            allocate(one_constant, 0, 1, column_type::constant);

            // A header for empty block is hardcoded in the last row: it makes
            // it impossible to avoid the hash lookup for the last block by
            // making it so long, that its last byte is outside of table bounds.
            copy_constrain(tag.back(), zero_constant);
            copy_constrain(length.back(), zero_constant);

            auto constrain_rows = [&](TYPE c, const std::string &name = "") {
                auto [has_vars, min_row, max_row] =
                    nil::crypto3::zk::snark::expression_row_range_visitor<TYPE>::row_range(c);
                BOOST_ASSERT(min_row < 2 && 1 <= max_row && max_row <= 2);
                auto c_rel = context_object.relativize(c, -1);
                auto first = min_row == 1 ? 0 : 1;
                auto last = max_row == 1 ? max_bytecode_size - 1 : max_bytecode_size - 2;
                context_object.relative_constrain(c_rel, first, last, name);
            }

            // RLC challenge correctness:
            copy_constrain(rlc_challenge[0], input.rlc_challenge);
            constrain_rows(rlc_challenge[1] - rlc_challenge[0], "RLC challenge");

            // Tag is 0 for headers and 1 for byte rows.
            constrain_rows(tag[1] * (tag[1] - 1), "tag is 0 or 1");

            // First row must be a header: else, it would be possible to replace
            // the first bytecode with its suffix, since checks for the initial
            // values of index and rlc_value are done on header lines.
            copy_constrain(tag[0], zero_constant);

            // 14. for all bytes bytecode_id is similar to previous
            non_first_row_constraints.push_back((is_executed[1] + is_metadata[1]) * (bytecode_id[0] - bytecode_id[1]));
            // Index is 0 in headers, it allows accumulated length computation.
            constrain_rows((1 - tag[1]) * index[1], "header index is 0");
            // For bytes, index values start from 0 and increment sequentially.
            constrain_rows((1 - tag[0]) * index[1] +
                           tag[1] * tag[0] * (index[1] - (index[0] + 1)),
                           "byte index definition");
            // Note that we can skip tag[1] factor in the first part, since
            // index is 0 in headers anyway.

            // For bytes, buffer id and length are same as in header.
            constrain_rows(tag[1] * (bytecode_id[1] - bytecode_id[0]),
                           "bytecode_id validilty for bytes");
            constrain_rows(tag[1] * (length[1] - length[0]),
                           "length validity for bytes");

            // In headers, RLC is reset to bytecode length and then accumulates
            // byte values.
            constrain_rows((1 - tag[1]) * (value_rlc[1] - length[1]) +
                           tag[1] * (value_rlc[1] -
                                     (value_rlc[0] * rlc_challenge[1] + value[1])),
                           "value RLC definition");

            // Push size is set to non-zero value at push opcodes, this is
            // controlled by a lookup below. After that, it must go all the way
            // to zero.
            constrain_rows(push_size[0] * (push_size[1] - (push_size[0] - 1)),
                           "push size decreases to zero");
            // Opcodes are all the bytes that are not used as push arguments,
            constrain_rows(is_opcode[1] - tag[1] * (1 - push_size[0] * push_size_inv[0]),
                           "opcode definition");
            constrain_rows(push_size[1] * (1 - push_size[1] * push_size_inv[1]),
                           "push_size_inv definition");
            // and it also works for the first byte if push size is zero in headers.
            constrain_rows((1 - tag[1]) * push_size[1], "push size is 0 in header");
            // Yep, this is mutual recursion.
            // Under this constraints, first row (a header) could be marked as an opcode,
            // but it does not matter actually: push size is fixed as 0 for headers!

            // Finally, bytecode_end marks a row where RLC is finalized, either
            // header row of an empty bytecode, or last (explicit) byte otherwise.
            TYPE length_diff = length[1] - (tag[1] + index[1]);
            constrain_rows(length_diff * (1 - length_diff * bytecode_end_witness[1]),
                           "witness for bytecode end condition");
            TYPE is_bytecode_end = 1 - length_diff * bytecode_end_witness[1];

            // After bytecode ends, there are padding zeros: potentially
            // missing push arguments and implicitly defined STOP opcode.
            copy_constrain(is_padding[0], zero_constant);
            TYPE prev_length_diff = length[0] - (tag[0] + index[0]);
            TYPE prev_is_end = 1 - prev_length__diff * bytecode_end_witness[0];
            constrain_rows(is_padding[1] - tag[1] * (prev_is_end + is_padding[0]),
                           "padding definition");
            constrain_rows(is_padding[1] * value, "padding bytes are 0s");

            // We need to make sure that if a bytecode is present in the table,
            // it's hash is checked, i.e. it reaches its last byte.
            // We do this by checking for padding row before new bytecode
            // starts and at the end of the table; if there is a padding row,
            // there must be the bytecode end row before too.
            // Note that we do not require all potentially used padding bytes
            // to be present: it's ok if lookup fails with malformed assignment,
            // we only care for false positive validity checks.
            constrain_rows((1 - tag[1]) * is_padding[0]);
            copy_constrain(is_padding.back(), one_constant);

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

            // Lookups
            std::vector<TYPE> tmp = {tag[1] * value[1]};
            context_object.relative_lookup(context_object.relativize(tmp, -1), "byte_range_table/full", 0,  max_bytecode_size);

            tmp = {
                is_bytecode_end[1],
                is_bytecode_end[1] * bytecode_id[1],
                is_bytecode_end[1] * (tag[1] + index[1]),
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
            for( size_t i = 0; i < 16; i++){
                tmp.push_back(bytecode_hash_t.bytecode_hash[1][i]);
            }
            context_object.relative_lookup(context_object.relativize(tmp, -1), "keccak_table", 0, max_bytecodes_amount-1);
        }
    };
};

}
