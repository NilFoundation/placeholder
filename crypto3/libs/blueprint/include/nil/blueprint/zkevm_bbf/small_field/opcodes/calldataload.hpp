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

#include <numeric>
#include <algorithm>

#include <nil/blueprint/zkevm_bbf/small_field/opcodes/abstract_opcode.hpp>

namespace nil::blueprint::bbf::zkevm_small_field{
    template<typename FieldType, GenerationStage stage>
    class zkevm_calldataload_bbf : generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;
    public:
        using typename generic_component<FieldType,stage>::TYPE;

        zkevm_calldataload_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state):
            generic_component<FieldType,stage>(context_object, false)
        {
            const std::size_t two_25 = 1 << 25;

            std::vector<TYPE> offset_chunks(16); // Offset
            std::array<TYPE, 32> bytes;          // Loaded valuem, split into two rows to decrease amount of rw_8_table lookups

            // Two similar values in different rows allows to decrease amount rw_8_table lookups twice
            TYPE need_lookup0, need_lookup1;     // Only if offset is < 2^25, similar values in different rowss
            TYPE offset0, offset1;               // Similar values in different rows

            TYPE subchunk_14_0, diff_14_0;
            TYPE subchunk_14_1, diff_14_1;
            TYPE high_chunks_sum;
            TYPE high_chunks_sum_inv;
            TYPE offset_in_range;

            // last_offset = offset+31
            TYPE last_offset_lo; // < 2^16
            TYPE last_offset_hi, diff_last_offset_hi; // < 2^9, diff_last_offset_hi = 0x1ff - last_offset_hi
            TYPE carry; // 0 or 1, offset = carry * 2^25 + last_offset_hi * 2^16 + last_offset_lo
            // need_lookup0 == need_lookup1 == offset_in_range * (1 - carry)

            if constexpr( stage == GenerationStage::ASSIGNMENT ){
                auto address_chunks = w_to_16(current_state.stack_top());

                // BOOST_LOG_TRIVIAL(trace) << "\tCALLEDATALOAD address: " << std::hex << current_state.stack_top() << std::dec;

                subchunk_14_0 = address_chunks[14] >> 9;
                subchunk_14_1 = address_chunks[14] & 0x1ff;

                diff_14_0 = 0x7f - subchunk_14_0;
                diff_14_1 = 0x1ff - subchunk_14_1;
                if( current_state.stack_top() <= two_25 - 1 ) {
                    offset_in_range = 1;
                }

                // Part of address that may be presented in rw_8_table.
                // If offset is not fit into 2^25, then need_lookup = 0 and gas_error should be next opcode
                std::size_t address = address_chunks[15] + (address_chunks[14] & 0x1ff) * 0x10000;
                offset0 = offset1 = address;

                std::size_t last_address = address + 31;
                last_offset_lo = last_address & 0xffff; // < 2^16
                last_offset_hi = (last_address >> 16) & 0x1ff; // < 2^9
                diff_last_offset_hi = 0x1ff - last_offset_hi; // < 2^9
                carry = (last_address >> 25); // 0 or 1

                if( current_state.stack_top() <= two_25 - 32 ) {
                    need_lookup0 = need_lookup1 = 1;
                }

                if( current_state.stack_top() <= two_25 - 32 ) {
                    for (std::size_t i = 0; i < 32; i++) {
                        bytes[i] = current_state.calldata(address + i);
                    }
                }
                for (std::size_t i = 0; i < 16; i++) {
                    offset_chunks[i] = address_chunks[i];
                }
                for (std::size_t i = 0; i < 14; i++){
                    high_chunks_sum += offset_chunks[i];
                }
                high_chunks_sum += subchunk_14_0;
                high_chunks_sum_inv = high_chunks_sum == 0? 0: high_chunks_sum.inversed();
                // BOOST_LOG_TRIVIAL(trace) << "\tneed_lookup = " << need_lookup0 <<
                //     " offset_in_range = " << offset_in_range <<
                //     " carry = " << carry ;
            }

            // Allocate bytes in two rows to prevent too much of lookup constraints to rw_table
            for (std::size_t i = 0; i < 16; i++) {
                allocate(offset_chunks[i], i, 0);
                allocate(bytes[i], i + 16, 0);
                allocate(bytes[i + 16], i + 16, 1);
            }
            allocate(subchunk_14_0, 0, 1);
            allocate(subchunk_14_1, 1, 1);
            allocate(diff_14_0, 2, 1);
            allocate(diff_14_1, 3, 1);

            allocate(last_offset_hi, 4, 1);
            allocate(diff_last_offset_hi, 5, 1);
            allocate(last_offset_lo, 6, 1);
            allocate(carry, 7, 1);

            allocate(offset0,32,0);
            allocate(offset1,32,1);
            allocate(need_lookup0, 33, 0);
            allocate(need_lookup1, 33, 1);
            allocate(high_chunks_sum, 34, 0);
            allocate(high_chunks_sum_inv, 35, 0);
            allocate(offset_in_range, 36, 0);

            TYPE high_chunks_sum_constraint;
            for( std::size_t i = 0; i < 14; i++ ){
                high_chunks_sum_constraint += offset_chunks[i];
            }
            high_chunks_sum_constraint += subchunk_14_0;

            constrain(high_chunks_sum_constraint - high_chunks_sum); // high_chunks_sum decomposition
            constrain(offset_in_range * (offset_in_range - 1)); // offset_in_range is 0 or 1
            constrain(high_chunks_sum * high_chunks_sum_inv - (1 - offset_in_range)); // high_chunks_sum_inv is 0 or 1
            constrain(offset_in_range * high_chunks_sum); // offset_in_range is 0 if high_chunks_sum is not
            constrain(offset_in_range * high_chunks_sum_inv); // offset_in_range is 0 high_chunks_sum_inv is not
            constrain(subchunk_14_0 + diff_14_0 - 0x7f);        // Range-check for subchunk_14_1
            constrain(subchunk_14_1 + diff_14_1 - 0x1ff);       // Range-check for subchunk_14_0
            constrain(subchunk_14_0 * 0x200 + subchunk_14_1 - offset_chunks[14]); // offset_chunks[14] decomposition
            constrain(offset_chunks[15] + subchunk_14_1 * 0x10000 - offset0);
            constrain(offset0 - offset1);

            constrain(carry * (carry - 1)); // carry is 0 or 1
            constrain(last_offset_lo + last_offset_hi * 0x10000 + carry * two_25 - offset0 - 31); // last_offset_lo = offset + 31
            constrain(last_offset_hi + diff_last_offset_hi - 0x1ff); // last_offset_hi + diff_last_offset_hi = 0x1ff
            constrain(need_lookup0 - offset_in_range * (1 - carry)); // need_lookup0 is 0 if offset is not in range
            constrain(need_lookup0 - need_lookup1);

            if constexpr( stage == GenerationStage::CONSTRAINTS ){
                constrain(current_state.pc_next() - current_state.pc(1) - 1);                                  // PC transition
                constrain(current_state.gas(1) - current_state.gas_next() - 3);                                // GAS transition
                constrain(current_state.stack_size_next() - current_state.stack_size(1));                      // stack_size transition
                constrain(current_state.memory_size(1) - current_state.memory_size_next());                    // memory_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(1) - 2 - 32 * need_lookup1);   // rw_counter transition

                // Read offset from stack
                lookup(rw_256_table<FieldType, stage>::stack_16_bit_lookup(
                    current_state.call_id(1),
                    current_state.stack_size(1) - 1,
                    current_state.rw_counter(1),
                    TYPE(0),                                               // is_write
                    offset_chunks
                ), "zkevm_rw_256");

                // Read 32 bytes from calldata
                TYPE no_need_lookup_constraint;
                for( std::size_t i = 0; i < 32; i++ ){
                    no_need_lookup_constraint += bytes[i];
                    if( i < 16 ){
                        std::vector<TYPE> tmp = rw_8_table<FieldType, stage>::calldata_r_lookup(
                            current_state.call_id(0),
                            offset0 + i,
                            current_state.rw_counter(0) + i + 1,
                            bytes[i]
                        );
                        for( std::size_t j = 0; j < tmp.size(); j++) tmp[j] = tmp[j] * need_lookup0;
                        lookup(tmp, "zkevm_rw_8");
                    } else {
                        std::vector<TYPE> tmp = rw_8_table<FieldType, stage>::calldata_r_lookup(
                            (current_state.call_id(1)),
                            (offset1 + i),
                            (current_state.rw_counter(1) + i + 1),
                            (bytes[i])
                        );
                        for( std::size_t j = 0; j < tmp.size(); j++) tmp[j] = tmp[j] * need_lookup1;
                        lookup(tmp, "zkevm_rw_8");
                    }
                }
                // constrain((1 - need_lookup0) * no_need_lookup_constraint); // if need_lookup is 0, then all high bytes are 0

                // Write result to stack
                lookup(rw_256_table<FieldType, stage>::stack_8_bit_lookup(
                    current_state.call_id(1),
                    current_state.stack_size(1) - 1,
                    current_state.rw_counter(1) + 1 + need_lookup1 * 32,
                    TYPE(1),                                               // is_write
                    bytes
                ), "zkevm_rw_256");
            }
        }
    };

    template<typename FieldType>
    class zkevm_calldataload_operation : public opcode_abstract<FieldType> {
    public:
        virtual std::size_t rows_amount() override {
            return 2;
        }
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
        ) override  {
            zkevm_calldataload_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
        }
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
        ) override  {
            zkevm_calldataload_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
        }
    };
}
