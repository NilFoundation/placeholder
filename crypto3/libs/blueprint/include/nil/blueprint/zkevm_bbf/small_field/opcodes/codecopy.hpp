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

#include <algorithm>
#include <numeric>

#include <nil/blueprint/zkevm_bbf/small_field/opcodes/abstract_opcode.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/subcomponents/memory_cost.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/subcomponents/word_size.hpp>
#include <nil/blueprint/zkevm_bbf/types/copy_event.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_word.hpp>

namespace nil::blueprint::bbf::zkevm_small_field {
    template<typename FieldType, GenerationStage stage>
    class zkevm_codecopy_bbf : generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

      public:
        using typename generic_component<FieldType, stage>::TYPE;

        // 1. Range checks
        //      a) dest_offset < 2^22          else is_gas_error = true
        //      b) length < 2^22               else is_gas_error = true
        //      c) dest_offset + length < 2^22 else is_gas_error = true
        // 2. bytecode_size lookup
        // 3. is_bytecode_copy_event
        //      a) if length == 0             then is_bytecode_copy_event = false
        //      b) if offset >= bytecode_size then is_bytecode_copy_event = false;
        //      c) if offset < bytecode_size  then
        //              is_bytecode_copy_event = true;
        //              real_copy_size = std::min(bytecode_size - offset, length)
        // 4. is_zero_copy_event
        //      b) if offset + length <= bytecode_size  then  is_zero_copy_event = false;
        //      c) if offset + length > bytecode_size   then
        //              is_zero_copy_event = true;
        //              zero_copy_size = std::min(length, offset+length - bytecode_size);

        zkevm_codecopy_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state)
            : generic_component<FieldType, stage>(context_object, false)
        {
            // using Memory_Cost = typename zkevm_small_field::memory_cost<FieldType, stage>;

            // std::array<TYPE, 16> dest_offset_chunks;  // < 2^22
            // std::array<TYPE, 16> offset_chunks;
            // std::array<TYPE, 16> length_chunks;       // < 2^22

            // // ALLOCATION
            // for (std::size_t i = 0; i < 16; i++) {
            //     allocate(dest_offset_chunks[i], i, 0);
            //     allocate(offset_chunks[i], i+16, 0);
            //     allocate(length_chunks[i], i, 1);
            // }
            // if constexpr (stage == GenerationStage::CONSTRAINTS) {
            //     // PC transition
            //     constrain(current_state.pc_next() - current_state.pc(2) - 1);
            //     // GAS transition
            //     // next -1 if out of range
            //     // constrain((current_state.gas(4) - current_state.gas_next() - 3 -
            //     //            3 * minimum_word_size - memory_expansion_cost) *
            //     //               overflow +
            //     //           (overflow - 1) * current_state.gas_next());
            //     // stack_size transition
            //     // constrain(current_state.stack_size(4) - current_state.stack_size_next() -
            //     //           3);`
            //     // memory_size transition
            //     // next - 1 if out of range
            //     // constrain((current_state.memory_size_next() -
            //     //            current_state.memory_size(4) - memory_expansion_size) *
            //     //               overflow +
            //     //           (overflow - 1) * current_state.memory_size_next());
            //     // rw_counter transition
            //     // constrain(current_state.rw_counter_next() - current_state.rw_counter(4) -
            //     //           3 - length * overflow);

            //     using RwTable = rw_256_table<FieldType, stage>;
            //     lookup(RwTable::stack_16_bit_lookup(
            //         current_state.call_id(0),
            //         current_state.stack_size(0) - 1,
            //         current_state.rw_counter(0),
            //         TYPE(0),  // is_write
            //         dest_offset_chunks
            //     ), "zkevm_rw_256");
            //     lookup(RwTable::stack_16_bit_lookup(
            //         current_state.call_id(1),
            //         current_state.stack_size(1) - 2,
            //         current_state.rw_counter(1) + 1,
            //         TYPE(0),  // is_write
            //         offset_chunks
            //     ), "zkevm_rw_256");
            //     lookup(RwTable::stack_16_bit_lookup(
            //         current_state.call_id(2),
            //         current_state.stack_size(2) - 3,
            //         current_state.rw_counter(2) + 2,
            //         TYPE(0),  // is_write
            //         length_chunks
            //     ), "zkevm_rw_256");
            // }
        }
    };

    template<typename FieldType>
    class zkevm_codecopy_operation : public opcode_abstract<FieldType> {
      public:
        virtual std::size_t rows_amount() override { return 3; }
        virtual void fill_context(
            typename generic_component<
                FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT>
                &current_state) override {
            zkevm_codecopy_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(
                context, current_state);
        }
        virtual void fill_context(
            typename generic_component<
                FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS>
                &current_state) override {
            zkevm_codecopy_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(
                context, current_state);
        }
    };
}  // namespace nil::blueprint::bbf::zkevm_small_field
