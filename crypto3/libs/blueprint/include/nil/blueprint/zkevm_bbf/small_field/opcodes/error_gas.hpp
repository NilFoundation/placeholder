//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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
// The above copyright error_gasice and this permission error_gasice shall be included in all
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
    class zkevm_error_gas_bbf : generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;
    public:
        using typename generic_component<FieldType,stage>::TYPE;

        // This component checks that -gas < MAX_ZKEVM_GAS_ERROR_BOUND (2^26 for now)
        zkevm_error_gas_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state):
            generic_component<FieldType,stage>(context_object, false)
        {
            TYPE gas_chunk_hi, diff_chunk_hi; // < 2^10
            TYPE gas_chunk_lo; // < 2^16

            const std::size_t hi_chunk_bound = (MAX_ZKEVM_GAS_BOUND >> 16);

            if constexpr( stage == GenerationStage::ASSIGNMENT){
                BOOST_LOG_TRIVIAL(trace) << std::hex << "\tzkevm_error_gas_bbf: current_state.gas() = " << current_state.gas();
                std::size_t current_gas = std::numeric_limits<std::size_t>::max() - current_state.gas() + 1;
                TYPE gas = current_gas;
                BOOST_LOG_TRIVIAL(trace) << std::hex << "\tcurrent_gas = "  << current_gas << " gas = " << gas <<std::dec;
                BOOST_ASSERT(current_state.gas() >= MAX_ZKEVM_GAS_ERROR_BOUND);
                BOOST_ASSERT(current_gas < MAX_ZKEVM_GAS_BOUND);
                gas_chunk_lo = gas.to_integral() & (0xFFFF);
                gas_chunk_hi = gas.to_integral() >> 16;
                diff_chunk_hi = hi_chunk_bound - 1 - gas_chunk_hi;
            }
            allocate(gas_chunk_lo, 0, 0);
            allocate(gas_chunk_hi, 1, 0);
            allocate(diff_chunk_hi, 2, 0);

            constrain(hi_chunk_bound - 1 - diff_chunk_hi- gas_chunk_hi);

            if constexpr( stage == GenerationStage::CONSTRAINTS){
                //constrain(current_state.pc_next() - current_state.pc(0) - 1);                 // PC transition
                constrain(current_state.gas(0) + gas_chunk_lo + 0x10000 * gas_chunk_hi);
                // constrain(current_state.stack_size(0) - current_state.stack_size_next());    // stack_size transition
                // constrain(current_state.memory_size(0) - current_state.memory_size_next());  // memory_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(0));       // rw_counter transition
            }
        }
    };

    template<typename FieldType>
    class zkevm_error_gas_operation : public opcode_abstract<FieldType> {
    public:
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
        ) override  {
            zkevm_error_gas_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
        }
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
        ) override  {
            zkevm_error_gas_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
        }
        virtual std::size_t rows_amount() override {
            return 1;
        }
    };
}