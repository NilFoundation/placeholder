#pragma once

#include <numeric>
#include <algorithm>

#include <nil/blueprint/zkevm_bbf/big_field/opcodes/abstract_opcode.hpp>

namespace nil::blueprint::bbf::zkevm_big_field{
    template<typename FieldType, GenerationStage stage>
    class zkevm_start_call_bbf : generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;
    public:
        using typename generic_component<FieldType,stage>::TYPE;

        zkevm_start_call_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state):
            generic_component<FieldType,stage>(context_object, false)
        {
            if constexpr( stage == GenerationStage::CONSTRAINTS ){
                // constrain(current_state.pc_next() - current_state.pc(0) - 1);                   // PC transition
                // constrain(current_state.gas(0) - current_state.gas_next() - 1);                 // GAS transition
                // constrain(current_state.stack_size(0) - current_state.stack_size_next());       // stack_size transition
                // constrain(current_state.memory_size(0) - current_state.memory_size_next());     // memory_size transition
                // constrain(current_state.rw_counter_next() - current_state.rw_counter(0));   // rw_counter transition
                // constrain(current_state.opcode_next() - next_opcode); // Next opcode restrictions
                constrain(current_state.rw_counter(0) - current_state.call_id(0));
            }
        }
    };

    template<typename FieldType>
    class zkevm_start_call_operation : public opcode_abstract<FieldType> {
    public:
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
        ) override  {
            zkevm_start_call_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
        }
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
        ) override  {
            zkevm_start_call_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
        }
        virtual std::size_t rows_amount() override {
            return 1;
        }
    };
}