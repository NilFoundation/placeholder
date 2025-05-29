#pragma once

#include <numeric>
#include <algorithm>

#include <nil/blueprint/zkevm_bbf/big_field/opcodes/abstract_opcode.hpp>

namespace nil::blueprint::bbf::zkevm_big_field{
    template<typename FieldType, GenerationStage stage>
    class zkevm_start_block_bbf : generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;
    public:
        using typename generic_component<FieldType,stage>::TYPE;

        zkevm_start_block_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state):
            generic_component<FieldType,stage>(context_object, false)
        {
            // TODO: Append all block context rw operations
            if constexpr( stage == GenerationStage::CONSTRAINTS ){
                constrain(current_state.pc(0));                                                 // PC transition
                constrain(current_state.gas(0));                                                // GAS transition
                constrain(current_state.stack_size(0));                                         // stack_size transition
                constrain(current_state.memory_size(0));                                        // memory_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(0) - call_context_readonly_field_amount);       // rw_counter transition
                constrain(current_state.rw_counter(0) - current_state.call_id(0));
                constrain(
                    (current_state.opcode_next() - TYPE(std::size_t(opcode_to_number(zkevm_opcode::start_transaction)))) *
                    (current_state.opcode_next() - TYPE(std::size_t(opcode_to_number(zkevm_opcode::end_block))))
                ); // Next opcode restrictions
            }
        }
    };

    template<typename FieldType>
    class zkevm_start_block_operation : public opcode_abstract<FieldType> {
    public:
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
        ) override  {
            zkevm_start_block_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
        }
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
        ) override  {
            zkevm_start_block_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
        }
        virtual std::size_t rows_amount() override {
            return 1;
        }
    };
}