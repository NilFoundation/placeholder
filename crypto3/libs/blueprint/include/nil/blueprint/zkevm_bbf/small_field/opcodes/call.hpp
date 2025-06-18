#pragma once

#include <numeric>
#include <algorithm>

#include <nil/blueprint/zkevm_bbf/small_field/opcodes/abstract_opcode.hpp>

namespace nil::blueprint::bbf::zkevm_small_field{
    template<typename FieldType, GenerationStage stage>
    class zkevm_call_bbf : generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;
    public:
        using typename generic_component<FieldType,stage>::TYPE;

        zkevm_call_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state):
            generic_component<FieldType,stage>(context_object, false)
        {
            // ! Not implemented yet
/*          if constexpr( stage == GenerationStage::ASSIGNMENT ){
                auto gas = current_state.stack_top();
                auto address = current_state.stack_top(1);
                auto value = current_state.stack_top(2);
                auto argOffset = current_state.stack_top(3);
                auto argLength = current_state.stack_top(4);
                auto retOffset = current_state.stack_top(5);
                auto retLength = current_state.stack_top(6);
                BOOST_LOG_TRIVIAL(trace)
                    << "\tCALL: gas=" << gas
                    << std::hex << " address=0x" << address << std::dec
                    << " value=" << value
                    << " argOffset=" << argOffset
                    << " argLength=" << argLength
                    << " retOffset=" << retOffset
                    << " retLength=" << retLength << std::endl;
            }
            if constexpr( stage == GenerationStage::CONSTRAINTS ){
                // constrain(current_state.pc_next() - current_state.pc(0) - 1);                   // PC transition
                // constrain(current_state.gas(0) - current_state.gas_next() - 1);                 // GAS transition
                // constrain(current_state.stack_size(0) - current_state.stack_size_next());       // stack_size transition
                // constrain(current_state.memory_size(0) - current_state.memory_size_next());     // memory_size transition
                // constrain(current_state.rw_counter_next() - current_state.rw_counter(0));   // rw_counter transition
            }*/
        }
    };

    template<typename FieldType>
    class zkevm_call_operation : public opcode_abstract<FieldType> {
    public:
        zkevm_call_operation() {}
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
        ) override  {
            zkevm_call_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
        }
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
        ) override  {
            zkevm_call_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
        }
        virtual std::size_t rows_amount() override {
            return 1;
        }
    };
}
