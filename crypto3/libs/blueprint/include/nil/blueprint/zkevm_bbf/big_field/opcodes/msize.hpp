#pragma once

#include <numeric>
#include <algorithm>

#include <nil/blueprint/zkevm_bbf/types/zkevm_word.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/opcodes/abstract_opcode.hpp>

namespace nil::blueprint::bbf::zkevm_big_field{
    template<typename FieldType, GenerationStage stage>
    class zkevm_msize_bbf : generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;
    public:
        using typename generic_component<FieldType,stage>::TYPE;

        zkevm_msize_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state):
            generic_component<FieldType,stage>(context_object, false)
        {
            using integral_type = typename FieldType::integral_type;
            TYPE memory_words;
            TYPE diff;
            TYPE diff31;
            if constexpr( stage == GenerationStage::ASSIGNMENT ){
                memory_words = integral_type(current_state.memory_size() + 31) / 32;
                diff = memory_words * 32 - current_state.memory_size();
                diff31 = 31 - diff;
            }
            allocate(memory_words, 0, 0);
            allocate(diff, 1, 0);
            allocate(diff31, 2, 0);

            if constexpr( stage == GenerationStage::CONSTRAINTS ){
                constrain(current_state.memory_size(0) + diff - memory_words * 32);
                constrain(diff + diff31 - 31);

                constrain(current_state.pc_next() - current_state.pc(0) - 1);                   // PC transition
                constrain(current_state.gas(0) - current_state.gas_next() - 2);                 // GAS transition
                constrain(current_state.stack_size(0) - current_state.stack_size_next() + 1);       // stack_size transition
                constrain(current_state.memory_size(0) - current_state.memory_size_next());     // memory_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(0) - 1);   // rw_counter transition
                constrain(current_state.memory_size_next()  - current_state.memory_size(0));

                lookup(rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0),
                    current_state.rw_counter(0),
                    TYPE(1),// is_write
                    0,
                    memory_words * 32
                ), "zkevm_rw");
            }
        }
    };

    template<typename FieldType>
    class zkevm_msize_operation : public opcode_abstract<FieldType> {
    public:
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
        ) override {
            zkevm_msize_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
        }
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
        ) override  {
            zkevm_msize_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
        }
        virtual std::size_t rows_amount() override {
            return 1;
        }
    };
}