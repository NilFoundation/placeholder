#pragma once

#include <numeric>
#include <algorithm>

#include <nil/blueprint/zkevm_bbf/types/opcode.hpp>
#include <nil/blueprint/zkevm_bbf/opcodes/dummy.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf{
            template<typename FieldType, GenerationStage stage>
            class zkevm_stop_bbf : generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;
            public:
                using typename generic_component<FieldType,stage>::TYPE;

                zkevm_stop_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state):
                    generic_component<FieldType,stage>(context_object, false)
                {
                    TYPE depth, depth_inv;
                    if constexpr( stage == GenerationStage::ASSIGNMENT ){
                        depth = current_state.depth() - 2;
                        depth_inv = depth == 0? 0: depth.inversed();
                    }
                    allocate(depth, 32, 0);
                    allocate(depth_inv, 33, 0);

                    // depth_inv is correct
                    constrain(depth * (depth * depth_inv - 1));
                    constrain(depth_inv * (depth * depth_inv - 1));

                    // Calculate next_opcode
                    TYPE next_opcode =
                        depth * depth_inv * TYPE(std::size_t(opcode_to_number(zkevm_opcode::end_call))) +
                        (1 - depth * depth_inv) * TYPE(std::size_t(opcode_to_number(zkevm_opcode::end_transaction)));
                    std::cout << "Next opcode = " << std::hex << next_opcode << std::endl;
                    std::cout << "Depth = " << depth << std::endl;

                    if constexpr( stage == GenerationStage::CONSTRAINTS ){
                        // constrain(current_state.pc_next() - current_state.pc(0) - 1);                   // PC transition
                        // constrain(current_state.gas(0) - current_state.gas_next() - 1);                 // GAS transition
                        // constrain(current_state.stack_size(0) - current_state.stack_size_next());       // stack_size transition
                        // constrain(current_state.memory_size(0) - current_state.memory_size_next());     // memory_size transition
                        // constrain(current_state.rw_counter_next() - current_state.rw_counter(0));   // rw_counter transition
                        // constrain(current_state.opcode_next() - next_opcode); // Next opcode restrictions
                        constrain(current_state.opcode_next() - next_opcode); // Next opcode restrictions
                            lookup(rw_table<FieldType, stage>::call_context_lookup(
                            current_state.call_id(0),
                            std::size_t(call_context_field::depth),
                            TYPE(0),
                            depth + 1
                        ), "zkevm_rw");

                    }
                }
            };

            template<typename FieldType>
            class zkevm_stop_operation : public opcode_abstract<FieldType> {
            public:
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
                ) override  {
                    zkevm_stop_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
                }
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
                ) override  {
                    zkevm_stop_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
                }
                virtual std::size_t rows_amount() override {
                    return 1;
                }
            };
        } // namespace bbf
    }   // namespace blueprint
}   // namespace nil
