#pragma once

#include <numeric>
#include <algorithm>

#include <nil/blueprint/zkevm_bbf/types/opcode.hpp>
#include <nil/blueprint/zkevm_bbf/opcodes/dummy.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf{
            template<typename FieldType, GenerationStage stage>
            class zkevm_end_call_bbf : generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;
            public:
                using typename generic_component<FieldType,stage>::TYPE;

                zkevm_end_call_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state):
                    generic_component<FieldType,stage>(context_object, false)
                {
                    TYPE lastcall_id;
                    TYPE length, length_inv;
                    TYPE offset;
                    if constexpr( stage == GenerationStage::ASSIGNMENT ){
                        lastcall_id = current_state.lastsubcall_id();
                        length = current_state.lastcall_returndata_length();
                        offset = current_state.lastcall_returndata_offset();
                        length_inv = length == 0? 0: length.inversed();
                    }
                    allocate(lastcall_id, 32, 0);
                    allocate(length, 33, 0);
                    allocate(offset, 34, 0);
                    allocate(length_inv, 35, 0);

                    // Length_inv correctness
                    constrain(length * (length * length_inv - 1));
                    constrain(length_inv * (length * length_inv - 1));

                    if constexpr( stage == GenerationStage::CONSTRAINTS ){
                        // constrain(current_state.pc_next() - current_state.pc(0) - 1);                   // PC transition
                        // constrain(current_state.gas(0) - current_state.gas_next() - 1);                 // GAS transition
                        // constrain(current_state.stack_size(0) - current_state.stack_size_next());       // stack_size transition
                        // constrain(current_state.memory_size(0) - current_state.memory_size_next());     // memory_size transition
                        // constrain(current_state.rw_counter_next() - current_state.rw_counter(0));   // rw_counter transition
                        lookup(rw_table<FieldType, stage>::call_context_editable_lookup(
                            current_state.call_id(0),
                            std::size_t(call_context_field::lastcall_returndata_length),
                            current_state.rw_counter(0),
                            TYPE(0),
                            TYPE(0),
                            length
                        ), "zkevm_rw");
                        lookup(rw_table<FieldType, stage>::call_context_editable_lookup(
                            current_state.call_id(0),
                            std::size_t(call_context_field::lastcall_returndata_offset),
                            current_state.rw_counter(0)+1,
                            TYPE(0),
                            TYPE(0),
                            offset
                        ), "zkevm_rw");
                        lookup(rw_table<FieldType, stage>::call_context_editable_lookup(
                            current_state.call_id(0),
                            std::size_t(call_context_field::lastcall_id),
                            current_state.rw_counter(0)+2,
                            TYPE(0),
                            TYPE(0),
                            lastcall_id
                        ), "zkevm_rw");

                        lookup({
                            length * length_inv,                                                          // is_first
                            TYPE(0),                                                                      // is_write
                            length * length_inv * TYPE(copy_op_to_num(copy_operand_type::returndata)),    // cp_type
                            TYPE(0),                                                                      // id_hi
                            length * length_inv * lastcall_id,                                            // id_lo
                            TYPE(0),                                                                      // counter_1
                            length * length_inv * (current_state.rw_counter(0) + 3),                      // counter_2
                            length
                        }, "zkevm_copy");
                        lookup({
                            length * length_inv,                                                       // is_first
                            length * length_inv,                                                       // is_write
                            length * length_inv * TYPE(copy_op_to_num(copy_operand_type::memory)),     // cp_type
                            TYPE(0),                                                                   // id_hi
                            length * length_inv * current_state.call_id(0),                            // id_lo
                            length * length_inv * offset,                                              // counter_1
                            length * length_inv * (current_state.rw_counter(0) + length + 3),          // counter_2
                            length
                        }, "zkevm_copy");
                    }
                }
            };

            template<typename FieldType>
            class zkevm_end_call_operation : public opcode_abstract<FieldType> {
            public:
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
                ) override  {
                    zkevm_end_call_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
                }
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
                ) override  {
                    zkevm_end_call_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
                }
                virtual std::size_t rows_amount() override {
                    return 1;
                }
            };
        } // namespace bbf
    }   // namespace blueprint
}   // namespace nil
