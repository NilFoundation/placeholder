#pragma once

#include <iostream>

#include <nil/blueprint/zkevm_bbf/big_field/opcodes/abstract_opcode.hpp>

namespace nil::blueprint::bbf::zkevm_big_field{
    // SHOULD NOT BE USED IN THE FINAL VERSION
    template<typename FieldType>
    class zkevm_dummy_operation : public opcode_abstract<FieldType> {
    public:
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
        ) override  {
        }
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
        ) override  {
            BOOST_LOG_TRIVIAL(debug) << "DUMMY CONTSTRAINT, REPLACE ME WITH SOME ACTUAL IMPL";
        }
        virtual std::size_t rows_amount() override {
            return 1;
        }
    };
}