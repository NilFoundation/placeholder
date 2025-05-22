//---------------------------------------------------------------------------//
// Copyright (c) 2025 Elena Tatuzova <e.tatuzova@nil.foundation>
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
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THEs
// SOFTWARE.
//---------------------------------------------------------------------------//
#pragma once

#include<nil/blueprint/zkevm_bbf/types/timeline_item.hpp>

namespace nil::blueprint::bbf::zkevm_small_field{
    // This is a table where all read/write operations are ordered by rw_id.
    // Main purpose is to prove that rw and state table contain only operations that are presented in timeline.

    template<typename FieldType, GenerationStage stage>
    class timeline_table : public generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;
        using generic_component<FieldType, stage>::multi_lookup_table;
    public:
        using typename generic_component<FieldType,stage>::TYPE;
        using input_type = typename std::conditional<stage==GenerationStage::ASSIGNMENT, std::vector<timeline_item>, std::nullptr_t>::type;
        using integral_type =  nil::crypto3::multiprecision::big_uint<257>;

    public:
        // timeline_table
        std::vector<TYPE> rw_id;
        std::vector<TYPE> rw_8_table_selector;
        std::vector<TYPE> rw_256_table_selector;
        std::vector<TYPE> state_table_selector;
        std::vector<TYPE> internal_counter;

        static std::size_t get_witness_amount(
            std::size_t instances_timeline
        ){ return 5 * instances_timeline; }

        timeline_table(
            context_type &context_object,
            const input_type &input,
            std::size_t max_timeline,
            std::size_t instances_timeline
        )
            :generic_component<FieldType,stage>(context_object),
            rw_id(max_timeline),
            rw_8_table_selector(max_timeline),
            rw_256_table_selector(max_timeline),
            state_table_selector(max_timeline),
            internal_counter(max_timeline)
        {
            if constexpr  (stage == GenerationStage::ASSIGNMENT) {
                auto timeline = input;
                BOOST_ASSERT(timeline.size() <= max_timeline);
            //     // BOOST_ASSERT(timeline[0].op == rw_operation_type::start);

                BOOST_LOG_TRIVIAL(trace) << "Timeline table:";
                std::size_t rw_8_start_internal_counter = 0xFFFFFFFFFFFFFFFF;
                for( std::size_t i = 0; i < timeline.size(); i++ ){
                    if( (
                            timeline[i].op == rw_operation_type::memory ||
                            timeline[i].op == rw_operation_type::calldata ||
                            timeline[i].op == rw_operation_type::returndata
                        ) && (timeline[i].internal_counter < rw_8_start_internal_counter)
                    ) rw_8_start_internal_counter = timeline[i].internal_counter;
                }
                for( std::size_t i = 0; i < timeline.size(); i++ ){
                    rw_id[i] = timeline[i].rw_id;
                    rw_256_table_selector[i] = (
                        timeline[i].op == rw_operation_type::stack ||
                        timeline[i].op == rw_operation_type::call_context
                    )? 1: 0;
                    rw_8_table_selector[i] = (
                        timeline[i].op == rw_operation_type::memory ||
                        timeline[i].op == rw_operation_type::calldata ||
                        timeline[i].op == rw_operation_type::returndata
                    )? 1: 0;
                    state_table_selector[i] = (
                        timeline[i].op == rw_operation_type::state_call_context ||
                        timeline[i].op == rw_operation_type::state ||
                        timeline[i].op == rw_operation_type::transient_storage ||
                        timeline[i].op == rw_operation_type::access_list
                    )? 1: 0;
                    internal_counter[i] = (
                        timeline[i].op == rw_operation_type::memory ||
                        timeline[i].op == rw_operation_type::calldata ||
                        timeline[i].op == rw_operation_type::returndata
                    )? timeline[i].internal_counter - rw_8_start_internal_counter + 1: timeline[i].internal_counter;
                }
            }
            for( std::size_t i = 0; i < max_timeline; i++ ){
                std::size_t current_column = 0;
                allocate(rw_id[i], current_column++, i);
                allocate(rw_8_table_selector[i], current_column++, i);
                allocate(rw_256_table_selector[i], current_column++, i);
                allocate(state_table_selector[i], current_column++, i);
                allocate(internal_counter[i], current_column++, i);
            }
            if constexpr  (stage == GenerationStage::CONSTRAINTS) {
                constrain(rw_id[0]);

                std::vector<TYPE> every_row_constraints;
                std::vector<TYPE> non_first_row_constraints;

                non_first_row_constraints.push_back(rw_8_table_selector[1] * (rw_8_table_selector[1] - 1));
                non_first_row_constraints.push_back(rw_256_table_selector[1] * (rw_256_table_selector[1] - 1));
                non_first_row_constraints.push_back(state_table_selector[1] * (state_table_selector[1] - 1));
                non_first_row_constraints.push_back(
                    (state_table_selector[1] + rw_8_table_selector[1] + rw_256_table_selector[1] - 1)
                    * (state_table_selector[1] + rw_8_table_selector[1] + rw_256_table_selector[1])
                );
                non_first_row_constraints.push_back(
                    (1 - state_table_selector[1] - rw_8_table_selector[1] - rw_256_table_selector[1]) *
                    (state_table_selector[2] + rw_8_table_selector[2] + rw_256_table_selector[2])
                );
                non_first_row_constraints.push_back(
                    (state_table_selector[1] + rw_8_table_selector[1] + rw_256_table_selector[1]) * (rw_id[1] - rw_id[0] - 1)
                );

                for( auto& constraint: every_row_constraints){
                    context_object.relative_constrain(context_object.relativize(constraint, -1), 0, max_timeline - 1);
                }
                for( auto &constraint: non_first_row_constraints ){
                    context_object.relative_constrain(context_object.relativize(constraint, -1), 1, max_timeline - 1);
                }
            }
            std::vector<std::vector<std::size_t>> timeline_lookup_columns;
            std::size_t current_id = 0;
            for( std::size_t i = 0; i < instances_timeline; i++ ){
                std::vector<std::size_t> current_lookup;
                for( std::size_t j = 0; j < 5; j++ ){
                    current_lookup.push_back(current_id++);
                }
                timeline_lookup_columns.push_back(current_lookup);
            }
            multi_lookup_table("zkevm_timeline",timeline_lookup_columns,0,max_timeline);
        }
    };
}
