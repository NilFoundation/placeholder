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
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//
#pragma once

#include<nil/blueprint/zkevm_bbf/types/state_operation.hpp>

namespace nil::blueprint::bbf::zkevm_small_field{
    template<typename FieldType, GenerationStage stage>
    class state_timeline_table : public generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;
    public:
        using typename generic_component<FieldType,stage>::TYPE;
        using input_type = typename std::conditional<stage==GenerationStage::ASSIGNMENT, state_operations_vector, std::nullptr_t>::type;
        using integral_type =  nil::crypto3::multiprecision::big_uint<257>;
    public:
        // state_timeline_table
        std::vector<TYPE> is_original;                       // boolean
        std::vector<TYPE> rw_id;                             // 2 chunks fitted in field element less than 2^25
        std::vector<TYPE> internal_counter;                  // 2 chunks fitted in field element less than 2^25

        static std::size_t get_witness_amount(){ return 3; }

        state_timeline_table(context_type &context_object, const input_type &input, std::size_t max_state)
            :generic_component<FieldType,stage>(context_object),
            rw_id(max_state),
            is_original(max_state),
            internal_counter(max_state)
        {
            // BOOST_LOG_TRIVIAL(trace) << "State table";
            auto &state_trace = input;
            if constexpr  (stage == GenerationStage::ASSIGNMENT) {
                BOOST_ASSERT(state_trace.size() <= max_state);
                BOOST_ASSERT(state_trace[0].op == rw_operation_type::start);
                for( std::size_t i = 0; i < state_trace.size(); i++ ){
                    rw_id[i] = state_trace[i].rw_counter;
                    if( i!=0 ) is_original[i] = state_trace[i].is_original? 1 : 0;
                    internal_counter[i] = state_trace[i].internal_counter;
                }
            }
            for( std::size_t i = 0; i < max_state; i++ ){
                std::size_t current_column = 0;
                allocate(is_original[i], current_column++, i);          //0
                allocate(rw_id[i], current_column++, i);                //1
                allocate(internal_counter[i], current_column++, i);     //2
            }
            lookup_table("zkevm_state_timeline",std::vector<std::size_t>({0,1,2}),0,max_state);
        }
    };
}