//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#include <nil/blueprint/zkevm_bbf/types/copy_event.hpp>

namespace nil::blueprint::bbf::zkevm_small_field{
    template<typename FieldType, GenerationStage stage>
    class copy_table : public generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup_table;

    public:
        using typename generic_component<FieldType,stage>::TYPE;
        using integral_type =  nil::crypto3::multiprecision::big_uint<257>;

        struct input_type {
            std::conditional_t<stage == GenerationStage::ASSIGNMENT, std::vector<copy_event>, std::monostate> copy_events;
            std::conditional_t<stage == GenerationStage::ASSIGNMENT, zkevm_keccak_buffers, std::monostate> bytecodes;
        };

        // For connection with upper-level circuits
        std::vector<TYPE>                 is_write;
        std::vector<TYPE>                 cp_type;
        std::vector<std::array<TYPE, 16>> id;   // For memory, calldata, returndata it would be call_id,
                                                // For bytecode it's bytecode_id
                                                // for keccak it'll be full hash
        std::vector<TYPE>                 counter_1;
        std::vector<TYPE>                 counter_2;
        std::vector<TYPE>                 length;

        static constexpr std::size_t is_write_index = 0;
        static constexpr std::size_t cp_type_index = 1;
        static constexpr std::size_t id_start_index = 2;
        static constexpr std::size_t counter_1_index = 18;
        static constexpr std::size_t counter_2_index = 19;
        static constexpr std::size_t length_index = 20;

        static std::size_t get_witness_amount(){
            return 21;
        }

        copy_table(context_type &context_object, const input_type &complex_input, std::size_t max_copy_events)
            :generic_component<FieldType,stage>(context_object),
            is_write(max_copy_events * 2),
            cp_type(max_copy_events * 2),
            id(max_copy_events * 2),
            counter_1(max_copy_events * 2),
            counter_2(max_copy_events * 2),
            length(max_copy_events * 2)
        {
            const auto &input = complex_input.copy_events;
            const auto &bytecodes = complex_input.bytecodes;

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                BOOST_ASSERT(input.size() < max_copy_events);
                std::size_t current_row = 0;

                std::map<zkevm_word_type, std::size_t> bytecode_ids;
                for(std::size_t index = 0; index < bytecodes.get_data().size(); index++){
                    bytecode_ids[bytecodes.get_data()[index].second] = index + 1;
                }

                for( auto &cp: input ){
                    length[current_row] = cp.length;
                    length[current_row + 1] = cp.length;
                    cp_type[current_row] = copy_op_to_num(cp.source_type);
                    cp_type[current_row+1] = copy_op_to_num(cp.destination_type);

                    if( cp.source_type == copy_operand_type::keccak ){
                        auto id_chunks = w_to_16(cp.source_id);
                        for( std::size_t i = 0; i < id_chunks.size(); i++) id[current_row][i] = id_chunks[i];
                    } else if (cp.source_type == copy_operand_type::bytecode ) {
                        id[current_row][15] = bytecode_ids[cp.source_id];
                    } else {
                        id[current_row][15] = cp.source_id;
                    }
                    if( cp.destination_type == copy_operand_type::keccak ){
                        auto id_chunks = w_to_16(cp.destination_id);
                        for( std::size_t i = 0; i < id_chunks.size(); i++) id[current_row + 1][i] = id_chunks[i];
                    } else if (cp.destination_type == copy_operand_type::bytecode ) {
                        id[current_row + 1][15] = bytecode_ids[cp.destination_id];
                    } else {
                        id[current_row + 1][15] = cp.destination_id;
                    }
                    counter_1[current_row] = cp.src_counter_1;
                    counter_2[current_row] = cp.src_counter_2;
                    counter_1[current_row+1] = cp.dst_counter_1;
                    counter_2[current_row+1] = cp.dst_counter_2;
                    current_row += 2;
                }
            }
            for( std::size_t i = 0; i < max_copy_events * 2; i++ ){
                if constexpr (stage == GenerationStage::ASSIGNMENT) { is_write[i] = i%2; }
                allocate(is_write[i], is_write_index, i);
                allocate(cp_type[i], cp_type_index , i);
                for( std::size_t j = 0; j < 16; j++){
                    allocate(id[i][j], id_start_index + j, i);
                }
                allocate(counter_1[i], counter_1_index, i);
                allocate(counter_2[i], counter_2_index, i);
                allocate(length[i], length_index, i);
            }
            std::vector<std::size_t> lookup_columns;
            for( std::size_t i = 0; i < get_witness_amount(); i++){
                lookup_columns.push_back(i);
            }
            lookup_table("zkevm_copy",lookup_columns,0,max_copy_events * 2);
        }
    };
}
