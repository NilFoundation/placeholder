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
        std::vector<TYPE>                   src_type;
        std::vector<TYPE>                   src_id;   // For memory, calldata, returndata it would be call_id,
                                                      // For bytecode it's bytecode_id
                                                      // It cannot be keccak for now.
                                                      // If we need to prove that some data is a part of keccak buffer make it similar to dst_id
        std::vector<TYPE>                   src_counter_1;
        std::vector<TYPE>                   src_counter_2;
        std::vector<TYPE>                   dst_type;
        std::vector<std::array<TYPE,16>>    dst_id;
        std::vector<TYPE>                   dst_counter_1;
        std::vector<TYPE>                   dst_counter_2;
        std::vector<TYPE>                   length;

        // static constexpr std::size_t cp_type_index = 1;
        // static constexpr std::size_t id_start_index = 2;
        // static constexpr std::size_t counter_1_index = 18;
        // static constexpr std::size_t counter_2_index = 19;
        // static constexpr std::size_t length_index = 20;

        static std::size_t get_witness_amount(){
            return 24;
        }

        static constexpr std::size_t  src_type_index = 0;
        static constexpr std::size_t  src_id_index = 1;
        static constexpr std::size_t  src_counter_1_index = 2;
        static constexpr std::size_t  src_counter_2_index = 3;
        static constexpr std::size_t  dst_type_index = 4;
        static constexpr std::size_t  dst_counter_1_index = 21;
        static constexpr std::size_t  dst_counter_2_index = 22;
        static constexpr std::size_t  length_index = 23;

        copy_table(context_type &context_object, const input_type &complex_input, std::size_t max_copy_events)
            :generic_component<FieldType,stage>(context_object),
            src_type(max_copy_events),
            src_id(max_copy_events),
            src_counter_1(max_copy_events),
            src_counter_2(max_copy_events),
            dst_type(max_copy_events),
            dst_id(max_copy_events),
            dst_counter_1(max_copy_events),
            dst_counter_2(max_copy_events),
            length(max_copy_events)
        {
            const auto &input = complex_input.copy_events;
            const auto &bytecodes = complex_input.bytecodes;

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                BOOST_ASSERT(input.size() < max_copy_events);

                std::map<zkevm_word_type, std::size_t> bytecode_ids;
                for(std::size_t index = 0; index < bytecodes.get_data().size(); index++){
                    bytecode_ids[bytecodes.get_data()[index].second] = index + 1;
                }

                for( std::size_t i = 0; i < input.size(); i++ ){
                    const auto &cp = input[i];
                    length[i] = cp.length;
                    src_type[i] = copy_op_to_num(cp.source_type);
                    dst_type[i] = copy_op_to_num(cp.destination_type);

                    if( cp.source_type == copy_operand_type::keccak ){
                        BOOST_ASSERT(false);
                        BOOST_LOG_TRIVIAL(fatal) << "Keccak buffer as a copy source is not supported in copy table";
                    } else if (cp.source_type == copy_operand_type::bytecode ) {
                        src_id[i] = bytecode_ids[cp.source_id];
                    } else {
                        src_id[i] = cp.source_id;
                    }
                    if( cp.destination_type == copy_operand_type::keccak ){
                        auto id_chunks = w_to_16(cp.destination_id);
                        for( std::size_t j = 0; j < id_chunks.size(); j++) dst_id[i][j] = id_chunks[j];
                    } else if (cp.destination_type == copy_operand_type::bytecode ) {
                        dst_id[i][15] = bytecode_ids[cp.destination_id];
                    } else {
                        dst_id[i][15] = cp.destination_id;
                    }
                    src_counter_1[i] = cp.src_counter_1;
                    src_counter_2[i] = cp.src_counter_2;
                    dst_counter_1[i] = cp.dst_counter_1;
                    dst_counter_2[i] = cp.dst_counter_2;
                }
            }
            for( std::size_t i = 0; i < max_copy_events; i++ ){
                std::size_t current_column = 0;
                allocate(src_type[i], current_column++ , i);
                allocate(src_id[i], current_column++ , i);
                allocate(src_counter_1[i], current_column++ , i);
                allocate(src_counter_2[i], current_column++ , i);
                allocate(dst_type[i], current_column++ , i);
                for( std::size_t j = 0; j < 16; j++){
                    allocate(dst_id[i][j], current_column++, i);
                }
                allocate(dst_counter_1[i], current_column++, i);
                allocate(dst_counter_2[i], current_column++, i);
                allocate(length[i], current_column++, i);
            }
            std::vector<std::size_t> lookup_columns;
            for( std::size_t i = 0; i < get_witness_amount(); i++){
                lookup_columns.push_back(i);
            }
            lookup_table("zkevm_copy",lookup_columns,0,max_copy_events);
        }

        static std::vector<TYPE> codecopy_lookup(
            TYPE src_id,
            TYPE src_offset,
            TYPE call_id,
            TYPE dst_counter_1,
            TYPE dst_counter_2,
            TYPE length
        ){
            std::vector<TYPE> result = {};
            result.push_back(TYPE(copy_op_to_num(copy_operand_type::bytecode))); // src_type
            result.push_back(src_id); // src_id
            result.push_back(src_offset); // src_counter_1
            result.push_back(TYPE(0)); // src_counter_2, not used in codecopy
            result.push_back(TYPE(copy_op_to_num(copy_operand_type::memory))); // dst_type
            for( std::size_t i = 0; i < 15; i++ ){
                result.push_back(TYPE(0));
            }
            result.push_back(call_id); // dst_id, call_id
            result.push_back(dst_counter_1); // dst_counter_1
            result.push_back(dst_counter_2); // dst_counter_2
            result.push_back(length); // length
            return result;
        }
    };
}

