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
    // Timeline table uses only three columns:
    //   is_original
    //   rw_id
    //   internal_counter
    // Opcode contains all that is necessary to opcodes
    //   op
    //   id
    //   address
    //   field_type
    //   storage_key
    //   rw_id
    //   is_write
    //   value
    //   previous_value
    //   initial_value
    // Full contains both columns for timeline and opcode
    enum class state_table_mode { timeline, opcode, full };

    template<typename FieldType, GenerationStage stage>
    class state_table : public generic_component<FieldType, stage> {
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

        // using state_timeline_table_type = typename state_timeline_table<FieldType, stage>;
    public:
        // state_table
        std::vector<TYPE> is_original;                       // 0
        std::vector<TYPE> op;                                // 1
        std::vector<TYPE> id;                                // 2          -- 2 chunks fitted in field element less than 2^25
        std::vector<std::array<TYPE, 10>> address;           // 3-12       -- 10 chunks
        std::vector<TYPE> field_type;                        // 13
        std::vector<std::array<TYPE, 16>> storage_key;       // 14 -- 45   -- 16 full chunks
        std::vector<TYPE> rw_id;                             // 46   -- 2 chunks fitted in field element less than 2^25
        std::vector<TYPE> is_write;                          // 47
        std::vector<std::array<TYPE, 16>> value ;            // 48 -- 79
        std::vector<std::array<TYPE, 16>> previous_value ;   // 80 -- 111
        std::vector<std::array<TYPE, 16>> initial_value ;    // 112 -- 143
        std::vector<TYPE> internal_counter;                  // 144 -- 2 chunks fitted in field element less than 2^25
        std::vector<TYPE> call_id;
        std::vector<TYPE> parent_id;
        std::vector<TYPE> update_parent_selector;

        static std::size_t get_witness_amount(state_table_mode mode ){
            switch (mode) {
            case state_table_mode::timeline:
                return 3;
            case state_table_mode::opcode:
                return 80; // 1 + 2 + 10 + 1 + 16 + 2 + 16 + 16 + 16;
            case state_table_mode::full:
                return 84; // 1 + 2 + 10 + 1 + 16 + 2 + 16 + 16 + 16 + 1;
            }
            BOOST_LOG_TRIVIAL(fatal) << "Unknown state table mode";
            return 0;
        }

        state_table(context_type &context_object, const input_type &input, std::size_t max_state, state_table_mode mode)
            :generic_component<FieldType,stage>(context_object),
            rw_id(max_state)
        {
            BOOST_LOG_TRIVIAL(info) << "State table";

            // Resize all necessary vectors
            is_original.resize(max_state);
            rw_id.resize(max_state);
            if( mode == state_table_mode::opcode || mode == state_table_mode::full ){
                op.resize(max_state);
                id.resize(max_state);
                address.resize(max_state);
                field_type.resize(max_state);
                storage_key.resize(max_state);
                is_write.resize(max_state);
                value.resize(max_state);
                previous_value.resize(max_state);
                initial_value.resize(max_state);
            }
            if( mode == state_table_mode::timeline || mode == state_table_mode::full ){
                internal_counter.resize(max_state);
            }
            if( mode == state_table_mode::full ){
                call_id.resize(max_state);
                parent_id.resize(max_state);
                update_parent_selector.resize(max_state);
            }

            auto &state_trace = input;
            if constexpr  (stage == GenerationStage::ASSIGNMENT) {
                BOOST_ASSERT(state_trace[0].op == rw_operation_type::start);
                for( std::size_t i = 0; i < state_trace.size(); i++ ){
                    rw_id[i] = state_trace[i].rw_counter;
                    if( i!=0 ) is_original[i] = state_trace[i].is_original? 1 : 0;
                    if( mode == state_table_mode::full || mode == state_table_mode::timeline ){
                        internal_counter[i] = state_trace[i].internal_counter;
                    }
                    if( mode == state_table_mode::opcode || mode == state_table_mode::full ){
                        op[i] = std::size_t(state_trace[i].op);
                        id[i] = state_trace[i].id;

                        auto address_chunks = w_to_16(state_trace[i].address);
                        for( std::size_t j = 0; j < 10; j++ ){
                            address[i][j] = address_chunks[6 + j];
                        }
                        field_type[i] = state_trace[i].field;

                        auto storage_key_chunks = w_to_16(state_trace[i].storage_key);
                        for( std::size_t j = 0; j < 16; j++ ){
                            storage_key[i][j] = storage_key_chunks[j];
                        }
                        is_write[i] = state_trace[i].is_write;

                        auto value_chunks = w_to_16(state_trace[i].value);
                        for( std::size_t j = 0; j < 16; j++ ){
                            value[i][j] = value_chunks[j];
                        }

                        auto previous_value_chunks = w_to_16(state_trace[i].previous_value);
                        for( std::size_t j = 0; j < 16; j++ ){
                            previous_value[i][j] = previous_value_chunks[j];
                        }

                        auto initial_value_chunks = w_to_16(state_trace[i].initial_value);
                        for( std::size_t j = 0; j < 16; j++ ){
                            initial_value[i][j] = initial_value_chunks[j];
                        }
                    }
                    if( mode == state_table_mode::full ){
                        call_id[i] = state_trace[i].call_id;
                        parent_id[i] = state_trace[i].parent_id;
                        if( i == 0) continue;
                        if( (i != state_trace.size() - 1 ) && (
                            state_trace[i].id == state_trace[i+1].id &&
                            state_trace[i].op == state_trace[i+1].op &&
                            state_trace[i].address == state_trace[i+1].address &&
                            state_trace[i].field == state_trace[i+1].field &&
                            state_trace[i].storage_key == state_trace[i+1].storage_key
                        ) )   continue;
                        if( state_trace[i].op == rw_operation_type::state && state_trace[i].parent_id != 0)
                            update_parent_selector[i] = 1;
                        if( (state_trace[i].op == rw_operation_type::access_list || state_trace[i].op == rw_operation_type::transient_storage ) &&
                            state_trace[i].grandparent_id != 0
                        ) update_parent_selector[i] = 1;
                    }
                }
                if( mode == state_table_mode::opcode || mode == state_table_mode::full ){
                    for( std::size_t i = state_trace.size(); i < max_state; i++ ){
                        op[i] = std::size_t(rw_operation_type::padding);
                    }
                }
            }
            for( std::size_t i = 0; i < max_state; i++ ){
                std::size_t current_column = 0;
                if( mode == state_table_mode::timeline ){
                    allocate(is_original[i], current_column++, i);          //0
                    allocate(rw_id[i], current_column++, i);                //1
                    allocate(internal_counter[i], current_column++, i);     //2
                }
                if( mode == state_table_mode::opcode || mode == state_table_mode::full ){
                    allocate(is_original[i], current_column++, i);          //0
                    allocate(op[i], current_column++, i);                   //1
                    allocate(id[i], current_column++, i);                   //2
                    for( std::size_t j = 0; j < 10; j++ ){
                        allocate(address[i][j], current_column++, i);       //3-12
                    }
                    allocate(field_type[i], current_column++, i);           //13
                    for( std::size_t j = 0; j < 16; j++ ){
                        allocate(storage_key[i][j], current_column++, i);   //14-45
                    }
                    allocate(rw_id[i], current_column++, i);                //46
                    allocate(is_write[i], current_column++, i);             //47
                    for( std::size_t j = 0; j < 16; j++ ){
                        allocate(value[i][j], current_column++, i);         //48-79
                    }
                    for( std::size_t j = 0; j < 16; j++ ){
                        allocate(previous_value[i][j], current_column++, i); //80-111
                    }
                    for( std::size_t j = 0; j < 16; j++ ){
                        allocate(initial_value[i][j], current_column++, i);  //112-143
                    }
                }
                if( mode == state_table_mode::full ){
                    allocate(internal_counter[i], current_column++, i); //144
                    allocate(call_id[i], current_column++, i);          //145
                    allocate(parent_id[i], current_column++, i);        //146
                    allocate(update_parent_selector[i], current_column++, i);  // 147
                }
            }
            std::vector<std::size_t> state_table_area;
            if( mode == state_table_mode::full){
                std::size_t current_column = 0;
                state_table_area.push_back(current_column++); // is_original
                state_table_area.push_back(current_column++); // op
                state_table_area.push_back(current_column++); // id
                for( std::size_t j = 0; j < 10; j++ ) state_table_area.push_back(current_column++); // address
                state_table_area.push_back(current_column++); // field_type
                for( std::size_t j = 0; j < 16; j++ ) state_table_area.push_back(current_column++); // storage_key
                state_table_area.push_back(current_column++); // rw_id
                state_table_area.push_back(current_column++); // is_write
                for( std::size_t j = 0; j < 16; j++ ) state_table_area.push_back(current_column++); // value
                for( std::size_t j = 0; j < 16; j++ ) state_table_area.push_back(current_column++); // previous_value
                for( std::size_t j = 0; j < 16; j++ ) current_column++; // initial_value is not included
                current_column++; // internal_counter
                state_table_area.push_back(current_column++); // call_id
            }

            std::vector<std::size_t> parent_table_area;
            if( mode == state_table_mode::full ){
                std::size_t current_column  = 0;
                current_column++;                                   //is_original
                parent_table_area.push_back(current_column++);      // op
                parent_table_area.push_back(current_column++);      // id
                for( std::size_t j = 0; j < 10; j++ ) parent_table_area.push_back(current_column++); // address
                parent_table_area.push_back(current_column++);      // field_type
                for( std::size_t j = 0; j < 16; j++ ) parent_table_area.push_back(current_column++); // storage_key
                parent_table_area.push_back(current_column++);      // rw_id
                current_column++;      // is_write

                for( std::size_t j = 0; j < 16; j++ ) current_column++; // value
                for( std::size_t j = 0; j < 16; j++ ) current_column++; // previous_value
                for( std::size_t j = 0; j < 16; j++ ) current_column++; // initial_value
                current_column++; // internal_counter
                current_column++; // call_id
                parent_table_area.push_back(current_column++);  //parent_id
                parent_table_area.push_back(current_column++);  //update_parent_selector[i]
            }

            if( mode == state_table_mode::timeline ){
                lookup_table("zkevm_state_timeline", std::vector<std::size_t>({0,1,2}), 0, max_state);
            }
            if( mode == state_table_mode::opcode ){
                std::vector<std::size_t> opcode_table_area;
                for( std::size_t i = 0; i < state_table::get_witness_amount(mode); i++ ){
                    opcode_table_area.push_back(i);
                }
                lookup_table("zkevm_state_opcode",opcode_table_area,0,max_state);
            }
            if( mode == state_table_mode::full ){
                lookup_table("zkevm_state",state_table_area, 0, max_state);
                lookup_table("zkevm_state_parent",parent_table_area, 0, max_state);
            }
        }

        static std::vector<TYPE> access_list_lookup(
            TYPE call_id,
            const std::array<TYPE, 10> &call_context_address, // 10 chunks
            TYPE field,
            const std::array<TYPE, 16> &K, // 16 chunks
            TYPE rw_counter,
            TYPE value,
            TYPE previous_value,
            TYPE initial_value
        ){
            std::vector<TYPE> result;
            result.push_back(TYPE(1)); // It's original change, not call_commit
            result.push_back(TYPE(std::size_t(rw_operation_type::access_list)));
            result.push_back(call_id); // All state changes are grouped by block
            result.insert(result.end(), call_context_address.begin(), call_context_address.end());
            result.push_back(field); // field
            result.insert(result.end(), K.begin(), K.end()); // storage_key_hi, storage_key
            result.push_back(rw_counter); // rw_id
            result.push_back(TYPE(1)); // always write for access list
            for( std::size_t i = 0; i < 15; i++ ) result.push_back(TYPE(0));
            result.push_back(value);
            for( std::size_t i = 0; i < 15; i++ ) result.push_back(TYPE(0));
            result.push_back(previous_value);
            for( std::size_t i = 0; i < 15; i++ ) result.push_back(TYPE(0));
            result.push_back(initial_value);
            return result;
        }

        static std::vector<TYPE> storage_read_lookup(
            TYPE call_id,
            const std::array<TYPE, 10> &call_context_address, // 10 chunks
            const std::array<TYPE, 16> &K, // 16 chunks
            TYPE rw_counter,
            const std::array<TYPE, 16> &value,
            const std::array<TYPE, 16> &initial_value
        ){
            std::vector<TYPE> result;
            result.push_back(TYPE(1)); // It's original change, not call_commit
            result.push_back(TYPE(std::size_t(rw_operation_type::state)));
            result.push_back(call_id); // All state changes are grouped by block
            result.insert(result.end(), call_context_address.begin(), call_context_address.end());
            result.push_back(TYPE(0)); // field
            result.insert(result.end(), K.begin(), K.end()); // storage_key_hi, storage_key
            result.push_back(rw_counter); // rw_id
            result.push_back(TYPE(0));      // is_write
            result.insert(result.end(), value.begin(), value.end()); // value_
            result.insert(result.end(), value.begin(), value.end()); // it's read operation, so, previous_value equals value
            result.insert(result.end(), initial_value.begin(), initial_value.end()); // initial_value
            return result;
        }

        static std::vector<TYPE> storage_write_lookup(
            TYPE call_id,
            const std::array<TYPE, 10> &call_context_address, // 10 chunks
            const std::array<TYPE, 16> &K, // 16 chunks
            TYPE rw_counter,
            const std::array<TYPE, 16> &value,
            const std::array<TYPE, 16> &previous_value,
            const std::array<TYPE, 16> &initial_value
        ){
            std::vector<TYPE> result;
            result.push_back(TYPE(1)); // It's original change, not call_commit
            result.push_back(TYPE(std::size_t(rw_operation_type::state)));
            result.push_back(call_id); // All state changes are grouped by block
            result.insert(result.end(), call_context_address.begin(), call_context_address.end());
            result.push_back(TYPE(0)); // field
            result.insert(result.end(), K.begin(), K.end()); // storage_key_hi, storage_key
            result.push_back(rw_counter); // rw_id
            result.push_back(TYPE(1));      // is_write
            result.insert(result.end(), value.begin(), value.end()); // value_
            result.insert(result.end(), previous_value.begin(), previous_value.end()); // it's read operation, so, previous_value equals value
            result.insert(result.end(), initial_value.begin(), initial_value.end()); // initial_value
            return result;
        }
    };
}