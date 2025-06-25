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

#include<nil/blueprint/zkevm_bbf/types/short_rw_operation.hpp>

namespace nil::blueprint::bbf::zkevm_small_field{
    template<typename FieldType, GenerationStage stage>
    class rw_256_table_instance : public generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;
    public:
        using typename generic_component<FieldType,stage>::TYPE;
        using input_type = typename std::conditional<stage==GenerationStage::ASSIGNMENT, short_rw_operations_vector, std::nullptr_t>::type;
        using integral_type =  nil::crypto3::multiprecision::big_uint<257>;
    protected:
        std::size_t start;                              // first index used in rw_trace building
        std::size_t end;                                // last assigned operation in rw_trace
        std::size_t max_rw_size;                        // rows_amount
    public:
        // rw_table_256
        std::vector<TYPE> op;                           // stack, call_context
        std::vector<TYPE> id;                           // 2 chunks fitted in field element less than 2^25
        std::vector<TYPE> address;                      // < 1024
        std::vector<TYPE> rw_id;                        // 2 chunks fitted in field element less than 2^25
        std::vector<TYPE> is_write;                     // bool
        std::vector<std::array<TYPE, 16>> value;        // 16 chunks
        std::vector<TYPE> internal_counter;             // 2  chunks fitted in field element less than 2^25
        std::vector<TYPE> is_filled;                    // bool

        static std::size_t get_witness_amount(){
            return 21;
        }

        std::size_t get_start_index() const {
            return start;
        }

        std::size_t get_last_assigned_index() const {
            return end;
        }

        std::size_t get_max_rw_size() const {
            return max_rw_size;
        }

        rw_256_table_instance(
            context_type &context_object,
            const input_type &input,
            std::size_t _max_rw_size,
            std::size_t _start
        ) :generic_component<FieldType,stage>(context_object),
            max_rw_size(_max_rw_size),
            start(_start),
            op(max_rw_size),
            id(max_rw_size),
            address(max_rw_size),
            rw_id(max_rw_size),
            is_write(max_rw_size),
            value(max_rw_size),
            internal_counter(max_rw_size),
            is_filled(max_rw_size)
        {
            if constexpr  (stage == GenerationStage::ASSIGNMENT) {
                auto rw_trace = input;
                std::size_t current_row = 0;
                std::size_t current_op = start;

                while( current_row < max_rw_size && current_op < rw_trace.size() ){
                    const auto &rwop = rw_trace[current_op];
                    current_op++;
                    if(
                        rwop.op != rw_operation_type::start
                        && rwop.op != rw_operation_type::call_context
                        && rwop.op != rw_operation_type::stack
                    ) {
                        continue;
                    }
                    end = current_op - 1; // last assigned operation in rw_trace
                    op[current_row] = std::size_t(rwop.op);
                    id[current_row] = rwop.id;
                    address[current_row] = integral_type(rwop.address);
                    is_write[current_row] = rwop.is_write;
                    rw_id[current_row] = rwop.rw_counter;
                    auto v = w_to_16(rwop.value);
                    for( std::size_t j = 0; j < 16; j++ ){
                        value[current_row][j] = v[j];
                    }
                    BOOST_LOG_TRIVIAL(trace) << "rw_256_op " << current_row << ": " << std::hex << rwop << std::dec;
                    current_row++;
                }
                if( current_op == rw_trace.size() ||
                    std::size_t(rw_trace[current_op].op) > std::size_t(rw_operation_type::stack)
                ) end = rw_trace.size();
                if( end != rw_trace.size() ) BOOST_LOG_TRIVIAL(trace) << "Last opertaion " << current_op << "." << rw_trace[current_op];
                BOOST_LOG_TRIVIAL(trace) << "rw_256 filled rows amount = " << current_row;
                for( std::size_t i = current_row; i < max_rw_size; i++ ){
                    op[i] = std::size_t(rw_operation_type::padding);
                }
            }

            for( std::size_t i = 0; i < max_rw_size; i++ ){
                std::size_t current_column = 0;
                allocate(op[i], current_column++, i);                       // 0
                allocate(id[i], current_column++, i);                       // 1
                allocate(address[i], current_column++, i);                  // 2
                allocate(rw_id[i], current_column++, i);                    // 3
                allocate(is_write[i], current_column++, i);                 // 4
                for(std::size_t j = 0; j < 16; j++)
                    allocate(value[i][j], current_column++, i);             // 5 - 21
            }

        }

        static constexpr std::size_t get_rw_id_column_index() {
            return 3;
        }
    };

    template<typename FieldType, GenerationStage stage>
    class rw_256_table : public generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;
        using generic_component<FieldType, stage>::multi_lookup_table;
    public:
        using typename generic_component<FieldType,stage>::TYPE;
        using input_type = typename std::conditional<stage==GenerationStage::ASSIGNMENT, short_rw_operations_vector, std::nullptr_t>::type;
        using integral_type =  nil::crypto3::multiprecision::big_uint<257>;
        using InstanceType = rw_256_table_instance<FieldType, stage>;
    public:
        static std::size_t get_witness_amount(std::size_t instances_rw_256){
            return instances_rw_256 * InstanceType::get_witness_amount();
        }

        std::vector<InstanceType> instances;
        std::vector<std::vector<std::size_t>> rw_256_table_areas;

        rw_256_table(
            context_type &context_object,
            const input_type &input,
            std::size_t max_rw_size,
            std::size_t instances_rw_256
        ) : generic_component<FieldType,stage>(context_object),
            rw_256_table_areas(instances_rw_256)
        {
            std::size_t current_column = 0;

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                BOOST_ASSERT(input[0].op == rw_operation_type::start);
            }
            for( std::size_t i = 0; i < instances_rw_256; i++ ){
                rw_256_table_areas[i].resize(InstanceType::get_witness_amount());
                for( std::size_t j = 0; j < InstanceType::get_witness_amount(); j++ ){
                    rw_256_table_areas[i][j] = current_column++;
                }
                context_type instance_context = context_object.subcontext(rw_256_table_areas[i], 0, max_rw_size);
                instances.emplace_back(
                    instance_context,
                    input,
                    max_rw_size,
                    i == 0 ? 0 : instances[i - 1].get_last_assigned_index()
                );
            }
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                if( instances.back().get_last_assigned_index() < input.size() ) {
                    std::size_t need_more = 0;
                    for( std::size_t i = instances.back().get_last_assigned_index(); i < input.size(); i++ ){
                        if(
                            input[i].op == rw_operation_type::stack ||
                            input[i].op == rw_operation_type::call_context
                        ) {
                            need_more++;
                        }
                    }
                    BOOST_LOG_TRIVIAL(fatal) << "Not enough space in rw_256 table. "
                        << "max_rw_size: " << max_rw_size << ", "
                        << "instances_rw_256: " << instances_rw_256 << ", "
                        << "need to assign more " << need_more << " operations";

                    BOOST_ASSERT(false);
                }
            }
            multi_lookup_table("zkevm_rw_256", rw_256_table_areas, 0, max_rw_size);
        }


        static std::vector<TYPE> call_context_read_only_one_chunk_lookup(
            TYPE call_id,
            std::size_t field,
            TYPE value
        ){
            std::vector<TYPE> result = {
                TYPE(std::size_t(rw_operation_type::call_context)),
                call_id,
                TYPE(field),                                          // address
                call_id + field,                                      // rw_id
                TYPE(0),                                              // is_write
            };
            for( std::size_t i = 0; i < 15; i++ ){
                result.push_back(TYPE(0));
            }
            result.push_back(value);
            return result;
        }

        // Used for addresses
        static std::vector<TYPE> call_context_read_only_16_bit_lookup(
            TYPE call_id,
            std::size_t field,
            const std::array<TYPE, 10> &value
        ){
            std::vector<TYPE> result = {
                TYPE(std::size_t(rw_operation_type::call_context)),
                call_id,
                TYPE(field),                                          // address
                call_id + field,                                      // rw_id
                TYPE(0),                                              // is_write
            };
            for( std::size_t i = 0; i < 6; i++ ){
                result.push_back(TYPE(0));
            }
            for( std::size_t i = 0; i < 10; i++ ){
                result.push_back(value[i]);
            }
            return result;
        }

        static std::vector<TYPE> call_context_read_only_16_bit_lookup(
            TYPE call_id,
            std::size_t field,
            const std::array<TYPE, 16> &value
        ){
            std::vector<TYPE> result = {
                TYPE(std::size_t(rw_operation_type::call_context)),
                call_id,
                TYPE(field),                                          // address
                call_id + field,                                      // rw_id
                TYPE(0),                                              // is_write
            };
            for( std::size_t i = 0; i < 16; i++ ){
                result.push_back(value[i]);
            }
            return result;
        }

        // static std::vector<TYPE> call_context_lookup(
        //     TYPE call_id,
        //     std::size_t field,
        //     TYPE value_hi,
        //     TYPE value_lo
        // ){
        //     return {
        //         TYPE(std::size_t(rw_operation_type::call_context)),
        //         call_id,
        //         TYPE(field),                                          // address
        //         call_id + field,                                      // rw_id
        //         TYPE(0),                                              // is_write
        //         value_hi,
        //         value_lo
        //     };
        // }

        // static std::vector<TYPE> call_context_editable_lookup(
        //     TYPE call_id,
        //     std::size_t field,
        //     TYPE rw_counter,
        //     TYPE is_write,
        //     TYPE value_hi,
        //     TYPE value_lo
        // ){
        //     return {
        //         TYPE(std::size_t(rw_operation_type::call_context)),
        //         call_id,
        //         TYPE(field),                                                          // address
        //         rw_counter,                                                           // rw_id
        //         is_write,                                                             // is_write
        //         value_hi,
        //         value_lo
        //     };
        // }

        static std::vector<TYPE> stack_16_bit_lookup(
            TYPE call_id,
            TYPE stack_pointer,
            TYPE rw_counter,
            TYPE is_write,
            std::vector<TYPE> value
        ){
            BOOST_ASSERT(value.size() == 16);
            std::vector<TYPE> result = {
                TYPE(std::size_t(rw_operation_type::stack)),
                call_id,
                stack_pointer,
                rw_counter,
                is_write
            };
            for( std::size_t i = 0; i < 16; i++ ){
                result.push_back(value[i]);
            }
            return result;
        }

        static std::vector<TYPE> stack_16_bit_lookup(
            TYPE call_id,
            TYPE stack_pointer,
            TYPE rw_counter,
            TYPE is_write,
            std::array<TYPE,16> value
        ){
            std::vector<TYPE> result = {
                TYPE(std::size_t(rw_operation_type::stack)),
                call_id,
                stack_pointer,
                rw_counter,
                is_write
            };
            for( std::size_t i = 0; i < 16; i++ ){
                result.push_back(value[i]);
            }
            return result;
        }

        static std::vector<TYPE> stack_one_chunk_lookup(
            TYPE call_id,
            TYPE stack_pointer,
            TYPE rw_counter,
            TYPE is_write,
            TYPE value
        ){
            std::vector<TYPE> result = {
                TYPE(std::size_t(rw_operation_type::stack)),
                call_id,
                stack_pointer,
                rw_counter,
                is_write
            };
            for( std::size_t i = 0; i < 15; i++ ){
                result.push_back(TYPE(0));
            }
            result.push_back(value);
            return result;
        }

        static std::vector<TYPE> stack_16_bit_lookup_reversed(
            TYPE call_id,
            TYPE stack_pointer,
            TYPE rw_counter,
            TYPE is_write,
            std::array<TYPE,16> value
        ){
            std::vector<TYPE> result = {
                TYPE(std::size_t(rw_operation_type::stack)),
                call_id,
                stack_pointer,
                rw_counter,
                is_write
            };
            for( std::size_t i = 0; i < 16; i++ ){
                result.push_back(value[15 - i]);
            }
            return result;
        }

        static std::vector<TYPE> stack_16_bit_lookup_reversed(
            TYPE call_id,
            TYPE stack_pointer,
            TYPE rw_counter,
            TYPE is_write,
            const std::vector<TYPE> &value
        ){
            BOOST_ASSERT(value.size() == 16);
            std::vector<TYPE> result = {
                TYPE(std::size_t(rw_operation_type::stack)),
                call_id,
                stack_pointer,
                rw_counter,
                is_write
            };
            for( std::size_t i = 0; i < 16; i++ ){
                result.push_back(value[15 - i]);
            }
            return result;
        }

        static std::vector<TYPE> stack_8_bit_lookup(
            TYPE call_id,
            TYPE stack_pointer,
            TYPE rw_counter,
            TYPE is_write,
            std::array<TYPE,32> value
        ){
            std::vector<TYPE> result = {
                TYPE(std::size_t(rw_operation_type::stack)),
                call_id,
                stack_pointer,
                rw_counter,
                is_write
            };
            for( std::size_t i = 0; i < 32; i += 2 ){
                result.push_back(value[i] * 256 + value[i+1]);
            }
            return result;
        }

        std::size_t get_rw_id_column_index(std::size_t instance_index) {
            BOOST_ASSERT(instance_index < instances.size());
            return rw_256_table_areas[instance_index][InstanceType::get_rw_id_column_index()];
        }
    };
}