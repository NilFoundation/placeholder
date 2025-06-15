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
    class rw_8_table_instance : public generic_component<FieldType, stage> {
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
        // rw_8
        std::vector<TYPE> op;                           // memory, calldata, returndata
        std::vector<TYPE> id;                           // 2 chunks fitted in field element less than 2^25
        std::vector<TYPE> address;                      // 1 chunk
        std::vector<TYPE> rw_id;                        // 2 chunks fitted in field element less than 2^25
        std::vector<TYPE> is_write;                     // bool
        std::vector<TYPE> value;                        // 1 byte
        std::vector<TYPE> internal_counter;             // 2  chunks fitted in field element less than 2^25
        std::vector<TYPE> is_filled;                    // bool

        static std::size_t get_witness_amount(){
            return 6;
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

        rw_8_table_instance(
            context_type &context_object,
            const input_type &input,
            std::size_t _max_rw_size,
            std::size_t _start
        ) :generic_component<FieldType,stage>(context_object),
            max_rw_size(_max_rw_size),
            end(0),
            op(max_rw_size),
            id(max_rw_size),
            address(max_rw_size),
            rw_id(max_rw_size),
            is_write(max_rw_size),
            value(max_rw_size),
            internal_counter(max_rw_size),
            is_filled(max_rw_size),
            start(_start)
        {
            if constexpr  (stage == GenerationStage::ASSIGNMENT) {
                BOOST_ASSERT(input[0].op == rw_operation_type::start);

                std::size_t current_row = 0;
                std::size_t current_op = start;

                while( current_row < max_rw_size && current_op < input.size() ){
                    const auto &rwop = input[current_op];
                    current_op++;

                    if(
                        rwop.op != rw_operation_type::start
                        && rwop.op != rw_operation_type::memory
                        && rwop.op != rw_operation_type::calldata
                        && rwop.op != rw_operation_type::returndata
                    ) {
                        continue;
                    }
                    end = current_op - 1; // last assigned operation in rw_trace
                    op[current_row] = std::size_t(rwop.op);
                    id[current_row] = rwop.id;
                    address[current_row] = integral_type(rwop.address);
                    is_write[current_row] = rwop.is_write;
                    rw_id[current_row] = rwop.rw_counter;
                    value[current_row] = rwop.value;

                    BOOST_LOG_TRIVIAL(trace) << "rw_8_op " << current_row << " : " << std::hex << rwop;
                    current_row++;
                }
                if( current_op == input.size() ) end = input.size();
                BOOST_LOG_TRIVIAL(trace) << "rw_8 filled rows amount = " << current_row;
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
                allocate(value[i], current_column++, i);                    // 5
                // allocate(is_filled[i], current_column++, i);                // 6
                // allocate(internal_counter[i], current_column++, i);         // 7
            }
        }

        static std::vector<std::size_t> get_zkevm_rw_8_lookup_columns() {
            return {0, 1, 2, 3, 4, 5};
        }

        static std::size_t get_rw_id_column_index() {
            return 3;
        }
    };

    template<typename FieldType, GenerationStage stage>
    class rw_8_table : public generic_component<FieldType, stage> {
         using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::multi_lookup_table;
    public:
        using typename generic_component<FieldType,stage>::TYPE;
        using input_type = typename std::conditional<stage==GenerationStage::ASSIGNMENT, short_rw_operations_vector, std::nullptr_t>::type;
        using integral_type =  nil::crypto3::multiprecision::big_uint<257>;
    public:
        using InstanceType = rw_8_table_instance<FieldType, stage>;

        static std::size_t get_witness_amount(std::size_t instances_rw_8){
            return  InstanceType::get_witness_amount() * instances_rw_8;
        }

        std::vector<InstanceType> instances;
        std::vector<std::vector<std::size_t>> rw_8_lookup_areas;

        std::size_t get_rw_id_column_index(std::size_t instance_id) const {
            BOOST_ASSERT(instance_id < rw_8_lookup_areas.size());
            return rw_8_lookup_areas[instance_id][InstanceType::get_rw_id_column_index()];
        }

        rw_8_table(
            context_type &context_object,
            const input_type &input,
            std::size_t max_rw_size,
            std::size_t instances_rw_8
        ) :generic_component<FieldType,stage>(context_object),
            rw_8_lookup_areas(instances_rw_8)
        {
            std::vector<std::vector<std::size_t>>instance_areas(instances_rw_8);
            std::size_t current_column = 0;
            std::size_t starting_internal_counter = 0;

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                // if( input.size() >= max_rw_size * instances_rw_8 ){
                //     BOOST_LOG_TRIVIAL(fatal) << "Not enough space in rw_8 dynamic table. " <<
                //         "Input size: " << input.size() << ", "
                //         "max_rw_size: " << max_rw_size << ", "
                //         "instances_rw_8: " << instances_rw_8;
                // }
                // BOOST_ASSERT(input.size() < max_rw_size * instances_rw_8);
                for( std::size_t i = 0; i < input.size(); i++ ){
                    if(
                        input[i].op == rw_operation_type::memory ||
                        input[i].op == rw_operation_type::calldata ||
                        input[i].op == rw_operation_type::returndata
                    ) {
                        starting_internal_counter = input[i].internal_counter - 1;
                        break;
                    }
                }
                BOOST_LOG_TRIVIAL(trace) << "starting_internal_counter = " << std::hex << starting_internal_counter;
            }
            for( std::size_t i = 0; i < instances_rw_8; i++ ){
                for( std::size_t j = 0; j < InstanceType::get_witness_amount(); j++ ){
                    instance_areas[i].push_back(current_column++);
                }
                for( auto j: InstanceType::get_zkevm_rw_8_lookup_columns() ) {
                    rw_8_lookup_areas[i].push_back(instance_areas[i][j]);
                }
                context_type instance_context = context_object.subcontext(instance_areas[i], 0, max_rw_size);
                instances.emplace_back(
                    instance_context, input,
                    max_rw_size,
                    i==0? 0: instances[i-1].get_last_assigned_index()
                );
            }
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                if( instances.back().get_last_assigned_index() < input.size() ) {
                    std::size_t need_more = 0;
                    for( std::size_t i = instances.back().get_last_assigned_index(); i < input.size(); i++ ){
                        if(
                            input[i].op == rw_operation_type::memory ||
                            input[i].op == rw_operation_type::calldata ||
                            input[i].op == rw_operation_type::returndata
                        ) {
                            need_more++;
                        }
                    }
                    BOOST_LOG_TRIVIAL(fatal) << "Not enough space in rw_8 table. "
                        << "max_rw_size: " << max_rw_size << ", "
                        << "instances_rw_8: " << instances_rw_8 << ", "
                        << "need to assign more " << need_more << " operations";
                    BOOST_ASSERT(false);
                }
            }
            multi_lookup_table("zkevm_rw_8", rw_8_lookup_areas, 0, max_rw_size);
        }

        static std::vector<TYPE> memory_lookup(
            TYPE call_id,
            TYPE memory_address,
            TYPE rw_counter,
            TYPE is_write,
            TYPE value_lo
        ){
            return {
                TYPE(std::size_t(rw_operation_type::memory)),
                call_id,
                memory_address,
                rw_counter,
                is_write,
                value_lo
            };
        }

        static std::vector<TYPE> calldata_r_lookup(
            TYPE call_id,
            TYPE calldata_address,
            TYPE rw_counter,
            TYPE value_lo
        ){
            return {
                TYPE(std::size_t(rw_operation_type::calldata)),
                call_id,
                calldata_address,
                rw_counter,
                TYPE(0),              // is_write
                value_lo
            };
        }

        static std::vector<TYPE> calldata_lookup(
            TYPE call_id,
            TYPE calldata_address,
            TYPE rw_counter,
            TYPE is_write,
            TYPE value_lo
        ){
            return {
                TYPE(std::size_t(rw_operation_type::calldata)),
                call_id,
                calldata_address,
                rw_counter,
                is_write,
                value_lo
            };
        }

        static std::vector<TYPE> returndata_r_lookup(
            TYPE call_id,
            TYPE returndata_address,
            TYPE rw_counter,
            TYPE value_lo
        ){
            return {
                TYPE(std::size_t(rw_operation_type::returndata)),
                call_id,
                returndata_address,
                rw_counter,
                TYPE(0),              // is_write
                value_lo
            };
        }

        static std::vector<TYPE> returndata_lookup(
            TYPE call_id,
            TYPE returndata_address,
            TYPE rw_counter,
            TYPE is_write,
            TYPE value_lo
        ){
            return {
                TYPE(std::size_t(rw_operation_type::returndata)),
                call_id,
                returndata_address,
                rw_counter,
                is_write,
                value_lo
            };
        }
    };
}