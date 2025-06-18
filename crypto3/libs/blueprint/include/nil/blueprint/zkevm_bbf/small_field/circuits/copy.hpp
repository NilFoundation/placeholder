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

#include <nil/blueprint/zkevm_bbf/small_field/tables/keccak.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/tables/bytecode.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/tables/rw_8.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/tables/copy.hpp>

namespace nil::blueprint::bbf::zkevm_small_field{
    template<typename FieldType, GenerationStage stage>
    class copy_instance : public generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

    public:
        using typename generic_component<FieldType, stage>::table_params;
        using typename generic_component<FieldType,stage>::TYPE;
        using integral_type =  nil::crypto3::multiprecision::big_uint<257>;

        struct input_type {
            TYPE rlc_challenge;
            std::conditional_t<stage == GenerationStage::ASSIGNMENT, const std::vector<copy_event>&, std::monostate> copy_events;
        };

        static constexpr std::size_t copy_table_advice_amount = 5;
        static constexpr std::size_t copy_advice_amount = 9;
        static std::size_t get_witness_amount() {
            return copy_advice_amount + copy_operand_types_amount;
        }

    protected:
        std::size_t last_event;
        std::size_t last_byte_index;

    public:
        std::size_t get_last_assigned_event() const {
            return last_event;
        }
        std::size_t get_last_assigned_byte_index() const {
            return last_byte_index;
        }

        std::vector<TYPE> is_first;           // 0
        std::vector<TYPE> is_write;           // 1
        std::vector<TYPE> cp_type;            // 2
        std::vector<TYPE> id;                 // 3
        std::vector<TYPE> counter_1;          // 4
        std::vector<TYPE> counter_2;          // 5
        std::vector<TYPE> length;             // 6
        std::vector<TYPE> value;              // 7
        std::vector<TYPE> rlc;                // 8
        std::vector<TYPE> is_last;            // 9
        std::vector<std::array<TYPE, copy_operand_types_amount>> type_selector;

        TYPE current_rlc;

        std::size_t is_first_index;
        std::size_t is_write_index;
        std::size_t cp_type_index;
        std::size_t id_index;
        std::size_t counter_1_index;
        std::size_t counter_2_index;
        std::size_t length_index;

        copy_instance(context_type &context_object,
            const input_type &input,
            const std::vector<TYPE> &rlc_challenge,
            const std::vector<TYPE> &src_id,
            const std::vector<TYPE> &dst_id,
            TYPE  start_rlc,
            std::size_t max_copy_rows,
            std::size_t start_event_index,
            std::size_t start_event_byte
        ) :generic_component<FieldType,stage>(context_object),
            is_first(max_copy_rows),
            is_write(max_copy_rows),
            cp_type(max_copy_rows),
            id(max_copy_rows),
            counter_1(max_copy_rows),
            counter_2(max_copy_rows),
            length(max_copy_rows),
            value(max_copy_rows),
            rlc(max_copy_rows),
            is_last(max_copy_rows),
            type_selector(max_copy_rows)
        {
            // auto zerohash = w_to_16(zkevm_keccak_hash({}));
            BOOST_LOG_TRIVIAL(trace) << "Copy instance" << std::endl;

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                std::size_t current_row = 0;

                current_row = 0;
                std::size_t current_event = start_event_index;
                std::size_t current_byte_index = start_event_byte;
                bool is_first_byte = (current_byte_index == 0);
                current_rlc = start_rlc;
                last_event = current_event;
                last_byte_index = current_byte_index;

                std::size_t src_counter_1;
                std::size_t src_counter_2;
                std::size_t dst_counter_1;
                std::size_t dst_counter_2;

                while( current_row < max_copy_rows ){
                    if( current_event >= input.copy_events.size() ) {
                        current_rlc = 0;
                        last_event = input.copy_events.size();
                        break;
                    }
                    if( current_byte_index >= input.copy_events[current_event].length ) {
                        current_event++;
                        current_byte_index = 0;
                        is_first_byte = true;
                    }
                    if( current_event >= input.copy_events.size() ) {
                        current_rlc = 0;
                        last_event = input.copy_events.size();
                        break;
                    }
                    const auto &cp = input.copy_events[current_event];

                    if( is_first_byte ){
                        BOOST_LOG_TRIVIAL(debug)
                            << "\tCopy event " << copy_op_to_string(cp.source_type)
                            << " => " << copy_op_to_string(cp.destination_type)
                            << " data size " << cp.size()
                            << std::endl;
                        is_first_byte = false;
                        is_first[current_row] = 1;
                        is_first[current_row + 1] = 1;
                    }
                    src_counter_1 = cp.src_counter_1 + current_byte_index;
                    src_counter_2 = cp.src_counter_2 + current_byte_index;
                    dst_counter_1 = cp.dst_counter_1 + current_byte_index;
                    dst_counter_2 = cp.dst_counter_2 + current_byte_index;

                    cp_type[current_row] = copy_op_to_num(cp.source_type);
                    cp_type[current_row + 1] = copy_op_to_num(cp.destination_type);

                    id[current_row] = src_id[current_event];
                    id[current_row+1] = dst_id[current_event];

                    counter_1[current_row] = src_counter_1;
                    counter_2[current_row] = src_counter_2;
                    counter_1[current_row + 1] = dst_counter_1;
                    counter_2[current_row + 1] = dst_counter_2;
                    length[current_row] = cp.length - current_byte_index;
                    length[current_row + 1] = cp.length - current_byte_index;
                    value[current_row] = cp.get_value(current_byte_index);
                    value[current_row + 1] = cp.get_value(current_byte_index);

                    if( current_byte_index == 0){
                        rlc[current_row] = length[current_row] * rlc_challenge[current_row];
                    } else if ( current_row == 0 ){
                        rlc[current_row] = start_rlc * rlc_challenge[current_row];
                    } else {
                        rlc[current_row] = rlc[current_row - 1] * rlc_challenge[current_row];
                    }
                    rlc[current_row + 1] = rlc[current_row] + value[current_row];
                    current_rlc = current_row == 0? start_rlc: rlc[current_row - 1];

                    type_selector[current_row][copy_op_to_num(cp.source_type) - 1] = 1;
                    type_selector[current_row + 1][copy_op_to_num(cp.destination_type) - 1] = 1;

                    if( current_byte_index == cp.length - 1) {
                        is_last[current_row + 1] = 1;
                    }

                    BOOST_LOG_TRIVIAL(debug) << "\t\t" << current_row << ". "
                        << std::hex
                        << id[current_row] << " " << counter_1[current_row] << " " << counter_2[current_row] << "    "
                        << id[current_row + 1] << " " << counter_1[current_row+1] << " " << counter_2[current_row+1] << "    "
                        << cp.get_key(current_byte_index) <<  " => "
                        << cp.get_value(current_byte_index) << std::dec
                        << " length " << length[current_row] << " " << length[current_row + 1]
                        << " rlc " << rlc[current_row] << " => " << rlc[current_row + 1];

                    src_counter_1++;
                    src_counter_2++;
                    dst_counter_1++;
                    dst_counter_2++;
                    last_event = current_event;
                    last_byte_index = current_byte_index;
                    current_byte_index++;
                    current_row += 2;
                }
            }
            for( std::size_t i = 0; i < max_copy_rows; i++){
                if constexpr ( stage == GenerationStage::ASSIGNMENT) {
                    is_write[i] = i%2;
                }
                std::size_t current_column = 0;

                is_first_index = current_column; allocate(is_first[i], current_column++, i);
                is_write_index = current_column; allocate(is_write[i], current_column++, i);
                cp_type_index = current_column;  allocate(cp_type[i], current_column++, i);
                id_index = current_column;  allocate(id[i], current_column++, i);
                counter_1_index = current_column;  allocate(counter_1[i], current_column++, i);
                counter_2_index = current_column;  allocate(counter_2[i], current_column++, i);
                length_index = current_column;  allocate(length[i], current_column++, i);
                for(std::size_t j = 0; j < copy_operand_types_amount - 1; j++){ // Without padding
                    allocate(type_selector[i][j], current_column++, i);
                }
                allocate(value[i], current_column++, i);

                allocate(rlc[i],current_column++, i);
                allocate(is_last[i], current_column++, i);
            }
            if constexpr( stage == GenerationStage::CONSTRAINTS ){
                std::vector<std::pair<TYPE, std::string>> even;
                std::vector<std::pair<TYPE, std::string>> odd;
                std::vector<std::pair<TYPE, std::string>> every;
                std::vector<std::pair<TYPE, std::string>> not_first;
                std::vector<std::pair<TYPE, std::string>> not_first_and_not_last;
                std::vector<std::pair<TYPE, std::string>> not_first_even;
                std::vector<std::pair<TYPE, std::string>> not_last_odd;

                every.push_back({is_write[1]  * (is_write[1] - 1), "Is_write is 0 or 1"});
                every.push_back({is_first[1]  * (is_first[1] - 1), "Is_first is 0 or 1"});
                every.push_back({is_last[1]  * (is_last[1] - 1), "Is_last is 0 or 1"});

                TYPE type_selector_sum;
                TYPE cp_type_constraint;
                for(std::size_t j = 0; j < copy_operand_types_amount; j++){
                    type_selector_sum += type_selector[1][j];
                    cp_type_constraint += (j+1) * type_selector[1][j];
                    every.push_back({type_selector[1][j]  * (type_selector[1][j] - 1), "Type selector is 0 or 1"});
                }
                every.push_back({type_selector_sum  * (type_selector_sum - 1), "Only one type selector in the row may be 1"});
                every.push_back({cp_type_constraint - cp_type[1], "cp_type is correctly defined by type_selector"});
                every.push_back({(type_selector_sum - 1)* is_last[1], "is_last may be 1 only if one of selectors is 1"});
                every.push_back({(type_selector_sum - 1)* is_first[1], "is_first may be 1 only if one of selectors is 1"});

                not_first_and_not_last.push_back({(type_selector_sum - is_first[1] - is_last[1]) * (id[0] - id[2]), "Not first and not last: id before and after are equal"});
                not_first_and_not_last.push_back({(type_selector_sum - is_first[1] - is_last[1]) * (cp_type[0] - cp_type[2]), "Not first and not last: cp_type before and after are equal"});
                not_first_and_not_last.push_back({(type_selector_sum - is_first[1] - is_last[1]) * (counter_1[0] - counter_1[2] + 1), "Not first and not last: counter_1 increments"});
                not_first_and_not_last.push_back({(type_selector_sum - is_first[1] - is_last[1]) * (counter_2[0] - counter_2[2] + 1), "Not first and not last: counter_2 increments"});
                not_first_and_not_last.push_back({(type_selector_sum - is_first[1] - is_last[1]) * (length[0] - length[2] - 1), "Not first and not last: length before and after decreased"});

                even.push_back({is_write[1], "is_write is 0 on even rows"});
                even.push_back({is_last[1], "is_last is 0 on even rows"});
                even.push_back({is_first[1] * (rlc[1] - length[1] * rlc_challenge[1]), "If is_first then rlc equals length"});

                // TODO: Process first row where is_first = 0
                not_first_even.push_back({
                    (type_selector_sum - is_first[1]) * (rlc[1] - rlc[0] * rlc_challenge[1]),
                    "Not first event rows and not is_first then rlc = rlc_prev * rlc_challenge"
                });

                odd.push_back({1 - is_write[1], "Odd rows is_write is always 1"});
                odd.push_back({is_first[1] - is_first[0], "Odd rows is_first equals to previous"});
                odd.push_back({value[1] - value[0], "Odd rows value equals to previous"});
                odd.push_back({length[1] - length[0], "Odd rows length equals to previous"});
                odd.push_back({is_last[1] * (length[1] - 1),"Odd_rows. Is_last => length==1"});

                not_last_odd.push_back({type_selector_sum * (1 - is_last[1]) * (id[0] - id[2]),"Odd rows. If not is_last id_prev=id_next"});
                not_last_odd.push_back({type_selector_sum * (1 - is_last[1]) * (cp_type[0] - cp_type[2]),"Odd rows. If not is_last cp_type_prev=cp_type_next"});
                not_last_odd.push_back({type_selector_sum * (1 - is_last[1]) * (counter_1[0] - counter_1[2] + 1),"Odd rows. If not is_last, counter_1 increased"});
                not_last_odd.push_back({type_selector_sum * (1 - is_last[1]) * (counter_2[0] - counter_2[2] + 1),"Odd rows. If not is_last, counter_2 increased"});
                not_last_odd.push_back({type_selector_sum * (rlc[1] - rlc[0] - value[1]), "Odd rows. rlc = rlc_prev + value"});
                not_last_odd.push_back({type_selector_sum * (1 - is_last[1]) * (length[0] - length[2] - 1),"Odd rows. If not is_last length decreased"});

                TYPE memory_selector = type_selector[1][copy_op_to_num(copy_operand_type::memory) - 1];
                TYPE keccak_selector = type_selector[1][copy_op_to_num(copy_operand_type::keccak) - 1];
                TYPE bytecode_selector = type_selector[1][copy_op_to_num(copy_operand_type::bytecode) - 1];
                TYPE calldata_selector = type_selector[1][copy_op_to_num(copy_operand_type::calldata) - 1];
                TYPE returndata_selector = type_selector[1][copy_op_to_num(copy_operand_type::returndata) - 1];

                even.push_back({keccak_selector, "Keccak_selector is always 0 on even rows"});

                std::vector<TYPE> tmp;
                tmp = rw_8_table<FieldType, stage>::memory_lookup(
                    id[1],     // call_id
                    counter_1[1], // address
                    counter_2[1], // rw_counter
                    is_write[1],  // is_write
                    value[1]
                );
                for( std::size_t i = 0; i < tmp.size(); i++) tmp[i] = context_object.relativize(memory_selector*tmp[i], -1);
                context_object.relative_lookup(tmp, "zkevm_rw_8", 0, max_copy_rows - 1);

                // Used both for CALLx calldata writing and CALLDATACOPY calldata reading
                tmp = rw_8_table<FieldType, stage>::calldata_lookup(
                    id[1],
                    counter_1[1], // address
                    counter_2[1], // rw_counter
                    is_write[1],
                    value[1]
                );
                for( std::size_t i = 0; i < tmp.size(); i++) tmp[i] = context_object.relativize(calldata_selector*tmp[i], -1);
                context_object.relative_lookup(tmp, "zkevm_rw_8", 0, max_copy_rows);

                // Used both for RETURN, REVERT returndat writing and RETURNDATACOPY returndata reading
                tmp = rw_8_table<FieldType, stage>::returndata_lookup(
                    id[1],
                    counter_1[1], // address
                    counter_2[1], // rw_counter
                    is_write[1],  // is_write
                    value[1]
                );
                for( std::size_t i = 0; i < tmp.size(); i++) tmp[i] = context_object.relativize(returndata_selector*tmp[i], -1);
                context_object.relative_lookup(tmp, "zkevm_rw_8", 0, max_copy_rows);

                tmp = {
                    counter_1[1],   // offset
                    value[1],
                    id[1]
                };
                for( std::size_t i = 0; i < tmp.size(); i++) tmp[i] = context_object.relativize(bytecode_selector*tmp[i], -1);
                context_object.relative_lookup(tmp, "zkevm_bytecode_copy", 0, max_copy_rows - 1);

                // TODO: Move to  main object from instance
                tmp = {
                    is_first[1] * cp_type[0],
                    is_first[1] * id[0],
                    is_first[1] * counter_1[0],
                    is_first[1] * counter_2[0],
                    is_first[1] * cp_type[1],
                    is_first[1] * id[1],
                    is_first[1] * counter_1[1],
                    is_first[1] * counter_2[1],
                    is_first[1] * length[1]
                };
                for( std::size_t i = 0; i < tmp.size(); i++) tmp[i] = context_object.relativize(tmp[i], -1);
                // TODO: Circuit construction may be slow, optimize!
                for( std::size_t i = 1; i < max_copy_rows; i+=2 )
                    context_object.relative_lookup(tmp, "zkevm_rlc_copy", i);

                large_copy_table_columns = {
                    is_first_index,
                    is_write_index,
                    cp_type_index,
                    id_index,
                    counter_1_index,
                    counter_2_index,
                    length_index
                };

                for( std::size_t i = 0; i < even.size(); i++ ){
                    for( std::size_t j = 0; j < max_copy_rows-1; j+=2 ){
                        context_object.relative_constrain(context_object.relativize(even[i].first, -1), j, even[i].second);
                    }
                }
                for( std::size_t i = 0; i < not_first_even.size(); i++ ){
                    for( std::size_t j = 2; j < max_copy_rows-1; j+=2 ){
                        context_object.relative_constrain(context_object.relativize(not_first_even[i].first, -1), j, not_first_even[i].second);
                    }
                }
                for( std::size_t i = 0; i < odd.size(); i++ ){
                    for( std::size_t j = 1; j <= max_copy_rows-1; j+=2 ){
                        context_object.relative_constrain(context_object.relativize(odd[i].first, -1), j, odd[i].second);
                    }
                }
                for( std::size_t i = 0; i < not_last_odd.size(); i++ ){
                    for( std::size_t j = 1; j <= max_copy_rows-3; j+=2 ){
                        context_object.relative_constrain(context_object.relativize(not_last_odd[i].first, -1), j, not_last_odd[i].second);
                    }
                }
                for( std::size_t i = 0; i < every.size(); i++ ){
                    context_object.relative_constrain(context_object.relativize(every[i].first, -1), 0, max_copy_rows-1, every[i].second);
                }
                for( std::size_t i = 0; i < not_first.size(); i++ ){
                    context_object.relative_constrain(context_object.relativize(not_first[i].first, -1), 1, max_copy_rows-1, not_first[i].second);
                }
                for( std::size_t i = 0; i < not_first_and_not_last.size(); i++ ){
                    context_object.relative_constrain(context_object.relativize(not_first_and_not_last[i].first, -1), 1, max_copy_rows-2, not_first_and_not_last[i].second);
                }
            }
        }

    protected:
        std::vector<std::size_t> large_copy_table_columns;
    public:
        std::vector<std::size_t> get_large_copy_table_columns() const{
            return large_copy_table_columns;
        }
    };


    template<typename FieldType, GenerationStage stage>
    class copy : public generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;
        using generic_component<FieldType, stage>::multi_lookup_table;

    public:
        using BytecodeTable = bytecode_table<FieldType, stage>;
        using RWTable = rw_8_table<FieldType, stage>;
        using KeccakTable = keccak_table<FieldType, stage>;
        using CopyTable = copy_table<FieldType, stage>;

        using InstanceType = copy_instance<FieldType, stage>;

        using typename generic_component<FieldType, stage>::table_params;
        using typename generic_component<FieldType,stage>::TYPE;
        using integral_type =  nil::crypto3::multiprecision::big_uint<257>;

        struct input_type {
            TYPE rlc_challenge;

            BytecodeTable::input_type bytecodes;
            KeccakTable::private_input_type keccak_buffers;
            RWTable::input_type rw_operations;
            std::conditional_t<stage == GenerationStage::ASSIGNMENT, std::vector<copy_event>, std::monostate> copy_events;
        };

        static constexpr std::size_t copy_table_advice_amount = 5;
        static constexpr std::size_t copy_advice_amount = 25;

        static table_params get_minimal_requirements(
            std::size_t max_copy_events,
            std::size_t max_copy_rows,
            std::size_t instances_copy,
            std::size_t max_rw,
            std::size_t instances_rw_8,
            std::size_t max_keccak_blocks,
            std::size_t max_bytecode
        ) {
            // TODO: place copy table under keccak table
            // TODO: update when BytecodeTable will be multicolumn
            std::size_t witnesses = copy_table_advice_amount
                + InstanceType::get_witness_amount() * instances_copy
                + BytecodeTable::get_witness_amount()
                + RWTable::get_witness_amount(instances_rw_8)
                + KeccakTable::get_witness_amount()
                + CopyTable::get_witness_amount()
                + 1; // RLC challenge column
            BOOST_LOG_TRIVIAL(info) << "Copy circuit witness_amount = " << witnesses;
            return {
                .witnesses = witnesses,
                .public_inputs = 1,
                .constants = 0,
                .rows =  std::max(
                    std::max(max_copy_rows, max_rw),
                    std::max(max_keccak_blocks, max_bytecode)
                )
            };
        }

        static void allocate_public_inputs(
            context_type &context, input_type &input,
            std::size_t max_copy_events,
            std::size_t max_copy_rows,
            std::size_t instances_copy,
            std::size_t max_rw,
            std::size_t instances_rw_8,
            std::size_t max_keccak_blocks,
            std::size_t max_bytecode
        ) {
            context.allocate(input.rlc_challenge, 0, 0, column_type::public_input);
        }

        std::vector<InstanceType> instances;

        copy(context_type &context_object,
            const input_type &input,
            std::size_t max_copy_events,
            std::size_t max_copy_rows,
            std::size_t instances_copy,
            std::size_t max_rw,
            std::size_t instances_rw_8,
            std::size_t max_keccak_blocks,
            std::size_t max_bytecode
        ) :generic_component<FieldType,stage>(context_object) {
            auto zerohash = w_to_16(zkevm_keccak_hash({}));

            // Allocate places for dynamic lookups
            std::size_t current_column = 0;
            std::vector<std::size_t> copy_lookup_area;
            for( std::size_t i = 0; i < CopyTable::get_witness_amount(); i++){
                copy_lookup_area.push_back(current_column++);
            }
            context_type copy_ct = context_object.subcontext( copy_lookup_area, 0, max_copy_events);
            CopyTable c_t = CopyTable(copy_ct, {input.copy_events, input.bytecodes}, max_copy_events);

            std::vector<std::size_t> bytecode_lookup_area;
            for( std::size_t i = 0; i < BytecodeTable::get_witness_amount(); i++){
                bytecode_lookup_area.push_back(current_column++);
            }
            context_type bytecode_ct = context_object.subcontext(bytecode_lookup_area,0,max_bytecode);
            BytecodeTable bc_t = BytecodeTable(bytecode_ct, input.bytecodes, max_bytecode);

            std::vector<std::size_t> rw_lookup_area;
            for( std::size_t i = 0; i < RWTable::get_witness_amount(instances_rw_8); i++){
                rw_lookup_area.push_back(current_column++);
            }
            context_type rw_ct = context_object.subcontext(rw_lookup_area,0,max_rw);
            RWTable rw_t = RWTable(rw_ct, input.rw_operations, max_rw, instances_rw_8);

            std::vector<std::size_t> keccak_lookup_area;
            for( std::size_t i = 0; i < KeccakTable::get_witness_amount(); i++){
                keccak_lookup_area.push_back(current_column++);
            }
            context_type keccak_ct = context_object.subcontext( keccak_lookup_area, 0, max_copy_events * 2);
            KeccakTable k_t = KeccakTable(keccak_ct, {input.rlc_challenge, input.keccak_buffers}, max_keccak_blocks);

            // Allocate RLC challenge -- common column for all copy instances
            std::vector<TYPE> rlc_challenge(max_copy_rows);
            if constexpr (stage == GenerationStage::ASSIGNMENT)  {
                for( std::size_t i = 0; i < max_copy_rows; i++){
                    rlc_challenge[i] = input.rlc_challenge;
                }
            }
            std::size_t rlc_challenge_column = current_column++;
            for( std::size_t i = 0; i < max_copy_rows; i++){
                allocate(rlc_challenge[i], rlc_challenge_column, i);
            }
            copy_constrain(input.rlc_challenge, rlc_challenge[0]);
            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                context_object.relative_constrain(
                    context_object.relativize(rlc_challenge[1] - rlc_challenge[0], -1),
                    1, max_copy_rows - 1,
                    "All rlc challenge column cells are equal to public input rlc_challenge"
                );
            }

            // Additional witnesses next to copy table
            std::vector<TYPE> real_id(max_copy_events); // Id for bytecode, memory, calldata, returndata, RLC for keccak
            std::vector<TYPE> cp_type_keccak_inv(max_copy_events); // Inverse of copy operand type
            std::vector<TYPE> cp_type_inv(max_copy_events);
            std::vector<TYPE> is_keccak(max_copy_events); // Dynamic selector for lookup to keccak_table
            std::vector<TYPE> is_filled(max_copy_events);

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                std::size_t current_row = 0;
                for( std::size_t i = 0; i < input.copy_events.size(); i++){
                    const auto &cp = input.copy_events[i];

                    is_filled[i] = 1;
                    if( cp.destination_type == copy_operand_type::keccak ){
                        real_id[i] = calculateRLC<FieldType>(cp.get_bytes(), input.rlc_challenge);
                        is_keccak[i] = 1;
                    } else {
                        real_id[i] = c_t.dst_id[i][15];
                    }
                }
            }

            std::size_t real_id_index;
            for( std::size_t i = 0; i < max_copy_events; i++){
                std::size_t current_column = BytecodeTable::get_witness_amount()
                    + KeccakTable::get_witness_amount()
                    + RWTable::get_witness_amount(instances_rw_8)
                    + CopyTable::get_witness_amount() + 1;

                if constexpr ( stage == GenerationStage::ASSIGNMENT) {
                    cp_type_keccak_inv[i] = c_t.dst_type[i] - copy_op_to_num(copy_operand_type::keccak) == 0 ? 0 : (c_t.dst_type[i] - copy_op_to_num(copy_operand_type::keccak)).inversed();
                    cp_type_inv[i] = c_t.dst_type[i] == 0? 0: c_t.dst_type[i].inversed();
                }

                real_id_index = current_column++; allocate(real_id[i], real_id_index, i);
                allocate(is_keccak[i], current_column++, i);
                allocate(cp_type_keccak_inv[i], current_column++, i);
                allocate(is_filled[i], current_column++, i);
                allocate(cp_type_inv[i], current_column++, i);
            }

            if constexpr (stage == GenerationStage::CONSTRAINTS){
                std::vector<std::pair<TYPE, std::string>> for_table;
                for_table.push_back({
                    (1 - is_keccak[1]) - (c_t.dst_type[1] - copy_op_to_num(copy_operand_type::keccak)) * cp_type_keccak_inv[1],
                    "is_keccak is 1 if and only if dst_type is keccak"
                });
                for_table.push_back({is_keccak[1] * (is_keccak[1] - 1), "is_keccak may be only 0 or 1"});
                for_table.push_back({is_keccak[1] * cp_type_keccak_inv[1], "is keccak is 1 only if cp_type_keccak_inv is 0"});
                for_table.push_back({
                    is_keccak[1] * (c_t.dst_type[1] - copy_op_to_num(copy_operand_type::keccak)),
                    "is_keccak is 1 only if dst_type is keccak"}
                );
                for( std::size_t i = 0; i < 15; i++){
                    for_table.push_back({(1 - is_keccak[1]) * c_t.dst_id[1][i], "if not is_keccak then 15 chunks if id must be zero"});
                }
                for_table.push_back({
                    (1 - is_keccak[1]) * (c_t.dst_id[1][15] - real_id[1]),
                    "if not is_keccak then 16th chunk of dst_id must be equal to real_id"}
                );

                for_table.push_back({
                    is_filled[1] - c_t.dst_type[1] * cp_type_inv[1],
                    "Is filled is 1 only if and only if dst_type is not zero"}
                );
                for_table.push_back({is_filled[1] * (is_filled[1] - 1), "is_filled may be only 0 or 1"});
                for_table.push_back({c_t.dst_type[1] * (is_filled[1] - 1), "if cp_type is not zero then is_filled must be 1"});
                for_table.push_back({cp_type_inv[1] * (is_filled[1] - 1), "if cp_type_inv is not zero then is_filled must be 1"});

                std::vector<TYPE> tmp{
                    is_keccak[1] * real_id[1]
                };
                for( std::size_t i = 0; i < 16; i++) tmp.push_back(is_keccak[1] * c_t.dst_id[1][i] + (1 - is_keccak[1]) * zerohash[i]);
                for( std::size_t i = 0; i < tmp.size(); i++) tmp[i] = context_object.relativize(tmp[i], -1);
                context_object.relative_lookup(tmp, "keccak_table",  0, max_copy_events - 1);

                for( std::size_t i = 0; i < for_table.size(); i++ ){
                    context_object.relative_constrain(context_object.relativize(for_table[i].first, -1), 0, max_copy_events- 1, for_table[i].second);
                }
            }

            std::vector<std::size_t> rlc_copy_table_columns;
            rlc_copy_table_columns.push_back(copy_lookup_area[CopyTable::src_type_index]);
            rlc_copy_table_columns.push_back(copy_lookup_area[CopyTable::src_id_index]);
            rlc_copy_table_columns.push_back(copy_lookup_area[CopyTable::src_counter_1_index]);
            rlc_copy_table_columns.push_back(copy_lookup_area[CopyTable::src_counter_2_index]);
            rlc_copy_table_columns.push_back(copy_lookup_area[CopyTable::dst_type_index]);
            rlc_copy_table_columns.push_back(real_id_index);
            rlc_copy_table_columns.push_back(copy_lookup_area[CopyTable::dst_counter_1_index]);
            rlc_copy_table_columns.push_back(copy_lookup_area[CopyTable::dst_counter_2_index]);
            rlc_copy_table_columns.push_back(copy_lookup_area[CopyTable::length_index]);
            lookup_table("zkevm_rlc_copy",rlc_copy_table_columns,0,max_copy_events);

            // Allocate circuit instances
            current_column = BytecodeTable::get_witness_amount()
                + KeccakTable::get_witness_amount()
                + RWTable::get_witness_amount(instances_rw_8)
                + CopyTable::get_witness_amount()
                + copy_table_advice_amount
                + 1; // RLC challenge column
            std::vector<std::vector<std::size_t>> instances_copy_area;
            for( std::size_t i = 0; i < instances_copy; i++){
                std::vector<std::size_t> instance_copy_area;
                for( std::size_t j = 0; j < InstanceType::get_witness_amount(); j++){
                    instance_copy_area.push_back(current_column++);
                }
                instances_copy_area.push_back(instance_copy_area);
                context_type instance_copy_ct = context_object.subcontext(instances_copy_area[i], 0, max_copy_rows);
                typename InstanceType::input_type instance_input = {
                    input.rlc_challenge,
                    input.copy_events
                };
                instances.emplace_back(
                    instance_copy_ct,
                    instance_input,
                    rlc_challenge,
                    c_t.src_id,
                    real_id,
                    i == 0 ? TYPE(0) : instances[i-1].current_rlc,
                    max_copy_rows,
                    i == 0 ? 0: instances[i-1].get_last_assigned_event(),
                    i == 0 ? 0: instances[i-1].get_last_assigned_byte_index()
                );
            }

            std::vector<std::vector<std::size_t>> large_copy_table_columns(instances_copy);
            for( std::size_t i = 0; i < instances_copy; i++ ){
                auto cols = instances[i].get_large_copy_table_columns();
                BOOST_LOG_TRIVIAL(trace) << "zkevm_large_copy instance " << i << ": ";
                for( std::size_t j = 0; j < cols.size(); j++){
                    large_copy_table_columns[i].push_back(instances_copy_area[i][cols[j]]);
                    BOOST_LOG_TRIVIAL(trace) << "\t" << large_copy_table_columns[i].back();
                }
            }
            multi_lookup_table("zkevm_large_copy", large_copy_table_columns, 0, max_copy_rows);

            if constexpr (stage == GenerationStage::CONSTRAINTS ){
                std::vector<TYPE> tmp = {
                    is_filled[1],
                    TYPE(0),
                    c_t.src_type[1],
                    c_t.src_id[1],
                    c_t.src_counter_1[1],
                    c_t.src_counter_2[1],
                    c_t.length[1]
                };
                for( std::size_t i = 0; i < tmp.size(); i++) tmp[i] = context_object.relativize(tmp[i], -1);
                context_object.relative_lookup(tmp, "zkevm_large_copy", 0, max_copy_events - 1);
                tmp = {
                    is_filled[1],
                    TYPE(1),
                    c_t.dst_type[1],
                    real_id[1],
                    c_t.dst_counter_1[1],
                    c_t.dst_counter_2[1],
                    c_t.length[1]
                };
                for( std::size_t i = 0; i < tmp.size(); i++) tmp[i] = context_object.relativize(tmp[i], -1);
                context_object.relative_lookup(tmp, "zkevm_large_copy", 0, max_copy_events - 1);
            }


            for( std::size_t i = 1; i < instances_copy; i++ ){
                constrain(instances[i].rlc[0] - instances[i-1].rlc[max_copy_rows-2],
                    "Staring RLC of next instance must be equal to final RLC of previous instance even row", true
                );
                constrain(instances[i].cp_type[0] - instances[i-1].cp_type[max_copy_rows-2],
                    "Staring cp_type of next instance must be equal to final cp_type of previous instance even row", true
                );
                constrain(instances[i].id[0] - instances[i-1].id[max_copy_rows-2],
                    "Staring id of next instance must be equal to final id of previous instance even row", true
                );
                constrain(instances[i].value[0] - instances[i-1].value[max_copy_rows-2],
                    "Staring value of next instance must be equal to final value of previous instance even row", true
                );
                constrain(instances[i].counter_1[0] - instances[i-1].counter_1[max_copy_rows-2],
                    "Staring counter_1 of next instance must be equal to final counter_1 of previous instance even row", true
                );
                constrain(instances[i].counter_2[0] - instances[i-1].counter_2[max_copy_rows-2],
                    "Staring counter_2 of next instance must be equal to final counter_2 of previous instance even row", true
                );

                constrain(instances[i].rlc[1] - instances[i-1].rlc[max_copy_rows-1],
                    "Staring RLC of next instance must be equal to final RLC of previous instance odd row", true
                );
                constrain(instances[i].cp_type[1] - instances[i-1].cp_type[max_copy_rows-1],
                    "Staring cp_type of next instance must be equal to final cp_type of previous instance even row", true
                );
                constrain(instances[i].id[1] - instances[i-1].id[max_copy_rows-1],
                    "Staring id of next instance must be equal to final id of previous instance odd row", true
                );
                constrain(instances[i].value[1] - instances[i-1].value[max_copy_rows-1],
                    "Staring value of next instance must be equal to final value of previous instance odd row", true
                );
                constrain(instances[i].counter_1[1] - instances[i-1].counter_1[max_copy_rows-1],
                    "Staring counter_1 of next instance must be equal to final counter_1 of previous instance odd row", true
                );
                constrain(instances[i].counter_2[1] - instances[i-1].counter_2[max_copy_rows-1],
                    "Staring counter_2 of next instance must be equal to final counter_2 of previous instance odd row", true
                );
            }
        }
    };
}
