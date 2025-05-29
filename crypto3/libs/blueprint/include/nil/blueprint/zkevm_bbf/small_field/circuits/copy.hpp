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
    class copy : public generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

    public:
        using BytecodeTable = bytecode_table<FieldType, stage>;
        using RWTable = rw_8_table<FieldType, stage>;
        using KeccakTable = keccak_table<FieldType, stage>;
        using CopyTable = copy_table<FieldType, stage>;

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
            std::size_t max_copy,
            std::size_t max_rw,
            std::size_t max_keccak_blocks,
            std::size_t max_bytecode
        ) {
            return {
                .witnesses = copy_advice_amount + copy_table_advice_amount
                        + BytecodeTable::get_witness_amount()
                        + RWTable::get_witness_amount()
                        + KeccakTable::get_witness_amount()
                        + CopyTable::get_witness_amount(),
                .public_inputs = 1,
                .constants = 0,
                .rows =  std::max(
                    std::max(max_copy, max_rw),
                    std::max(max_keccak_blocks, max_bytecode)
                )
            };
        }

        static void allocate_public_inputs(
            context_type &context, input_type &input,
            std::size_t max_copy_events,
            std::size_t max_copy,
            std::size_t max_rw,
            std::size_t max_keccak_blocks,
            std::size_t max_bytecode
        ) {
            context.allocate(input.rlc_challenge, 0, 0, column_type::public_input);
        }

        copy(context_type &context_object,
            const input_type &input,
            std::size_t max_copy_events,
            std::size_t max_copy,
            std::size_t max_rw,
            std::size_t max_keccak_blocks,
            std::size_t max_bytecode
        ) :generic_component<FieldType,stage>(context_object) {
            auto zerohash = w_to_16(zkevm_keccak_hash({}));
            // BOOST_LOG_TRIVIAL(trace) << "Copy assignment and circuit construction" << std::endl;

            // Allocate places for dynamic lookups
            std::size_t current_column = 0;
            std::vector<std::size_t> copy_lookup_area;
            for( std::size_t i = 0; i < CopyTable::get_witness_amount(); i++){
                copy_lookup_area.push_back(current_column++);
            }
            context_type copy_ct = context_object.subcontext( copy_lookup_area, 0, max_copy_events * 2);
            CopyTable c_t = CopyTable(copy_ct, {input.copy_events, input.bytecodes}, max_copy_events);

            std::vector<std::size_t> bytecode_lookup_area;
            for( std::size_t i = 0; i < BytecodeTable::get_witness_amount(); i++){
                bytecode_lookup_area.push_back(current_column++);
            }
            context_type bytecode_ct = context_object.subcontext(bytecode_lookup_area,0,max_bytecode);
            BytecodeTable bc_t = BytecodeTable(bytecode_ct, input.bytecodes, max_bytecode);

            std::vector<std::size_t> rw_lookup_area;
            for( std::size_t i = 0; i < RWTable::get_witness_amount(); i++){
                rw_lookup_area.push_back(current_column++);
            }
            context_type rw_ct = context_object.subcontext(rw_lookup_area,0,max_rw);
            RWTable rw_t = RWTable(rw_ct, input.rw_operations, max_rw);

            std::vector<std::size_t> keccak_lookup_area;
            for( std::size_t i = 0; i < KeccakTable::get_witness_amount(); i++){
                keccak_lookup_area.push_back(current_column++);
            }
            context_type keccak_ct = context_object.subcontext( keccak_lookup_area, 0, max_copy_events * 2);
            KeccakTable k_t = KeccakTable(keccak_ct, {input.rlc_challenge, input.keccak_buffers}, max_keccak_blocks);

            std::vector<TYPE> real_id(max_copy_events * 2); // Id for bytecode, memory, calldata, returndata, RLC for keccak
            std::vector<TYPE> cp_type_keccak_inv(max_copy_events * 2); // Inverse of copy operand type
            std::vector<TYPE> cp_type_inv(max_copy_events*2);
            std::vector<TYPE> is_keccak(max_copy_events * 2); // Dynamic selector for lookup to keccak_table
            std::vector<TYPE> is_filled(max_copy_events * 2);

            std::vector<TYPE> is_first(max_copy);
            std::vector<TYPE> is_write(max_copy);
            std::vector<TYPE> cp_type(max_copy);
            std::vector<TYPE> id(max_copy);
            std::vector<TYPE> counter_1(max_copy);
            std::vector<TYPE> counter_2(max_copy);
            std::vector<TYPE> length(max_copy);
            std::vector<TYPE> value(max_copy);
            std::vector<TYPE> rlc(max_copy);
            std::vector<TYPE> rlc_challenge(max_copy);
            std::vector<TYPE> is_last(max_copy);
            std::vector<std::array<TYPE, copy_operand_types_amount>>    type_selector(max_copy);

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                std::size_t current_row = 0;
                for( auto &cp: input.copy_events ){
                    is_filled[current_row] = 1;
                    is_filled[current_row + 1] = 1;
                    if( cp.source_type == copy_operand_type::keccak ){
                        real_id[current_row] = calculateRLC<FieldType>(cp.get_bytes(), input.rlc_challenge);
                        is_keccak[current_row] = 1; // It would never happen.
                    } else {
                        real_id[current_row] = c_t.id[current_row][15];
                    }

                    if( cp.destination_type == copy_operand_type::keccak ){
                        real_id[current_row + 1] = calculateRLC<FieldType>(cp.get_bytes(), input.rlc_challenge);
                        is_keccak[current_row + 1] = 1;
                    } else {
                        real_id[current_row + 1] = c_t.id[current_row + 1][15];
                    }

                    current_row += 2;
                }
                std::size_t copy_event_index = 0;
                current_row = 0;
                for( auto &cp: input.copy_events ){
                    BOOST_LOG_TRIVIAL(debug)
                        << "\tCopy event " << copy_op_to_num(cp.source_type)
                        << " => " << copy_op_to_num(cp.destination_type)
                        << " data size " << cp.size()
                        << std::endl;

                    std::size_t src_counter_1;
                    std::size_t src_counter_2;
                    std::size_t dst_counter_1;
                    std::size_t dst_counter_2;
                    for( std::size_t i = 0; i < cp.size(); i++ ){
                        if( i == 0 ) {
                            is_first[current_row] = 1;
                            is_first[current_row+1] = 1;
                            src_counter_1 = cp.src_counter_1;
                            src_counter_2 = cp.src_counter_2;
                            dst_counter_1 = cp.dst_counter_1;
                            dst_counter_2 = cp.dst_counter_2;
                        }

                        cp_type[current_row] = copy_op_to_num(cp.source_type);
                        cp_type[current_row + 1] = copy_op_to_num(cp.destination_type);

                        id[current_row] = real_id[copy_event_index];
                        id[current_row+1] = real_id[copy_event_index+1];

                        counter_1[current_row] = src_counter_1;
                        counter_2[current_row] = src_counter_2;
                        counter_1[current_row + 1] = dst_counter_1;
                        counter_2[current_row + 1] = dst_counter_2;
                        length[current_row] = cp.length - i;
                        length[current_row + 1] = cp.length - i;
                        value[current_row] = cp.get_value(i);
                        value[current_row + 1] = cp.get_value(i);

                        rlc_challenge[current_row] = input.rlc_challenge;
                        rlc_challenge[current_row  + 1] = input.rlc_challenge;
                        rlc[current_row] = i == 0? length[current_row] * rlc_challenge[current_row]: rlc[current_row - 1] * rlc_challenge[current_row];
                        rlc[current_row + 1] = rlc[current_row] + value[current_row];
                        type_selector[current_row][copy_op_to_num(cp.source_type) - 1] = 1;
                        type_selector[current_row + 1][copy_op_to_num(cp.destination_type) - 1] = 1;

                        BOOST_LOG_TRIVIAL(trace) << "\t\t" << current_row << ". "
                            << std::hex
                            << cp.source_id << " " << counter_1[current_row] << " " << counter_2[current_row] << "    "
                            << cp.destination_id << " " << counter_1[current_row+1] << " " << counter_2[current_row+1] << "    "
                            << cp.get_key(i) <<  " => "
                            << cp.get_value(i) << std::dec
                            << " length " << length[current_row] << " " << length[current_row + 1]
                            << " rlc_challenge " << rlc_challenge[current_row] << " " << rlc_challenge[current_row + 1] << std::endl;
                        src_counter_1++;
                        src_counter_2++;
                        dst_counter_1++;
                        dst_counter_2++;
                        current_row += 2;
                    }
                    is_last[current_row - 1] = 1;
                    copy_event_index+=2;
                    BOOST_LOG_TRIVIAL(trace) << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "\tFor bytes size = " << cp.size() << " last row is " << current_row - 1 << std::endl;
                }
            }
            for( std::size_t i = 0; i < max_copy_events * 2; i++){
                if constexpr ( stage == GenerationStage::ASSIGNMENT) {
                    cp_type_keccak_inv[i] = c_t.cp_type[i] - copy_op_to_num(copy_operand_type::keccak) == 0 ? 0 : (c_t.cp_type[i] - copy_op_to_num(copy_operand_type::keccak)).inversed();
                    cp_type_inv[i] = c_t.cp_type[i] == 0? 0: c_t.cp_type[i].inversed();
                }

                std::size_t current_column =
                    BytecodeTable::get_witness_amount() + KeccakTable::get_witness_amount()
                        + RWTable::get_witness_amount() + CopyTable::get_witness_amount();
                allocate(real_id[i], current_column++, i);
                allocate(is_keccak[i], current_column++, i);
                allocate(cp_type_keccak_inv[i], current_column++, i);
                allocate(is_filled[i], current_column++, i);
                allocate(cp_type_inv[i], current_column++, i);
            }
            std::size_t is_first_index = 0;
            std::size_t is_write_index = 0;
            std::size_t cp_type_index = 0;
            std::size_t id_index = 0;
            std::size_t counter_1_index = 0;
            std::size_t counter_2_index = 0;
            std::size_t length_index = 0;

            for( std::size_t i = 0; i < max_copy; i++){
                if constexpr ( stage == GenerationStage::ASSIGNMENT) {
                    is_write[i] = i%2;
                }
                std::size_t current_column = copy_table_advice_amount
                    + BytecodeTable::get_witness_amount() + KeccakTable::get_witness_amount()
                    + RWTable::get_witness_amount() + CopyTable::get_witness_amount();

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
                allocate(rlc_challenge[i],current_column++, i);
                allocate(is_last[i], current_column++, i);
            }
            if constexpr( stage == GenerationStage::CONSTRAINTS ){
                std::vector<TYPE> even;
                std::vector<TYPE> odd;
                std::vector<TYPE> every;
                std::vector<TYPE> non_first;
                std::vector<TYPE> for_table;

                for_table.push_back((1 - is_keccak[1]) - (c_t.cp_type[1] - copy_op_to_num(copy_operand_type::keccak)) * cp_type_keccak_inv[1]);
                for_table.push_back(is_keccak[1] * (is_keccak[1] - 1));
                for_table.push_back(is_keccak[1] * cp_type_keccak_inv[1]);
                for_table.push_back(is_keccak[1] * (c_t.cp_type[1] - copy_op_to_num(copy_operand_type::keccak)));
                for( std::size_t i = 0; i < 15; i++){
                    for_table.push_back((1 - is_keccak[1]) * c_t.id[1][i]);
                }
                for_table.push_back((1 - is_keccak[1]) * (c_t.id[1][15] - real_id[1]));

                for_table.push_back(is_filled[1] - c_t.cp_type[1] * cp_type_inv[1]);
                for_table.push_back(is_filled[1] * (is_filled[1] - 1));
                for_table.push_back( c_t.cp_type[1] * (is_filled[1] - 1));
                for_table.push_back( cp_type_inv[1] * (is_filled[1] - 1));

                std::vector<TYPE> tmp{
                    is_keccak[1] * real_id[1],
                };
                for( std::size_t i = 0; i < 16; i++) tmp.push_back(is_keccak[1] * c_t.id[1][i] + (1 - is_keccak[1]) * zerohash[i]);
                for( std::size_t i = 0; i < tmp.size(); i++) tmp[i] = context_object.relativize(tmp[i], -1);
                context_object.relative_lookup(tmp, "keccak_table",  0, max_copy_events * 2 - 1);

                every.push_back(is_write[1]  * (is_write[1] - 1));
                every.push_back(is_first[1]  * (is_first[1] - 1));
                every.push_back(is_last[1]  * (is_last[1] - 1));

                TYPE type_selector_sum;
                TYPE cp_type_constraint;
                for(std::size_t j = 0; j < copy_operand_types_amount; j++){
                    type_selector_sum += type_selector[1][j];
                    cp_type_constraint += (j+1) * type_selector[1][j];
                    every.push_back(type_selector[1][j]  * (type_selector[1][j] - 1));
                }
                every.push_back(type_selector_sum  * (type_selector_sum - 1));
                every.push_back(cp_type_constraint - cp_type[1]);
                every.push_back((type_selector_sum - 1)* is_last[1]);
                every.push_back((type_selector_sum - 1)* is_first[1]);

                non_first.push_back(type_selector_sum * (rlc_challenge[1] - rlc_challenge[0]));

                even.push_back(is_write[1]);
                even.push_back(is_last[1]);
                even.push_back(type_selector_sum * (1 - is_first[1]) * (id[0] - id[2]));
                even.push_back(type_selector_sum * (1 - is_first[1]) * (cp_type[0] - cp_type[2]));

                even.push_back(type_selector_sum * (1 - is_first[1]) * (counter_1[0] - counter_1[2] + 1));
                even.push_back(type_selector_sum * (1 - is_first[1]) * (counter_2[0] - counter_2[2] + 1));

                even.push_back((1 - is_first[1]) * type_selector_sum * (length[0] - length[2] - 1));
                even.push_back(is_first[1] *(rlc[1] - length[1] * rlc_challenge[1]));
                even.push_back((1 - is_first[1]) * type_selector_sum * (rlc[1] - rlc[0] * rlc_challenge[1]));

                odd.push_back(1 - is_write[1]);
                odd.push_back(value[1] - value[0]);
                odd.push_back(is_first[1] - is_first[0]);
                odd.push_back(length[1] - length[0]);

                odd.push_back(type_selector_sum * (1 - is_last[1]) * (id[0] - id[2]));
                odd.push_back(type_selector_sum * (1 - is_last[1]) * (cp_type[0] - cp_type[2]));
                odd.push_back(type_selector_sum * (1 - is_last[1]) * (counter_1[0] - counter_1[2] + 1));
                odd.push_back(type_selector_sum * (1 - is_last[1]) * (counter_2[0] - counter_2[2] + 1));
                odd.push_back(type_selector_sum * (rlc[1] - rlc[0] - value[1]));
                odd.push_back((1 - is_last[1]) * type_selector_sum * (length[0] - length[2] - 1));
                odd.push_back((1 - is_last[1]) * type_selector_sum * (counter_1[0] - counter_1[2] + 1));
                odd.push_back((1 - is_last[1]) * type_selector_sum * (counter_2[0] - counter_2[2] + 1));
                odd.push_back(is_last[1] * (length[1] - 1));

                TYPE memory_selector = type_selector[1][copy_op_to_num(copy_operand_type::memory) - 1];
                TYPE keccak_selector = type_selector[1][copy_op_to_num(copy_operand_type::keccak) - 1];
                TYPE bytecode_selector = type_selector[1][copy_op_to_num(copy_operand_type::bytecode) - 1];
                TYPE calldata_selector = type_selector[1][copy_op_to_num(copy_operand_type::calldata) - 1];
                TYPE returndata_selector = type_selector[1][copy_op_to_num(copy_operand_type::returndata) - 1];

                tmp = rw_8_table<FieldType, stage>::memory_lookup(
                    id[1],     // call_id
                    counter_1[1], // address
                    counter_2[1], // rw_counter
                    is_write[1],  // is_write
                    value[1]
                );
                for( std::size_t i = 0; i < tmp.size(); i++) tmp[i] = context_object.relativize(memory_selector*tmp[i], -1);
                context_object.relative_lookup(tmp, "zkevm_rw_8", 0, max_copy - 1);

                // Used both for CALLx calldata writing and CALLDATACOPY calldata reading
                tmp = rw_8_table<FieldType, stage>::calldata_lookup(
                    id[1],
                    counter_1[1], // address
                    counter_2[1], // rw_counter
                    is_write[1],
                    value[1]
                );
                for( std::size_t i = 0; i < tmp.size(); i++) tmp[i] = context_object.relativize(calldata_selector*tmp[i], -1);
                context_object.relative_lookup(tmp, "zkevm_rw_8", 0, max_copy);

                // Used both for RETURN, REVERT returndat writing and RETURNDATACOPY returndata reading
                tmp = rw_8_table<FieldType, stage>::returndata_lookup(
                    id[1],
                    counter_1[1], // address
                    counter_2[1], // rw_counter
                    is_write[1],  // is_write
                    value[1]
                );
                for( std::size_t i = 0; i < tmp.size(); i++) tmp[i] = context_object.relativize(returndata_selector*tmp[i], -1);
                context_object.relative_lookup(tmp, "zkevm_rw_8", 0, max_copy);

                tmp = {
                    counter_1[1],   // offset
                    value[1],
                    id[1]
                };
                for( std::size_t i = 0; i < tmp.size(); i++) tmp[i] = context_object.relativize(bytecode_selector*tmp[i], -1);
                // context_object.relative_lookup(tmp, "zkevm_bytecode_copy", 0, max_copy - 1);

                std::vector<std::size_t> rlc_copy_table_columns;
                rlc_copy_table_columns.push_back(copy_lookup_area[CopyTable::is_write_index]);
                rlc_copy_table_columns.push_back(copy_lookup_area[CopyTable::cp_type_index]);
                rlc_copy_table_columns.push_back(
                    BytecodeTable::get_witness_amount() + KeccakTable::get_witness_amount() +
                    RWTable::get_witness_amount() + CopyTable::get_witness_amount()
                );
                rlc_copy_table_columns.push_back(copy_lookup_area[CopyTable::counter_1_index]);
                rlc_copy_table_columns.push_back(copy_lookup_area[CopyTable::counter_2_index]);
                rlc_copy_table_columns.push_back(copy_lookup_area[CopyTable::length_index]);
                lookup_table("zkevm_rlc_copy",rlc_copy_table_columns,0,max_copy_events * 2);

                tmp = {
                    is_first[1] * is_write[1],
                    is_first[1] * cp_type[1],
                    is_first[1] * id[1],
                    is_first[1] * counter_1[1],
                    is_first[1] * counter_2[1],
                    is_first[1] * length[1]
                };
                for( std::size_t i = 0; i < tmp.size(); i++) tmp[i] = context_object.relativize(tmp[i], -1);
                context_object.relative_lookup(tmp, "zkevm_rlc_copy", 0, max_copy - 1);

                std::vector<std::size_t> large_copy_table_columns = {
                    is_first_index,
                    is_write_index,
                    cp_type_index,
                    id_index,
                    counter_1_index,
                    counter_2_index,
                    length_index
                };
                lookup_table("zkevm_large_copy", large_copy_table_columns, 0, max_copy);
                tmp = {
                    is_filled[1],
                    c_t.is_write[1],
                    c_t.cp_type[1],
                    real_id[1],
                    c_t.counter_1[1],
                    c_t.counter_2[1],
                    c_t.length[1]
                };
                for( std::size_t i = 0; i < tmp.size(); i++) tmp[i] = context_object.relativize(tmp[i], -1);
                context_object.relative_lookup(tmp, "zkevm_large_copy", 0, max_copy_events - 1);

                for( std::size_t i = 0; i < even.size(); i++ ){
                    for( std::size_t j = 0; j < max_copy-1; j+=2 ){
                        context_object.relative_constrain(context_object.relativize(even[i], -1), j);
                    }
                }
                for( std::size_t i = 0; i < odd.size(); i++ ){
                    for( std::size_t j = 1; j <= max_copy-1; j+=2 ){
                        context_object.relative_constrain(context_object.relativize(odd[i], -1), j);
                    }
                }
                for( std::size_t i = 0; i < every.size(); i++ ){
                    context_object.relative_constrain(context_object.relativize(every[i], -1), 0, max_copy-1);
                }
                for( std::size_t i = 0; i < non_first.size(); i++ ){
                    context_object.relative_constrain(context_object.relativize(non_first[i], -1), 1, max_copy-1);
                }
                for( std::size_t i = 0; i < for_table.size(); i++ ){
                    context_object.relative_constrain(context_object.relativize(for_table[i], -1), 0, max_copy_events*2 - 1);
                }
            }
        }
    };
}
