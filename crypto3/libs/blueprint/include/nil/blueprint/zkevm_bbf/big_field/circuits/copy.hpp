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

#include <nil/blueprint/zkevm_bbf/big_field/subcomponents/keccak_table.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/subcomponents/bytecode_table.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/subcomponents/rw_table.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/subcomponents/copy_table.hpp>

namespace nil::blueprint::bbf::zkevm_big_field{
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
        using RWTable = rw_table<FieldType, stage>;
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
            CopyTable::input_type copy_events;
        };

        static constexpr std::size_t copy_advice_amount = 25;

        static table_params get_minimal_requirements(
            std::size_t max_copy,
            std::size_t max_rw,
            std::size_t max_keccak_blocks,
            std::size_t max_bytecode
        ) {
            return {
                .witnesses = copy_advice_amount
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
            std::size_t max_copy,
            std::size_t max_rw,
            std::size_t max_keccak_blocks,
            std::size_t max_bytecode
        ) {
            context.allocate(input.rlc_challenge, 0, 0, column_type::public_input);
        }

        copy(context_type &context_object,
            const input_type &input,
            std::size_t max_copy,
            std::size_t max_rw,
            std::size_t max_keccak_blocks,
            std::size_t max_bytecode
        ) :generic_component<FieldType,stage>(context_object) {
            auto zerohash = zkevm_keccak_hash({});
            BOOST_LOG_TRIVIAL(trace) << "Copy assignment and circuit construction" << std::endl;

            // Allocate places for dynamic lookups
            std::size_t current_column = 0;
            std::vector<std::size_t> copy_lookup_area;
            for( std::size_t i = 0; i < CopyTable::get_witness_amount(); i++){
                copy_lookup_area.push_back(current_column++);
            }
            std::vector<std::size_t> bytecode_lookup_area;
            for( std::size_t i = 0; i < BytecodeTable::get_witness_amount(); i++){
                bytecode_lookup_area.push_back(current_column++);
            }
            std::vector<std::size_t> keccak_lookup_area;
            for( std::size_t i = 0; i < KeccakTable::get_witness_amount(); i++){
                keccak_lookup_area.push_back(current_column++);
            }
            std::vector<std::size_t> rw_lookup_area;
            for( std::size_t i = 0; i < RWTable::get_witness_amount(); i++){
                rw_lookup_area.push_back(current_column++);
            }

            context_type bytecode_ct = context_object.subcontext(bytecode_lookup_area,0,max_bytecode);
            context_type keccak_ct = context_object.subcontext( keccak_lookup_area, 0, max_keccak_blocks);
            context_type rw_ct = context_object.subcontext(rw_lookup_area, 0, max_rw);
            context_type copy_ct = context_object.subcontext( copy_lookup_area, 0, max_copy);

            BytecodeTable bc_t = BytecodeTable(bytecode_ct, input.bytecodes, max_bytecode);
            KeccakTable k_t = KeccakTable(keccak_ct, {input.rlc_challenge, input.keccak_buffers}, max_keccak_blocks);
            RWTable rw_t = RWTable(rw_ct, input.rw_operations, max_rw, true);
            CopyTable c_t = CopyTable(copy_ct, input.copy_events, max_copy, false);

            const std::vector<TYPE> is_first = c_t.is_first;
            const std::vector<TYPE> is_write = c_t.is_write;
            const std::vector<TYPE> cp_type = c_t.cp_type;
            const std::vector<TYPE> id_hi = c_t.id_hi;
            const std::vector<TYPE> id_lo = c_t.id_lo;
            const std::vector<TYPE> counter_1 = c_t.counter_1;
            const std::vector<TYPE> counter_2 = c_t.counter_2;
            const std::vector<TYPE> length = c_t.length;

            std::vector<TYPE>                   op(max_copy);
            std::vector<TYPE>                   context_id(max_copy);
            std::vector<TYPE>                   addr(max_copy);
            std::vector<TYPE>                   field_type(max_copy);
            std::vector<TYPE>                   storage_key_hi(max_copy);
            std::vector<TYPE>                   storage_key_lo(max_copy);
            std::vector<TYPE>                   value_hi(max_copy);
            std::vector<TYPE>                   value_lo(max_copy);
            std::vector<std::array<TYPE, copy_operand_types_amount>>    type_selector(max_copy);
            std::vector<TYPE>                   rlc(max_copy);
            std::vector<TYPE>                   rlc_challenge(max_copy);
            std::vector<TYPE>                   is_last(max_copy);

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                std::size_t current_row = 0;
                for( auto &cp: input.copy_events ){
                    std::cout
                        << "\tCopy event " << copy_op_to_num(cp.source_type)
                        << " => " << copy_op_to_num(cp.destination_type)
                        << " data size " << cp.size()
                        << std::endl;
                    for( std::size_t i = 0; i < cp.size(); i++ ){
                        op[current_row] = cp.get_op(i);
                        op[current_row + 1] = cp.get_op(i);
                        context_id[current_row] = cp.get_context_id(i);
                        context_id[current_row + 1] = cp.get_context_id(i);
                        addr[current_row] = cp.get_address(i);
                        addr[current_row + 1] = cp.get_address(i);
                        field_type[current_row] = cp.get_field_type(i);
                        field_type[current_row + 1] = cp.get_field_type(i);
                        storage_key_hi[current_row] = w_hi<FieldType>(cp.get_key(i));
                        storage_key_hi[current_row + 1] = w_hi<FieldType>(cp.get_key(i));
                        storage_key_lo[current_row] = w_lo<FieldType>(cp.get_key(i));
                        storage_key_lo[current_row + 1] = w_lo<FieldType>(cp.get_key(i));
                        value_hi[current_row] = w_hi<FieldType>(cp.get_value(i));
                        value_hi[current_row + 1] = w_hi<FieldType>(cp.get_value(i));
                        value_lo[current_row] = w_lo<FieldType>(cp.get_value(i));
                        value_lo[current_row + 1] = w_lo<FieldType>(cp.get_value(i));

                        rlc_challenge[current_row] = input.rlc_challenge;
                        rlc_challenge[current_row  + 1] = input.rlc_challenge;
                        rlc[current_row] = i == 0? length[current_row] * rlc_challenge[current_row]: rlc[current_row - 1] * rlc_challenge[current_row];
                        rlc[current_row + 1] = rlc[current_row] + value_lo[current_row];
                        type_selector[current_row][copy_op_to_num(cp.source_type) - 1] = 1;
                        type_selector[current_row + 1][copy_op_to_num(cp.destination_type) - 1] = 1;

                        BOOST_LOG_TRIVIAL(trace) << "\t\t" << current_row << ". "
                            << std::hex
                            << cp.source_id << " " << counter_1[current_row] << " " << counter_2[current_row] << "    "
                            << cp.destination_id << " " << counter_1[current_row+1] << " " << counter_2[current_row+1] << "    "
                            << cp.get_op(i) << " "
                            << cp.get_address(i) << " "
                            << cp.get_field_type(i) << " "
                            << cp.get_key(i) <<  " => "
                            << cp.get_value(i) << std::dec
                            << " length " << length[current_row] << " " << length[current_row + 1] << std::endl;
                        current_row += 2;
                    }
                    is_last[current_row - 1] = 1;
                    BOOST_LOG_TRIVIAL(trace) << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "\tFor bytes size = " << cp.size() << " last row is " << current_row - 1 << std::endl;
                }
            }
            for( std::size_t i = 0; i < max_copy; i++){
                std::size_t current_column =
                    BytecodeTable::get_witness_amount() + KeccakTable::get_witness_amount()
                        + RWTable::get_witness_amount() + CopyTable::get_witness_amount();

                for(std::size_t j = 0; j < copy_operand_types_amount - 1; j++){ // Without padding
                    allocate(type_selector[i][j], current_column++, i);
                }
                allocate(op[i], current_column++, i);
                allocate(context_id[i], current_column++, i);
                allocate(addr[i], current_column++, i);
                allocate(field_type[i], current_column++, i);
                allocate(storage_key_hi[i], current_column++, i);
                allocate(storage_key_lo[i], current_column++, i);
                allocate(value_hi[i], current_column++, i);
                allocate(value_lo[i], current_column++, i);

                allocate(rlc[i],current_column++, i);
                allocate(rlc_challenge[i],current_column++, i);
                allocate(is_last[i], current_column++, i);

            }
            if constexpr( stage == GenerationStage::CONSTRAINTS ){
                std::vector<TYPE> even;
                std::vector<TYPE> odd;
                std::vector<TYPE> every;
                std::vector<TYPE> non_first;

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
                even.push_back(type_selector_sum * (1 - is_first[1]) * (id_hi[0] - id_hi[2]));
                even.push_back(type_selector_sum * (1 - is_first[1]) * (id_lo[0] - id_lo[2]));
                even.push_back(type_selector_sum * (1 - is_first[1]) * (cp_type[0] - cp_type[2]));

                even.push_back(type_selector_sum * (1 - is_first[1]) * (counter_1[0] - counter_1[2] + 1));
                even.push_back(type_selector_sum * (1 - is_first[1]) * (counter_2[0] - counter_2[2] + 1));

                even.push_back((1 - is_first[1]) * type_selector_sum * (length[0] - length[2] - 1));
                even.push_back(is_first[1] *(rlc[1] - length[1] * rlc_challenge[1]));
                even.push_back((1 - is_first[1]) * type_selector_sum * (rlc[1] - rlc[0] * rlc_challenge[1]));

                odd.push_back(1 - is_write[1]);
                odd.push_back(addr[1] - addr[0]);
                odd.push_back(field_type[1] - field_type[0]);
                odd.push_back(storage_key_hi[1] - storage_key_hi[0]);
                odd.push_back(storage_key_lo[1] - storage_key_lo[0]);
                odd.push_back(value_hi[1] - value_hi[0]);
                odd.push_back(value_lo[1] - value_lo[0]);
                odd.push_back(is_first[1] - is_first[0]);
                odd.push_back(length[1] - length[0]);

                odd.push_back(type_selector_sum * (1 - is_last[1]) * (id_hi[0] - id_hi[2]));
                odd.push_back(type_selector_sum * (1 - is_last[1]) * (id_lo[0] - id_lo[2]));
                odd.push_back(type_selector_sum * (1 - is_last[1]) * (cp_type[0] - cp_type[2]));
                odd.push_back(type_selector_sum * (1 - is_last[1]) * (counter_1[0] - counter_1[2] + 1));
                odd.push_back(type_selector_sum * (1 - is_last[1]) * (counter_2[0] - counter_2[2] + 1));
                odd.push_back(type_selector_sum * (rlc[1] - rlc[0] - value_lo[1]));
                odd.push_back((1 - is_last[1]) * type_selector_sum * (length[0] - length[2] - 1));
                odd.push_back((1 - is_last[1]) * type_selector_sum * (counter_1[0] - counter_1[2] + 1));
                odd.push_back((1 - is_last[1]) * type_selector_sum * (counter_2[0] - counter_2[2] + 1));
                odd.push_back(is_last[1] * (length[1] - 1));

                TYPE memory_selector = type_selector[1][copy_op_to_num(copy_operand_type::memory) - 1];
                TYPE keccak_selector = type_selector[1][copy_op_to_num(copy_operand_type::keccak) - 1];
                TYPE calldata_selector = type_selector[1][copy_op_to_num(copy_operand_type::calldata) - 1];
                TYPE returndata_selector = type_selector[1][copy_op_to_num(copy_operand_type::returndata) - 1];

                std::vector<TYPE> tmp = rw_table<FieldType, stage>::memory_lookup(
                    id_lo[1],
                    counter_1[1], // address
                    counter_2[1], // rw_counter
                    is_write[1],  // is_write
                    value_lo[1]
                );
                BOOST_LOG_TRIVIAL(trace) << "Memory_lookup size " << tmp.size() << std::endl;
                for( std::size_t i = 0; i < tmp.size(); i++) tmp[i] = context_object.relativize(memory_selector*tmp[i], -1);
                context_object.relative_lookup(tmp, "zkevm_rw", 0, max_copy - 1);

                tmp = {
                    TYPE(1),
                    keccak_selector*is_last[1] * rlc[1],
                    keccak_selector*is_last[1] * id_hi[1] + (1 - keccak_selector * is_last[1]) * w_hi<FieldType>(zerohash),
                    keccak_selector*is_last[1] * id_lo[1] + (1 - keccak_selector * is_last[1]) * w_lo<FieldType>(zerohash)
                };
                for( std::size_t i = 1; i < tmp.size(); i++) tmp[i] = context_object.relativize(tmp[i], -1);
                context_object.relative_lookup(tmp, "keccak_table",  1, max_copy - 2);

                // tmp = {
                //     id_lo[1],
                //     op[1],
                //     context_id[1],
                //     addr[1],
                //     field_type[1],
                //     storage_key_hi[1],
                //     storage_key_lo[1],
                //     counter_2[1] + 1,
                //     value_hi[1],
                //     value_lo[1]
                // };
                // for( std::size_t i = 0; i < tmp.size(); i++)
                //     tmp[i] = context_object.relativize(reverted_selector*(1 - is_write[1])*tmp[i], -1);
                // context_object.relative_lookup(tmp, "zkevm_call_commit_table",  0, max_copy - 1);

                // tmp = {
                //     op[1],
                //     context_id[1],
                //     addr[1],
                //     field_type[1],
                //     storage_key_hi[1],
                //     storage_key_lo[1],
                //     counter_1[1],
                //     TYPE(1),
                //     value_hi[1],
                //     value_lo[1]
                // };
                // for( std::size_t i = 0; i < tmp.size(); i++)
                //     tmp[i] = context_object.relativize(reverted_selector*is_write[1]*tmp[i], -1);
                // context_object.relative_lookup(tmp, "zkevm_rw", 0, max_copy - 1);

                // Used both for CALLx calldata writing and CALLDATACOPY calldata reading
                tmp = rw_table<FieldType, stage>::calldata_lookup(
                    id_lo[1],
                    counter_1[1], // address
                    counter_2[1], // rw_counter
                    is_write[1],
                    value_lo[1]
                );
                BOOST_LOG_TRIVIAL(trace) << "Calldata_lookup size " << tmp.size() << std::endl;
                for( std::size_t i = 0; i < tmp.size(); i++) tmp[i] = context_object.relativize(calldata_selector*tmp[i], -1);
                context_object.relative_lookup(tmp, "zkevm_rw", 0, max_copy - 1);

                // Used both for RETURN, REVERT calldata writing and CALLDATACOPY calldata reading
                tmp = rw_table<FieldType, stage>::returndata_lookup(
                    id_lo[1],
                    counter_1[1], // address
                    counter_2[1], // rw_counter
                    is_write[1],  // is_write
                    value_lo[1]
                );
                BOOST_LOG_TRIVIAL(trace) << "Returndata_lookup size " << tmp.size() << std::endl;
                for( std::size_t i = 0; i < tmp.size(); i++) tmp[i] = context_object.relativize(returndata_selector*tmp[i], -1);
                context_object.relative_lookup(tmp, "zkevm_rw", 0, max_copy - 1);

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
            }
        }
    };
}
