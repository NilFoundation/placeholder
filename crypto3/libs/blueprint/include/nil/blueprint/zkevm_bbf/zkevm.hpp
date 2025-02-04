//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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

#include <functional>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/keccak_table.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/bytecode_table.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/rw_table.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/copy_table.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/exp_table.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_state.hpp>
#include <nil/blueprint/zkevm_bbf/opcodes/zkevm_opcodes.hpp>
#include <nil/blueprint/zkevm/zkevm_word.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf{
            template<typename FieldType, GenerationStage stage>
            class zkevm : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;
            public:
                using state = state_vars<FieldType, stage>;
                using typename generic_component<FieldType,stage>::TYPE;
                struct input_type{
                    TYPE rlc_challenge;
                    typename std::conditional<stage == GenerationStage::ASSIGNMENT, zkevm_keccak_buffers, std::nullptr_t>::type bytecodes;
                    typename std::conditional<stage == GenerationStage::ASSIGNMENT, zkevm_keccak_buffers, std::nullptr_t>::type keccak_buffers;
                    typename std::conditional<stage == GenerationStage::ASSIGNMENT, rw_operations_vector, std::nullptr_t>::type rw_operations;
                    typename std::conditional<stage == GenerationStage::ASSIGNMENT, std::vector<copy_event>, std::nullptr_t>::type copy_events;
                    typename std::conditional<stage == GenerationStage::ASSIGNMENT, std::vector<zkevm_state>, std::nullptr_t>::type zkevm_states;
                    typename std::conditional<stage == GenerationStage::ASSIGNMENT, std::vector<std::pair<zkevm_word_type,zkevm_word_type>>, std::nullptr_t>::type exponentiations;
                };
            public:
                using val = typename FieldType::value_type;
                using BytecodeTable = bytecode_table<FieldType, stage>;
                using RWTable = rw_table<FieldType, stage>;
                using ExpTable = exp_table<FieldType, stage>;
                using CopyTable = copy_table<FieldType, stage>;

                static nil::crypto3::zk::snark::plonk_table_description<FieldType> get_table_description(
                    std::size_t max_zkevm_rows,
                    std::size_t max_copy,
                    std::size_t max_rw,
                    std::size_t max_exponentations,
                    std::size_t max_bytecode
                ){
                    std::size_t implemented_opcodes_amount = get_implemented_opcodes_list().size();

                    std::size_t witness_amount = state::get_items_amout() + std::ceil(float(implemented_opcodes_amount)/4) + max_opcode_height/2 + opcode_columns_amount;
                    witness_amount += BytecodeTable::get_witness_amount();
                    witness_amount += RWTable::get_witness_amount();
                    witness_amount += ExpTable::get_witness_amount();
                    witness_amount += CopyTable::get_witness_amount();
                    witness_amount += 10;
                    nil::crypto3::zk::snark::plonk_table_description<FieldType> desc(witness_amount, 1, 5, 20);
                    desc.usable_rows_amount = std::max(max_zkevm_rows, std::max(std::max(max_copy, max_rw), std::max(max_exponentations, max_bytecode)) + 1);
                    return desc;
                }

                zkevm(
                    context_type &context_object,
                    const input_type &input,
                    std::size_t max_zkevm_rows,
                    std::size_t max_copy,
                    std::size_t max_rw,
                    std::size_t max_exponentations,
                    std::size_t max_bytecode,
                    std::size_t max_exponentiations = 50 // TODO:remove it later
                ) :generic_component<FieldType,stage>(context_object), implemented_opcodes(get_implemented_opcodes_list()) {
                    std::size_t implemented_opcodes_amount = implemented_opcodes.size();
                    std::size_t opcode_selectors_amount = std::ceil(float(implemented_opcodes_amount)/4);
                    std::size_t opcode_row_selectors_amount = max_opcode_height/2;
                    std::size_t current_column = state::get_items_amout() + opcode_selectors_amount + opcode_row_selectors_amount;
                    std::vector<zkevm_opcode> opcode_list;
                    std::vector<state> all_states(max_zkevm_rows);
                    std::vector<std::vector<TYPE>> opcode_selectors(max_zkevm_rows, std::vector<TYPE>(opcode_selectors_amount));
                    std::vector<std::vector<TYPE>> opcode_row_selectors(max_zkevm_rows, std::vector<TYPE>(opcode_row_selectors_amount));

                    std::vector<std::size_t> opcode_area;
                    std::cout << "Opcode_area: ";
                    for( std::size_t i = 0; i < opcode_columns_amount; i++){
                        std::cout << current_column << " ";
                        opcode_area.push_back(current_column++);
                    }
                    std::cout << std::endl;

                    std::vector<std::size_t> bytecode_lookup_area;
                    std::cout << "Bytecode_area: ";
                    for( std::size_t i = 0; i < BytecodeTable::get_witness_amount(); i++){
                        std::cout << current_column << " ";
                        bytecode_lookup_area.push_back(current_column++);
                    }
                    std::cout << std::endl;

                    std::vector<std::size_t> exp_lookup_area;
                    std::cout << "Exponentiation_area: ";
                    for( std::size_t i = 0; i < ExpTable::get_witness_amount(); i++){
                        std::cout << current_column << " ";
                        exp_lookup_area.push_back(current_column++);
                    }
                    std::cout << std::endl;

                    std::vector<std::size_t> rw_lookup_area;
                    std::cout << "RW_area: ";
                    for( std::size_t i = 0; i < RWTable::get_witness_amount(); i++){
                        std::cout << current_column << " ";
                        rw_lookup_area.push_back(current_column++);
                    }
                    std::cout << std::endl;

                    std::vector<std::size_t> copy_lookup_area;
                    std::cout << "Copy_area: ";
                    for( std::size_t i = 0; i < CopyTable::get_witness_amount(); i++){
                        std::cout << current_column << " ";
                        copy_lookup_area.push_back(current_column++);
                    }
                    std::cout << std::endl;
                    std::cout << std::endl;

                    context_type bytecode_ct = context_object.subcontext(bytecode_lookup_area,1,max_bytecode + 1);
                    context_type exp_ct = context_object.subcontext( exp_lookup_area, 1, max_exponentiations + 1);
                    context_type rw_ct = context_object.subcontext(rw_lookup_area,1,max_rw + 1);
                    context_type copy_ct = context_object.subcontext( copy_lookup_area, 1, max_copy + 1);

                    BytecodeTable bc_t = BytecodeTable(bytecode_ct, input.bytecodes, max_bytecode);
                    ExpTable e_t = ExpTable(exp_ct, input.exponentiations, max_exponentiations);
                    RWTable rw_t = RWTable(rw_ct, input.rw_operations, max_rw, true);
                    CopyTable c_t = CopyTable(copy_ct, input.copy_events, max_copy, true);

                    auto opcode_impls = get_opcode_implementations<FieldType>();

                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        std::cout << "ZKEVM assign size=" << input.zkevm_states.size() << std::endl;
                        std::size_t current_row = 0;
                        for( std::size_t i = 0; i <input.zkevm_states.size(); i++ ){
                            const auto &current_state = input.zkevm_states[i];
                            zkevm_opcode current_opcode = opcode_from_number(current_state.opcode);

                            if( opcode_impls.find(current_opcode) == opcode_impls.end() ){
                                std::cout << "Opcode not found " << current_opcode << " skip it" << std::endl;
                                continue;
                            }
                            std::size_t current_opcode_bare_rows_amount = opcode_impls[current_opcode]->rows_amount();
                            std::size_t current_opcode_rows_amount = std::ceil(float(current_opcode_bare_rows_amount)/2) * 2;
                            // std::cout << "Fresh subcontext:"
                            //     << current_row + current_opcode_bare_rows_amount%2 << "..."
                            //     << current_row + current_opcode_bare_rows_amount%2 + current_opcode_bare_rows_amount - 1
                            //     << std::endl;
                            context_type op_ct = context_object.fresh_subcontext(
                                opcode_area,
                                current_row + current_opcode_bare_rows_amount%2,
                                current_row + current_opcode_bare_rows_amount
                            );
                            std::size_t opcode_id = (std::find(implemented_opcodes.begin(), implemented_opcodes.end(), current_opcode) - implemented_opcodes.begin());
                            std::cout << current_opcode
                                << " with id = " << opcode_id
                                << " will be assigned as " << std::hex << current_state.opcode << std::dec
                                << " on row " << current_row
                                << " rows_amount = " << current_opcode_rows_amount
                                << " stack_size = " << current_state.stack_size
                                << " memory_size = " << current_state.memory_size
                                << " rw_counter = 0x" << std::hex<< current_state.rw_counter << std::dec
                                << " gas = " << current_state.gas
                                // << " bytecode_hash = " << current_state.bytecode_hash
                                << std::endl;

                            for( std::size_t j = 0; j < current_opcode_rows_amount; j++ ){
                                BOOST_ASSERT(current_row < max_zkevm_rows);
                                std::size_t row_counter = current_opcode_rows_amount - j - 1;
                                all_states[current_row]= {};
                                all_states[current_row].call_id = current_state.call_id;
                                all_states[current_row].bytecode_hash_hi = w_hi<FieldType>(current_state.bytecode_hash);
                                all_states[current_row].bytecode_hash_lo = w_lo<FieldType>(current_state.bytecode_hash);
                                all_states[current_row].pc = current_state.pc;
                                all_states[current_row].opcode = opcode_to_number(current_opcode);
                                all_states[current_row].gas_hi = (current_state.gas & 0xFFFF0000) >> 16;
                                all_states[current_row].gas_lo = current_state.gas & 0xFFFF;
                                all_states[current_row].stack_size = current_state.stack_size;
                                all_states[current_row].memory_size = current_state.memory_size;
                                all_states[current_row].rw_counter = current_state.rw_counter;
                                all_states[current_row].row_counter = row_counter;
                                all_states[current_row].step_start = (j == 0);
                                all_states[current_row].row_counter_inv = row_counter == 0? 0: val(row_counter).inversed(); //row_counter_inv
                                all_states[current_row].opcode_parity = opcode_id % 2; // opcode_parity
                                all_states[current_row].is_even = 1 - current_row % 2; // is_even

                                opcode_selectors[current_row].resize(opcode_selectors_amount);
                                if( current_row % 2 ==  (opcode_id % 4 ) / 2) opcode_selectors[current_row][opcode_id/4] = 1;
                                opcode_row_selectors[current_row].resize(opcode_row_selectors_amount);
                                opcode_row_selectors[current_row][row_counter/2] = 1;
                                current_row++;
                            }

                            opcode_impls[current_opcode]->fill_context(op_ct, current_state);
                        }

                        while(current_row < max_zkevm_rows ){
                            std::size_t opcode_id = std::find(implemented_opcodes.begin(), implemented_opcodes.end(), zkevm_opcode::padding) - implemented_opcodes.begin();
                            std::size_t row_counter = 1 - current_row % 2;
                            all_states[current_row] = {
                                0,
                                0,
                                0,
                                0,
                                opcode_to_number(zkevm_opcode::padding),
                                0,
                                0,
                                0,
                                0,
                                0,

                                row_counter,    //row_counter
                                row_counter,  //step_start
                                row_counter,    // inv_row_counter
                                opcode_id % 2, //opcode_parity
                                1 - current_row%2 //is_even
                            };
                            opcode_selectors[current_row].resize(opcode_selectors_amount);
                            if( current_row % 2 ==  (opcode_id % 4 ) / 2 ) opcode_selectors[current_row][opcode_id/4] = 1;
                            opcode_row_selectors[current_row].resize(opcode_selectors_amount);
                            opcode_row_selectors[current_row][row_counter/2] = 1;
                            current_row++;
                        }

                        std::cout << "Assignment" << std::endl;
                    }
                    std::vector<TYPE> sample_opcode_row;
                    for( std::size_t i = 0; i < all_states.size(); i++ ){
                        std::size_t cur_column = 0;
                        allocate(all_states[i].call_id, cur_column++, i);           //0
                        allocate(all_states[i].bytecode_hash_hi, cur_column++, i);  //1
                        allocate(all_states[i].bytecode_hash_lo, cur_column++, i);  //2
                        allocate(all_states[i].pc, cur_column++, i);                //3
                        allocate(all_states[i].opcode, cur_column++, i);            //4
                        allocate(all_states[i].gas_hi, cur_column++, i);            //5
                        allocate(all_states[i].gas_lo, cur_column++, i);            //6
                        allocate(all_states[i].stack_size, cur_column++, i);        //7
                        allocate(all_states[i].memory_size, cur_column++, i);       //8
                        allocate(all_states[i].rw_counter, cur_column++, i);        //9

                        allocate(all_states[i].row_counter,cur_column++,i);         //10
                        allocate(all_states[i].step_start, cur_column++, i);        //11
                        allocate(all_states[i].row_counter_inv, cur_column++, i);   //12
                        allocate(all_states[i].opcode_parity, cur_column++, i);     //13
                        allocate(all_states[i].is_even, cur_column++, i);// Do we really need it?

                        BOOST_ASSERT(cur_column == state::get_items_amout());

                        for( std::size_t j = 0; j < opcode_selectors_amount; j++){
                            allocate(opcode_selectors[i][j], cur_column++, i);
                        }
                        for( std::size_t j = 0; j < opcode_row_selectors_amount;j++){
                            allocate(opcode_row_selectors[i][j], cur_column++, i);
                        }
                        //std::cout << "Cur_column = " << cur_column << std::endl;
                    }
                    constrain(all_states[0].is_even - 1);
                    if constexpr (stage == GenerationStage::CONSTRAINTS) {
                        std::vector<TYPE> tmp;
                        tmp = {context_object.relativize(all_states[1].gas_hi, -1)};
                        context_object.relative_lookup(tmp, "chunk_16_bits/full", 0, max_zkevm_rows-1);
                        tmp = {context_object.relativize(all_states[1].gas_lo, -1)};
                        context_object.relative_lookup(tmp, "chunk_16_bits/full", 0, max_zkevm_rows-1);
                        for(std::size_t i = 0; i < range_checked_opcode_columns_amount; i++){
                            TYPE range_checked_column;
                            allocate(range_checked_column, opcode_area[i], max_zkevm_rows-1);
                            tmp = {context_object.relativize(range_checked_column, -(max_zkevm_rows-1))};
                            context_object.relative_lookup(tmp, "chunk_16_bits/full", 0, max_zkevm_rows-1);
                        }

                        // Remove it!
                        std::vector<TYPE> erc; // every row constraints
                        std::vector<TYPE> nfrc; // non-first row constraints
                        std::vector<TYPE> mc; // non-first and non-last row constraints
                        std::vector<TYPE> relative_mc;

                        erc.push_back(all_states[1].is_even * (all_states[1].is_even - 1));
                        nfrc.push_back(all_states[1].is_even + all_states[0].is_even - 1);

                        // Define step_start and row_counter
                        erc.push_back(all_states[1].step_start * (all_states[1].step_start - 1));
                        nfrc.push_back(all_states[1].step_start * all_states[0].row_counter);
                        nfrc.push_back(all_states[0].row_counter * (all_states[0].row_counter - all_states[1].row_counter - 1));
                        erc.push_back(all_states[1].row_counter * (all_states[1].row_counter * all_states[1].row_counter_inv - 1));
                        erc.push_back(all_states[1].row_counter_inv * (all_states[1].row_counter * all_states[1].row_counter_inv - 1));

                        // State does not change inside one step
                        nfrc.push_back((1-all_states[1].step_start) * (all_states[1].gas_hi - all_states[0].gas_hi));
                        nfrc.push_back((1-all_states[1].step_start) * (all_states[1].gas_lo - all_states[0].gas_lo));
                        nfrc.push_back((1-all_states[1].step_start) * (all_states[1].stack_size - all_states[0].stack_size));
                        nfrc.push_back((1-all_states[1].step_start) * (all_states[1].memory_size - all_states[0].memory_size));
                        nfrc.push_back((1-all_states[1].step_start) * (all_states[1].pc - all_states[0].pc));
                        nfrc.push_back((1-all_states[1].step_start) * (all_states[1].rw_counter - all_states[0].rw_counter));

                        TYPE opcode_selector_sum;
                        for( std::size_t j = 0; j < opcode_selectors[1].size(); j++){
                            opcode_selector_sum += opcode_selectors[1][j] + opcode_selectors[0][j];
                            erc.push_back(opcode_selectors[1][j] * ( 1 - opcode_selectors[1][j] ));
                        }
                        nfrc.push_back(all_states[0].is_even * (opcode_selector_sum - 1));

                        TYPE opcode_row_selector_sum;
                        for( std::size_t j = 0; j < opcode_row_selectors[1].size(); j++){
                            opcode_row_selector_sum += opcode_row_selectors[1][j];
                            erc.push_back(opcode_row_selectors[1][j] * ( 1 - opcode_row_selectors[1][j] ));
                        }
                        erc.push_back(opcode_row_selector_sum - 1);

                        std::map<zkevm_opcode, TYPE> zkevm_opcode_selectors;
                        std::map<std::pair<zkevm_opcode, std::size_t>, TYPE> zkevm_opcode_row_selectors;
                        TYPE opcode_selector_check_constraint;
                        TYPE opcode_row_selector_check_constraint;
                        TYPE opcode_length_check_constraint;
                        TYPE opcode_constraint;
                        TYPE row_counter_constraint;
                        TYPE evm_opcode_constraint;
                        for( std::size_t opcode_num = 0; opcode_num < implemented_opcodes_amount; opcode_num++){
                            zkevm_opcode current_opcode = implemented_opcodes[opcode_num];
                            if( opcode_impls.find(current_opcode) == opcode_impls.end() ) {
                                std::cout << "Opcode " << current_opcode <<" implementation not found" << std::endl;
                            }
                            std::size_t current_opcode_bare_rows_amount =
                                opcode_impls.find(current_opcode) == opcode_impls.end()?
                                0:
                                opcode_impls[current_opcode]->rows_amount();
                            std::size_t current_opcode_rows_amount = std::ceil(float(current_opcode_bare_rows_amount)/2) * 2;
                            TYPE o4 = opcode_selectors[1][opcode_num/4];
                            TYPE parity = opcode_num%2 ? all_states[1].opcode_parity: 1 - all_states[1].opcode_parity;
                            TYPE is_even = all_states[1].is_even;
                            TYPE zero_constraint;
                            std::size_t bit1 = (opcode_num % 4 == 3) ||  (opcode_num % 4 == 2);
                            //zkevm_opcode_selectors[current_opcode] = parity * (1 - is_even) * (opcode_selectors[1][opcode_num/4] + opcode_selectors[0][opcode_num/4]);
                            if( !bit1 ){
                                //  1 op  parity -- current_row
                                //  0  0  parity
                                zkevm_opcode_selectors[current_opcode] = parity * (
                                    is_even * opcode_selectors[1][opcode_num/4] +
                                    opcode_selectors[0][opcode_num/4] * (1 - is_even)
                                );
                            } else {
                                //  1 0  parity -- current_row
                                //  0 op parity
                                zkevm_opcode_selectors[current_opcode] = parity * (
                                    opcode_selectors[1][opcode_num/4] * (1 - is_even) +
                                    is_even * opcode_selectors[2][opcode_num/4]
                                );
                            }
                            opcode_selector_check_constraint += zkevm_opcode_selectors[current_opcode];
                            opcode_constraint += zkevm_opcode_selectors[current_opcode] * opcode_to_number(current_opcode);
                            if( current_opcode_rows_amount != 0)
                                opcode_length_check_constraint += zkevm_opcode_selectors[current_opcode] * (current_opcode_rows_amount - 1);
                            else
                                opcode_length_check_constraint += zkevm_opcode_selectors[current_opcode];
                            if( opcode_to_number(current_opcode) < 0x100 ) evm_opcode_constraint += zkevm_opcode_selectors[current_opcode];
                            for(std::size_t i = 0; i < max_opcode_height; i++){
                                TYPE row_sel = opcode_row_selectors[1][i/2];
                                TYPE row_parity = i%2 ? is_even : 1 - is_even;
                                TYPE zero_constraint;
                                TYPE one_constraint = zero_constraint + 1;
                                //zkevm_opcode_row_selectors[std::make_pair(current_opcode, i)] = zkevm_opcode_selectors[current_opcode] * row_parity * row_sel;
                                if( !bit1 ) {
                                    if( i%2 )
                                        zkevm_opcode_row_selectors[std::make_pair(current_opcode, i)] =
                                            parity * is_even * opcode_selectors[1][opcode_num/4] * row_sel;
                                    else
                                        zkevm_opcode_row_selectors[std::make_pair(current_opcode, i)] =
                                            parity * opcode_selectors[0][opcode_num/4] * (1 - is_even) * row_sel;
                                } else {
                                    if( i%2 )
                                        zkevm_opcode_row_selectors[std::make_pair(current_opcode, i)] =
                                            parity * is_even * opcode_selectors[2][opcode_num/4] * row_sel;
                                    else
                                        zkevm_opcode_row_selectors[std::make_pair(current_opcode, i)]
                                            = parity * opcode_selectors[1][opcode_num/4] * (1 - is_even) * row_sel;
                                }
                                opcode_row_selector_check_constraint += zkevm_opcode_row_selectors[std::make_pair(current_opcode, i)];
                                row_counter_constraint += zkevm_opcode_row_selectors[std::make_pair(current_opcode, i)] * i;
                            }
                        }
                        mc.push_back(all_states[1].step_start*(opcode_length_check_constraint - all_states[1].row_counter));
                        mc.push_back(opcode_selector_check_constraint - 1);
                        mc.push_back(opcode_row_selector_check_constraint - 1);
                        mc.push_back(opcode_constraint - all_states[1].opcode);
                        mc.push_back(row_counter_constraint - all_states[1].row_counter);

                        if( stage == GenerationStage::CONSTRAINTS) {
                            std::map<std::pair<zkevm_opcode, std::size_t>, std::vector<TYPE>> opcode_constraints_aggregator;
                            std::map<std::tuple<zkevm_opcode, std::size_t, std::string>, std::vector<std::vector<TYPE>>> opcode_lookup_constraints_aggregator;
                            std::size_t max_opcode_row_constraints = 0;
                            for( std::size_t opcode_num = 0; opcode_num < implemented_opcodes.size(); opcode_num++ ){
                                zkevm_opcode current_opcode = implemented_opcodes[opcode_num];
                                //std::cout << "Build constraints for " << current_opcode << std::endl;
                                if( opcode_impls.find(current_opcode) == opcode_impls.end() ){
                                    std::cout << "\tImplementation for "<< current_opcode << " is not defined" << std::endl;
                                    continue;
                                }
                                std::size_t current_opcode_bare_rows_amount = opcode_impls[current_opcode]->rows_amount();
                                //std::cout << "\tcurrent_opcode_bare_rows_amount = " << current_opcode_bare_rows_amount << std::endl;
                                context_type fresh_ct = context_object.fresh_subcontext(
                                    opcode_area,
                                    1,
                                    1 + current_opcode_bare_rows_amount
                                );
                                zkevm_state_vars<FieldType> opcode_state_vars(all_states, current_opcode_bare_rows_amount);

                                opcode_impls[current_opcode]->fill_context(fresh_ct, opcode_state_vars);
                                auto opcode_constraints = fresh_ct.get_constraints();
                                for( const auto &constr_list: opcode_constraints){
                                    for( const auto &local_row: constr_list.first){
                                        for( auto [constraint, name]: constr_list.second){
                                            std::size_t real_row = std::ceil(float(current_opcode_bare_rows_amount) / 2) * 2 - local_row - current_opcode_bare_rows_amount % 2;
                                            opcode_constraints_aggregator[{current_opcode, real_row}].push_back(constraint);
                                            if(opcode_constraints_aggregator[{current_opcode, real_row}].size() > max_opcode_row_constraints){
                                                max_opcode_row_constraints = opcode_constraints_aggregator[{current_opcode, real_row}].size();
                                            }
                                            //std::cout << "\t" << local_row << "=>" << real_row << ": " << constraint << std::endl;
                                        }
                                        //std::cout << std::endl;
                                    }
                                }
                                auto opcode_lookup_constraints = fresh_ct.get_lookup_constraints();
                                for( const auto &constr_list: opcode_lookup_constraints){
                                    for( const auto &local_row: constr_list.first){
                                        for( auto lookup_constraint: constr_list.second){
                                            std::size_t real_row = std::ceil(float(current_opcode_bare_rows_amount) / 2) * 2 - local_row - current_opcode_bare_rows_amount % 2;
                                            opcode_lookup_constraints_aggregator[{current_opcode, real_row, lookup_constraint.first}].push_back(lookup_constraint.second);
                                            //std::cout << "\t" << local_row << "=>" << real_row  << ": " << lookup_constraint.first << std::endl;
                                            for( auto constraint:lookup_constraint.second ){
                                                //std::cout << "\t\t" << constraint << std::endl;
                                            }
                                            //std::cout << std::endl;
                                        }
                                    }
                                }
                            }
                            std::cout << "Accumulate constraints " << max_opcode_row_constraints << std::endl;
                            for( std::size_t i = 0; i < max_opcode_row_constraints; i++ ){
                                TYPE acc_constraint;
                                // std::cout << "\tConstraint " << i << std::endl;
                                for( auto &[pair, constraints]: opcode_constraints_aggregator ){
                                    if( constraints.size() <= i) continue;
                                    acc_constraint += context_object.relativize(zkevm_opcode_row_selectors[pair], -1) * constraints[i];
                                    //std::cout << "\topcode " << pair.first << " row " << pair.second << " constraint " << context_object.relativize(zkevm_opcode_row_selectors[pair], -1) * constraints[i] << std::endl;
                                    //relative_mc.push_back(context_object.relativize(zkevm_opcode_row_selectors[pair], -1) * constraints[i]);
                                }
                                relative_mc.push_back(acc_constraint);
                                //std::cout << "\t" << acc_constraint << std::endl;
                            }
                            //relative_mc.push_back(context_object.relativize(zkevm_opcode_row_selectors[{zkevm_opcode::PUSH1, 1}], -1));
                            std::cout << "Accumulate lookup constraints " << std::endl;
                            std::map<std::string, std::vector<std::vector<TYPE>>> acc_lookup_constraints;
                            for( auto &[key, exprs]:opcode_lookup_constraints_aggregator){
                                auto &[local_opcode, local_row, table_name] = key;
                                //std::cout << "\t" << local_opcode << ", " << local_row << ", " << table_name << std::endl;
                                if( acc_lookup_constraints.find(table_name) == acc_lookup_constraints.end()) acc_lookup_constraints[table_name] = {};
                                if( acc_lookup_constraints[table_name].size() < exprs.size() ) acc_lookup_constraints[table_name].resize(exprs.size());
                                for( std::size_t i = 0; i < exprs.size(); i++ ) {
                                    acc_lookup_constraints[table_name][i].resize(exprs[i].size());
                                    for( std::size_t j = 0; j < exprs[i].size(); j++ ){
                                //        std::cout << "\t\t" << exprs[i][j] << std::endl;
                                        acc_lookup_constraints[table_name][i][j] += context_object.relativize(
                                            zkevm_opcode_row_selectors[{local_opcode, local_row}], -1
                                        ) * exprs[i][j];
                                    }
                                }
                            }
                            for( auto&[table_name, constraint_list]:acc_lookup_constraints ){
                                std::cout << "\tOpcode lookups amount for " << table_name << " = " << constraint_list.size() << std::endl;
                                for(auto &exprs: constraint_list){
                                    context_object.relative_lookup(exprs, table_name, 1, max_zkevm_rows - 1);
                                }
                            }
                        }

                        for( auto &constr: erc ){
                            context_object.relative_constrain(context_object.relativize(constr, -1), 0, max_zkevm_rows-1);
                        }
                        for( auto &constr: nfrc ){
                            context_object.relative_constrain(context_object.relativize(constr, -1), 1, max_zkevm_rows-1);
                        }
                        for( auto &constr: mc ){
                            context_object.relative_constrain(context_object.relativize(constr, -1), 1, max_zkevm_rows-2);
                        }
                        for( auto &constr: relative_mc ){
                            context_object.relative_constrain(constr, 0, max_zkevm_rows-2);
                        }
                        tmp.resize(6);
                        tmp[0] = context_object.relativize(evm_opcode_constraint, -1);
                        tmp[1] = context_object.relativize(evm_opcode_constraint * all_states[1].pc, -1);
                        tmp[2] = context_object.relativize(evm_opcode_constraint * all_states[1].opcode, -1);
                        tmp[3] = context_object.relativize(evm_opcode_constraint, -1);
                        tmp[4] = context_object.relativize(evm_opcode_constraint * all_states[1].bytecode_hash_hi, -1);
                        tmp[5] = context_object.relativize(evm_opcode_constraint * all_states[1].bytecode_hash_lo, -1);

                        // TODO(oclaw): bytecode check is to be adjusted between nil and placeholder
                        // https://github.com/NilFoundation/placeholder/issues/205
                        context_object.relative_lookup(tmp, "zkevm_bytecode", 1, max_zkevm_rows-1);
                   }
                }
            protected:
                static constexpr std::size_t max_opcode_height = 8;
                static constexpr std::size_t opcode_columns_amount = 48;
                static constexpr std::size_t range_checked_opcode_columns_amount = 32;
                std::vector<zkevm_opcode> implemented_opcodes = get_implemented_opcodes_list();
            };
        }
    }
}
