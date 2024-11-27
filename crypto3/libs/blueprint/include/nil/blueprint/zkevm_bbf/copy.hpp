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

#include <nil/blueprint/zkevm_bbf/subcomponents/keccak_table.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/bytecode_table.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/rw_table.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/copy_table.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            template<typename FieldType, GenerationStage stage>
            class copy : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;
            public:
                using typename generic_component<FieldType,stage>::TYPE;
                using integral_type =  boost::multiprecision::number<boost::multiprecision::backends::cpp_int_modular_backend<257>>;

                struct input_type{
                    TYPE rlc_challenge;
                    typename std::conditional<stage == GenerationStage::ASSIGNMENT, zkevm_keccak_buffers, nullptr_t>::type bytecodes;
                    typename std::conditional<stage == GenerationStage::ASSIGNMENT, zkevm_keccak_buffers, nullptr_t>::type keccak_buffers;
                    typename std::conditional<stage==GenerationStage::ASSIGNMENT, std::vector<rw_operation>, std::nullptr_t>::type rw_operations;
                    typename std::conditional<stage==GenerationStage::ASSIGNMENT, std::vector<copy_event>, std::nullptr_t>::type copy_events;
                };
            public:
                using BytecodeTable = bytecode_table<FieldType, stage>;
                using RWTable = rw_table<FieldType, stage>;
                using KeccakTable = keccak_table<FieldType, stage>;
                using CopyTable = copy_table<FieldType, stage>;

                static constexpr std::size_t copy_advice_amount = 11;

                static nil::crypto3::zk::snark::plonk_table_description<FieldType> get_table_description(
                    std::size_t max_copy,
                    std::size_t max_rw,
                    std::size_t max_keccak_blocks,
                    std::size_t max_bytecode
                ){
                    std::size_t witness_amount = copy_advice_amount;
                    witness_amount += BytecodeTable::get_witness_amount();
                    witness_amount += RWTable::get_witness_amount();
                    witness_amount += KeccakTable::get_witness_amount();
                    witness_amount += CopyTable::get_witness_amount();
                    nil::crypto3::zk::snark::plonk_table_description<FieldType> desc(witness_amount, 1, 3, 10);
                    desc.usable_rows_amount = std::max(std::max(max_copy, max_rw + 1), std::max(max_keccak_blocks + 1, max_bytecode + 1));
                    return desc;
                }
                copy(context_type &context_object,
                    const input_type &input,
                    std::size_t max_copy,
                    std::size_t max_rw,
                    std::size_t max_keccak_blocks,
                    std::size_t max_bytecode
                ) :generic_component<FieldType,stage>(context_object) {
                    auto zerohash = zkevm_keccak_hash({});
                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        std::cout << "Copy assign " << input.copy_events.size() << std::endl;
                    } else {
                        std::cout << "Copy circuit" << std::endl;
                    }

                    std::cout << "Copy assignment and circuit construction" << std::endl;
                    std::size_t current_column = copy_advice_amount;

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

                    // Dynamic lookups shouldn't be placed on 0 row.
                    context_type bytecode_ct = context_object.subcontext(bytecode_lookup_area,1,max_bytecode + 1);
                    context_type keccak_ct = context_object.subcontext( keccak_lookup_area, 1, max_keccak_blocks + 1);
                    context_type rw_ct = context_object.subcontext(rw_lookup_area, 1, max_rw + 1);

                    context_type copy_ct = context_object.subcontext( copy_lookup_area, 0, max_copy);

                    BytecodeTable bc_t = BytecodeTable(bytecode_ct, input.bytecodes, max_bytecode);
                    KeccakTable k_t = KeccakTable(keccak_ct, {input.rlc_challenge, input.keccak_buffers}, max_keccak_blocks);
                    RWTable rw_t = RWTable(rw_ct, input.rw_operations, max_rw, true);
                    CopyTable c_t = CopyTable(copy_ct, input.copy_events, max_copy, false);

                    const std::vector<TYPE> is_first = c_t.is_first;
                    const std::vector<TYPE> id_hi = c_t.id_hi;
                    const std::vector<TYPE> id_lo = c_t.id_lo;
                    const std::vector<TYPE> cp_type = c_t.cp_type;
                    const std::vector<TYPE> addr = c_t.addr;
                    const std::vector<TYPE> length = c_t.length;
                    const std::vector<TYPE> is_write = c_t.is_write;
                    const std::vector<TYPE> rw_counter = c_t.rw_counter;

                    std::vector<std::array<TYPE, 6>> type_selector(max_copy);
                    std::vector<TYPE>       bytes(max_copy);
                    std::vector<TYPE>       rlc(max_copy);
                    std::vector<TYPE>       rlc_challenge(max_copy);
                    std::vector<TYPE>       is_last(max_copy);

                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        std::size_t current_row = 0;
                        for( auto &cp: input.copy_events ){
                            std::cout
                                << "\tCopy event " << copy_op_to_num(cp.source_type)
                                << " => " << copy_op_to_num(cp.destination_type)
                                << " bytes size" << cp.bytes.size()
                                << std::endl;
                            for( std::size_t i = 0; i < cp.bytes.size(); i++ ){
                                std::cout << std::hex << std::size_t(cp.bytes[i]) << " " << std::dec;
                                bytes[current_row] = cp.bytes[i];
                                bytes[current_row + 1] = cp.bytes[i];
                                rlc_challenge[current_row] = input.rlc_challenge;
                                rlc_challenge[current_row  + 1] = input.rlc_challenge;
                                rlc[current_row] = i == 0? length[current_row] * rlc_challenge[current_row]: rlc[current_row - 1] * rlc_challenge[current_row];
                                rlc[current_row + 1] = rlc[current_row] + bytes[current_row];
                                type_selector[current_row][copy_op_to_num(cp.source_type) - 1] = 1;
                                type_selector[current_row + 1][copy_op_to_num(cp.destination_type) - 1] = 1;

                                current_row += 2;
                            }
                            is_last[current_row - 1] = 1;
                            std::cout << std::endl;
                            std::cout << "\tFor bytes size = " << cp.bytes.size() << " last row is " << current_row - 1 << std::endl;
                        }
                    }
                    for( std::size_t i = 0; i < max_copy; i++){
                        for(std::size_t j = 0; j < 6; j++){
                            allocate(type_selector[i][j], j, i);
                        }
                        allocate(bytes[i],6, i);
                        allocate(rlc[i],7, i);
                        allocate(rlc_challenge[i],8, i);
                        allocate(is_last[i], 9, i);

                        TYPE memory_selector = type_selector[i][copy_op_to_num(copy_operand_type::memory) - 1];
                        TYPE keccak_selector = type_selector[i][copy_op_to_num(copy_operand_type::keccak) - 1];
                        std::vector<TYPE> tmp;
                        tmp = {
                            memory_selector * TYPE(rw_op_to_num(rw_operation_type::memory)),
                            memory_selector * id_lo[i],
                            memory_selector * addr[i],
                            TYPE(0),// storage_key_hi
                            TYPE(0),// storage_key_lo
                            TYPE(0),// field
                            memory_selector * rw_counter[i],
                            memory_selector * is_write[i],// is_write
                            TYPE(0),
                            memory_selector * bytes[i]
                        };
                        lookup(tmp, "zkevm_rw");
                        tmp = {
                            TYPE(1) ,
                            keccak_selector * is_last[i] * rlc[i],
                            keccak_selector * is_last[i] * id_hi[i] + (1 - keccak_selector * is_last[i]) * w_hi<FieldType>(zerohash),
                            keccak_selector * is_last[i] * id_lo[i] + (1 - keccak_selector * is_last[i]) * w_lo<FieldType>(zerohash)
                        };
                        lookup(tmp, "keccak_table");
                    }
                    if constexpr( stage == GenerationStage::CONSTRAINTS ){
                        std::vector<TYPE> even;
                        std::vector<TYPE> odd;
                        std::vector<TYPE> every;
                        std::vector<TYPE> non_first;

                        every.push_back(context_object.relativize(is_write[1]  * (is_write[1] - 1), -1));
                        every.push_back(context_object.relativize(is_first[1]  * (is_first[1] - 1), -1));
                        every.push_back(context_object.relativize(is_last[1]  * (is_last[1] - 1), -1));
                        TYPE type_selector_sum;
                        TYPE cp_type_constraint;
                        for(std::size_t j = 0; j < 6; j++){
                            type_selector_sum += type_selector[1][j];
                            cp_type_constraint += (j+1) * type_selector[1][j];
                            every.push_back(context_object.relativize(type_selector[1][j]  * (type_selector[1][j] - 1), -1));
                        }
                        every.push_back(context_object.relativize(type_selector_sum  * (type_selector_sum - 1), -1));
                        every.push_back(context_object.relativize(cp_type_constraint - cp_type[1], -1));
                        every.push_back(context_object.relativize((type_selector_sum - 1)* is_last[1], -1));
                        every.push_back(context_object.relativize((type_selector_sum - 1)* is_first[1], -1));

                        non_first.push_back(context_object.relativize(type_selector_sum * (rlc_challenge[1] - rlc_challenge[0]), -1));

                        even.push_back(context_object.relativize(is_write[1], -1));
                        even.push_back(context_object.relativize(is_last[1], -1));
                        even.push_back(context_object.relativize(type_selector_sum * (1 - is_first[1]) * (id_hi[0] - id_hi[2]),-1));
                        even.push_back(context_object.relativize(type_selector_sum * (1 - is_first[1]) * (id_lo[0] - id_lo[2]),-1));
                        even.push_back(context_object.relativize(type_selector_sum * (1 - is_first[1]) * (cp_type[0] - cp_type[2]),-1));
                        even.push_back(context_object.relativize(type_selector_sum * (1 - is_first[1]) * (addr[0] - addr[2] + 1),-1));
                        even.push_back(context_object.relativize((1 - is_first[1]) * type_selector_sum * (length[0] - length[2] - 1),-1));
                        even.push_back(context_object.relativize((1 - is_first[1]) * type_selector_sum * (rw_counter[0] - rw_counter[2] + 1),-1));
                        even.push_back(context_object.relativize(is_first[1] *(rlc[1] - length[1] * rlc_challenge[1]),-1));
                        even.push_back(context_object.relativize((1 - is_first[1]) * type_selector_sum * (rlc[1] - rlc[0] * rlc_challenge[1]),-1));

                        odd.push_back(context_object.relativize(1 - is_write[1], -1));
                        odd.push_back(context_object.relativize(bytes[1] - bytes[0], -1));
                        odd.push_back(context_object.relativize(is_first[1] - is_first[0], -1));
                        odd.push_back(context_object.relativize(length[1] - length[0], -1));

                        odd.push_back(context_object.relativize(type_selector_sum * (1 - is_last[1]) * (id_hi[0] - id_hi[2]),-1));
                        odd.push_back(context_object.relativize(type_selector_sum * (1 - is_last[1]) * (id_lo[0] - id_lo[2]),-1));
                        odd.push_back(context_object.relativize(type_selector_sum * (1 - is_last[1]) * (cp_type[0] - cp_type[2]),-1));
                        odd.push_back(context_object.relativize(type_selector_sum * (1 - is_last[1]) * (addr[0] - addr[2] + 1),-1));
                        odd.push_back(context_object.relativize(type_selector_sum * (rlc[1] - rlc[0] - bytes[1]),-1));
                        odd.push_back(context_object.relativize((1 - is_last[1]) * type_selector_sum * (length[0] - length[2] - 1),-1));
                        odd.push_back(context_object.relativize((1 - is_last[1]) * type_selector_sum * (rw_counter[0] - rw_counter[2] + 1),-1));
                        odd.push_back(context_object.relativize(is_last[1] * (length[1] - 1), -1));

                        for( std::size_t i = 0; i < even.size(); i++ ){
                            for( std::size_t j = 0; j < max_copy-1; j+=2 ){
                                context_object.relative_constrain(even[i], j);
                            }
                        }
                        for( std::size_t i = 0; i < odd.size(); i++ ){
                            for( std::size_t j = 1; j <= max_copy-1; j+=2 ){
                                context_object.relative_constrain(odd[i], j);
                            }
                        }
                        for( std::size_t i = 0; i < every.size(); i++ ){
                            context_object.relative_constrain(every[i], 0, max_copy-1);
                        }
                        for( std::size_t i = 0; i < non_first.size(); i++ ){
                            context_object.relative_constrain(non_first[i], 1, max_copy-1);
                        }
                    }
                }
            };
        }
    }
}
