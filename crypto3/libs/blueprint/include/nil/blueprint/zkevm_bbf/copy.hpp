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
                    desc.usable_rows_amount = std::max(std::max(max_copy, max_rw), std::max(max_keccak_blocks, max_bytecode));
                    return desc;
                }
                copy(context_type &context_object,
                    const input_type &input,
                    std::size_t max_copy,
                    std::size_t max_rw,
                    std::size_t max_keccak_blocks,
                    std::size_t max_bytecode
                ) :generic_component<FieldType,stage>(context_object) {
                   if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        std::cout << "Copy assign " << input.copy_events.size() << std::endl;
                    } else {
                        std::cout << "Copy circuit" << std::endl;
                    }

                    std::cout << "Copy assignment and circuit construction" << std::endl;
                    std::size_t current_column = copy_advice_amount;

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
                    std::vector<std::size_t> copy_lookup_area;
                    for( std::size_t i = 0; i < CopyTable::get_witness_amount(); i++){
                        copy_lookup_area.push_back(current_column++);
                    }

                    context_type bytecode_ct = context_object.subcontext(bytecode_lookup_area,0,max_bytecode);
                    context_type keccak_ct = context_object.subcontext( keccak_lookup_area, 0, max_keccak_blocks);
                    context_type rw_ct = context_object.subcontext(rw_lookup_area,0,max_rw);
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

                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        std::size_t current_row = 1;
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
                                type_selector[current_row][copy_op_to_num(cp.source_type) - 1] = 1;
                                type_selector[current_row + 1][copy_op_to_num(cp.destination_type) - 1] = 1;

                                current_row += 2;
                            }
                            std::cout << std::endl;
                        }
                    }
                    for( std::size_t i = 0; i < max_copy; i++){
                        for(std::size_t j = 0; j < 6; j++){
                            allocate(type_selector[i][j], j, i);
                        }
                        allocate(bytes[i],6, i);
                        allocate(rlc[i],7, i);
                        allocate(rlc_challenge[i],8, i);
                        TYPE memory_selector = type_selector[i][copy_op_to_num(copy_operand_type::memory) - 1];
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
                        for(std::size_t j = 0; j < 6; j++){
                            constrain(type_selector[i][j] * (type_selector[i][j] - 1));
                        }
                    }
                }
            };
        }
    }
}
