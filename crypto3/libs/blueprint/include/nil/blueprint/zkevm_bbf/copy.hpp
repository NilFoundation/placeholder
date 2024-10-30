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

                static nil::crypto3::zk::snark::plonk_table_description<FieldType> get_table_description(
                    std::size_t max_copy,
                    std::size_t max_rw,
                    std::size_t max_keccak_blocks,
                    std::size_t max_bytecode
                ){
                    std::size_t witness_amount = 20;
                    witness_amount += BytecodeTable::get_witness_amount();
                    witness_amount += RWTable::get_witness_amount();
                    witness_amount += KeccakTable::get_witness_amount();
                    witness_amount += CopyTable::get_witness_amount();
                    nil::crypto3::zk::snark::plonk_table_description<FieldType> desc(witness_amount, 1, 3, 5);
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
                    } else
                        std::cout << "Copy circuit" << std::endl;
                }
            };
        }
    }
}
