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

#include <utility>

#include <nil/blueprint/zkevm_bbf/types/hashed_buffers.hpp>

namespace nil::blueprint::bbf::zkevm_small_field{
    // Component for bytecode table

    template<typename FieldType, GenerationStage stage>
    class bytecode_hash_table : public generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

        public:
        using typename generic_component<FieldType,stage>::TYPE;
        using input_type = std::conditional_t<
            stage == GenerationStage::ASSIGNMENT, zkevm_keccak_buffers, std::monostate
        >;

        std::size_t max_bytecodes_amount;

        // interfaces for interaction with other components:
        std::vector<TYPE> tag;
        std::vector<TYPE> bytecode_id;
        std::vector<TYPE> bytecode_size;
        std::vector<std::array<TYPE, 16>> bytecode_hash;

        static std::size_t get_witness_amount(){
            return 20;
        }

        bytecode_hash_table(context_type &context_object,
                            const input_type &input,
                            std::size_t max_bytecodes_amount_,
                            bool make_links = true) :
            max_bytecodes_amount(max_bytecodes_amount_),
            generic_component<FieldType,stage>(context_object),
            tag(max_bytecodes_amount),
            bytecode_id(max_bytecodes_amount),
            bytecode_size(max_bytecodes_amount),
            bytecode_hash(max_bytecodes_amount) {

            // if we're in assignment stage, prepare all the values
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                const auto &bytecodes = input.get_data();

                std::size_t cur = 0;
                for(std::size_t i = 0; i < bytecodes.size(); i++) {
                    tag[i] = 1;
                    bytecode_id[i] = i + 1;
                    bytecode_size[i] = bytecodes[i].first.size();
                    auto buff = w_to_16(bytecodes[i].second);
                    for(std::size_t j = 0; j < buff.size(); j++) {
                        bytecode_hash[i][j] = buff[j];
                    }
                }
                zkevm_word_type zero_hash = zkevm_keccak_hash({});
                auto zero_hash_chunks = w_to_16(zero_hash);
                for(std::size_t i = bytecodes.size(); i < max_bytecodes_amount; i++) {
                    for(std::size_t j = 0; j < zero_hash_chunks.size(); j++) {
                        bytecode_hash[i][j] = zero_hash_chunks[j];
                    }
                }
            }
            // allocate everything. NB: this replaces the map from the original component
            for(std::size_t i = 0; i < max_bytecodes_amount; i++) {
                std::size_t cur = 0;
                allocate(tag[i],cur++,i);
                allocate(bytecode_id[i],cur++,i);
                allocate(bytecode_size[i],cur++,i);
                for(std::size_t j = 0; j < 16; j++){
                    allocate(bytecode_hash[i][j],cur++,i);
                }
            }
            // declare dynamic lookup table
            std::vector<std::size_t> opcode_lookup_area = {0,1,2};
            std::vector<std::size_t> bytecode_lookup_area = {0,1,2};
            for( std::size_t i = 0; i < 16; i++){
                opcode_lookup_area.push_back(i + 3);
            }

            lookup_table("zkevm_bytecode_hash_opcodes", opcode_lookup_area ,0,max_bytecodes_amount);
            lookup_table("zkevm_bytecode_hash", bytecode_lookup_area ,0,max_bytecodes_amount);
        };
    };
}