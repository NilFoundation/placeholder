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

#include <utility>

#include <nil/blueprint/zkevm_bbf/types/hashed_buffers.hpp>

namespace nil::blueprint::bbf::zkevm_big_field{
    // Component for bytecode table

    template<typename FieldType, GenerationStage stage>
    class bytecode_table : public generic_component<FieldType, stage> {
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

        std::size_t max_bytecode_size;

        // interfaces for interaction with other components:
        std::vector<TYPE> tag = std::vector<TYPE>(max_bytecode_size);
        std::vector<TYPE> index = std::vector<TYPE>(max_bytecode_size);
        std::vector<TYPE> value = std::vector<TYPE>(max_bytecode_size);
        std::vector<TYPE> is_opcode = std::vector<TYPE>(max_bytecode_size);
        std::vector<TYPE> hash_hi = std::vector<TYPE>(max_bytecode_size);
        std::vector<TYPE> hash_lo = std::vector<TYPE>(max_bytecode_size);

        static std::size_t get_witness_amount(){
            return 6;
        }

        bytecode_table(context_type &context_object,
                            const input_type &input,
                            std::size_t max_bytecode_size_,
                            bool make_links = true) :
            max_bytecode_size(max_bytecode_size_),
            generic_component<FieldType,stage>(context_object) {

            // if we're in assignment stage, prepare all the values
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                auto bytecodes = input.get_data();

                std::size_t cur = 0;
                for(std::size_t i = 0; i < bytecodes.size(); i++) {
                    std::cout << "Bytecode " << i << " size = " << bytecodes[i].first.size() << std::endl;
                    TYPE hash_hi_val = w_hi<FieldType>(bytecodes[i].second);
                    TYPE hash_lo_val = w_lo<FieldType>(bytecodes[i].second);
                    TYPE push_size = 0;
                    const auto &buffer = bytecodes[i].first;
                    for(std::size_t j = 0; j < buffer.size(); j++, cur++){
                        BOOST_ASSERT(cur < max_bytecode_size);
                        std::uint8_t byte = buffer[j];
                        hash_hi[cur] = hash_hi_val;
                        hash_lo[cur] = hash_lo_val;
                        if( j == 0) { // HEADER
                            value[cur] = buffer.size();
                            tag[cur] = 0;
                            index[cur] = 0;
                            is_opcode[cur] = 0;
                            push_size = 0; // might be unnecessary
                            cur++;
                        }
                        // BYTE
                        value[cur] = byte;
                        hash_hi[cur] = hash_hi_val;
                        hash_lo[cur] = hash_lo_val;
                        tag[cur] = 1;
                        index[cur] = j;
                        if (push_size == 0) {
                            is_opcode[cur] = 1;
                            if (byte > 0x5f && byte < 0x80) push_size = byte - 0x5f;
                        } else {
                            is_opcode[cur] = 0;
                            push_size--;
                        }
                        //std::cout << cur << ". " << std::hex << std::size_t(byte) << " " << is_opcode[cur] << " " << push_size << std::dec << std::endl;
                    }
                }
            }
            // allocate everything. NB: this replaces the map from the original component
            for(std::size_t i = 0; i < max_bytecode_size; i++) {
                allocate(tag[i],0,i);
                allocate(index[i],1,i);
                allocate(value[i],2,i);
                allocate(is_opcode[i],3,i);
                allocate(hash_hi[i],4,i);
                allocate(hash_lo[i],5,i);
            }
            // declare dynamic lookup table
            lookup_table("zkevm_bytecode",std::vector<std::size_t>({0,1,2,3,4,5}),0,max_bytecode_size);
        };
    };
}