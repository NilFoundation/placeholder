//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova   <e.tatuzova@nil.foundation>
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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
#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/blueprint/components/hashes/keccak/util.hpp> //Move needed utils to bbf
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/types/hashed_buffers.hpp>

namespace nil::blueprint::bbf::zkevm_big_field{
    // Component for keccak table
    template<typename FieldType, GenerationStage stage>
    class keccak_table : public generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

    public:
        using typename generic_component<FieldType,stage>::TYPE;

        using private_input_type = std::conditional_t<
                stage == GenerationStage::ASSIGNMENT,
                zkevm_keccak_buffers, std::monostate
        >;

        struct input_type {
            TYPE rlc_challenge;
            private_input_type private_input;
        };

        std::size_t max_blocks;

        std::vector<TYPE> is_last = std::vector<TYPE>(max_blocks);
        std::vector<TYPE> hash_hi = std::vector<TYPE>(max_blocks);
        std::vector<TYPE> hash_lo = std::vector<TYPE>(max_blocks);
        std::vector<TYPE> RLC = std::vector<TYPE>(max_blocks);

        static std::size_t get_witness_amount(){
            return 4;
        }

        keccak_table(context_type &context_object,
            input_type input,
            std::size_t max_blocks_
        ) :
            max_blocks(max_blocks_),
            generic_component<FieldType,stage>(context_object) {
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                TYPE theta = input.rlc_challenge;

                std::size_t input_idx = 0;
                std::size_t block_counter = 0;
                std::vector<std::uint8_t> msg;
                zkevm_word_type hash;

                while( block_counter < max_blocks ) {
                    if( input_idx < input.private_input.input.size() ){
                        msg = std::get<0>(input.private_input.input[input_idx]);
                        hash = std::get<1>(input.private_input.input[input_idx]);
                        input_idx++;
                    } else {
                        msg = {};
                        hash = zkevm_keccak_hash(msg);
                    }
                    TYPE RLC_value = calculateRLC<FieldType>(msg, theta);
                    for( std::size_t block = 0; block < std::ceil(float(msg.size() + 1)/136); block++){
                        assert(block_counter < max_blocks);
                        if( block != std::ceil(float(msg.size() + 1)/136) - 1){
                            is_last[block_counter] = 0;
                        } else {
                            is_last[block_counter] = 1;
                        }
                        RLC[block_counter] = RLC_value;
                        hash_hi[block_counter] = w_hi<FieldType>(hash);
                        hash_lo[block_counter] = w_lo<FieldType>(hash);
                        block_counter++;
                    }
                }
            }
            // allocate everything. NB: this replaces the map from the original component
            for(std::size_t i = 0; i < max_blocks; i++) {
                allocate(is_last[i],0,i);
                allocate(RLC[i],1,i);
                allocate(hash_hi[i],2,i);
                allocate(hash_lo[i],3,i);
            }
            // declare dynamic lookup table
            lookup_table("keccak_table",std::vector<std::size_t>({0,1,2,3}),0,max_blocks);
        };
    };
}