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

namespace nil::blueprint::bbf::zkevm_small_field{
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

        std::vector<TYPE> RLC;
        std::vector<std::array<TYPE, 16>> hash;

        static std::size_t get_witness_amount(){
            return 17;
        }

        keccak_table(context_type &context_object,
            input_type input,
            std::size_t max_blocks_
        ) :
            max_blocks(max_blocks_),
            hash(max_blocks),
            RLC(max_blocks),
            generic_component<FieldType,stage>(context_object)
        {
            BOOST_LOG_TRIVIAL(trace) << "Small field keccak table assignment";
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                TYPE theta = input.rlc_challenge;

                BOOST_LOG_TRIVIAL(trace) << "Keccak buffters amount = " << input.private_input.get_data().size();
                for(std::size_t i = 0; i < input.private_input.get_data().size(); i++) {
                    const std::vector<std::uint8_t> &msg = input.private_input.get_data()[i].first;
                    zkevm_word_type hash_value = input.private_input.input[i].second;
                    RLC[i] = calculateRLC<FieldType>(msg, theta);
                    auto hash_chunks = w_to_16(hash_value);
                    for(std::size_t j = 0; j < hash_chunks.size(); j++) {
                        hash[i][j] = hash_chunks[j];
                    }
                }
                zkevm_word_type zero_hash = zkevm_keccak_hash({});
                auto zero_hash_chunks = w_to_16(zero_hash);
                for(std::size_t i = input.private_input.get_data().size(); i < max_blocks; i++) {
                    for(std::size_t j = 0; j < zero_hash_chunks.size(); j++) {
                        hash[i][j] = zero_hash_chunks[j];
                    }
                }
            }
            // allocate everything
            for(std::size_t i = 0; i < max_blocks; i++) {
                allocate(RLC[i],0,i);
                for( std::size_t j = 0; j < 16; j++){
                    allocate(hash[i][j],1+j,i);
                }
            }
            // declare dynamic lookup table
            std::vector<std::size_t> keccak_lookup_area = {0};
            for( std::size_t i = 0; i < 16; i++){
                keccak_lookup_area.push_back(1+i);
            }
            lookup_table("keccak_table",keccak_lookup_area,0,max_blocks);
        };
    };
}