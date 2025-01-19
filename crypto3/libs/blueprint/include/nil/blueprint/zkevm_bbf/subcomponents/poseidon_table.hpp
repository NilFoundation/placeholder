//---------------------------------------------------------------------------//
// Copyright (c) 2024 Georgios Fotiadis <gfotiadis@nil.foundation>
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

#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/types/hashed_buffers.hpp>

using namespace nil::crypto3::hashes::detail;

namespace nil {
    namespace blueprint {
        namespace bbf {
            // Component for poseidon table
            template<typename FieldType, GenerationStage stage>
            class poseidon_table : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;

            public:
                using typename generic_component<FieldType,stage>::TYPE;
                using input_type = typename std::conditional<stage == GenerationStage::ASSIGNMENT, std::vector<std::pair<std::pair<TYPE, TYPE>, TYPE>>, std::nullptr_t>::type;
                // struct input_type{
                //     std::vector<TYPE> proof;
                // };
                std::size_t max_poseidon_size;

                using policy = poseidon_policy<FieldType, 128, /*Rate=*/ 4>;
                using hash_t = crypto3::hashes::poseidon<policy>;   

                // interfaces for interaction with other components:
                std::vector<TYPE> hash_value = std::vector<TYPE>(max_poseidon_size);
                std::vector<TYPE> left_msg = std::vector<TYPE>(max_poseidon_size);
                std::vector<TYPE> right_msg = std::vector<TYPE>(max_poseidon_size);

                static std::size_t get_witness_amount(){
                    return 3;
                }

                poseidon_table(context_type &context_object,
                    input_type input,
                    std::size_t max_poseidon_size_
                ) :
                    max_poseidon_size(max_poseidon_size_),
                    generic_component<FieldType,stage>(context_object) {

                    using value_type = typename FieldType::value_type;
                        
                    std::cout << "Poseidon table:" << std::endl;
                    std::pair<TYPE, TYPE> msg;

                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        for (std::size_t i = 0; i < max_poseidon_size; i++) {
                            if( i < input.size() ){
                                msg = std::get<0>(input[i]);
                                hash_value[i] = std::get<1>(input[i]);  
                                left_msg[i] = std::get<0>(msg);
                                right_msg[i] = std::get<1>(msg);
                            }
                            else{
                                msg = {0, 0};
                                hash_value[i] = 0;
                                left_msg[i] = std::get<0>(msg);
                                right_msg[i] = std::get<1>(msg);
                            }
                        }
                    }

                    for(std::size_t i = 0; i < max_poseidon_size; i++) {
                        allocate(hash_value[i],0,i);
                        allocate(left_msg[i],1,i);
                        allocate(right_msg[i],2,i);
                    }
                    // // declare dynamic lookup table
                    lookup_table("poseidon_table", {0,1,2}, 0, max_poseidon_size);
                };
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil