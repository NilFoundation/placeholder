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

#include <nil/crypto3/bench/scoped_profiler.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/util.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            // Component for keccak table
            template<typename FieldType, GenerationStage stage>
            class rlp_table : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;


            public:
                using typename generic_component<FieldType,stage>::TYPE;

                // using private_input_type = std::conditional_t<
                //         stage == GenerationStage::ASSIGNMENT,
                //         zkevm_keccak_buffers, std::monostate
                // >;

                // struct input_type {
                //     TYPE rlc_challenge;
                //     private_input_type private_input;
                // }; 
//                 [0,    55]
//                 [55,  127]
//                 [128, 183]
//                 [184, 191]
//                 [192, 247]
//                 [248, 255]

                std::size_t max_rows;

                std::vector<TYPE> rlp_prefix    = std::vector<TYPE>(max_rows);
                std::vector<TYPE> first_element = std::vector<TYPE>(max_rows);
                std::vector<TYPE> len_high      = std::vector<TYPE>(max_rows);
                std::vector<TYPE> len_low       = std::vector<TYPE>(max_rows);
                // std::vector<TYPE> range_0_55    = std::vector<TYPE>(max_blocks);
                // std::vector<TYPE> range_55_127  = std::vector<TYPE>(max_blocks);
                // std::vector<TYPE> range_128_183 = std::vector<TYPE>(max_blocks);
                // std::vector<TYPE> range_184_191 = std::vector<TYPE>(max_blocks);
                // std::vector<TYPE> range_192_247 = std::vector<TYPE>(max_blocks);
                // std::vector<TYPE> range_248_255 = std::vector<TYPE>(max_blocks);

                static std::size_t get_witness_amount(){
                    return 4;
                }

                rlp_table(context_type &context_object) :
                    max_rows(14298),
                    generic_component<FieldType,stage>(context_object) {
                    size_t row_index = 0;
                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        // TYPE theta = input.rlc_challenge;
                        for (size_t i = 0; i < 128; i++) {
                            rlp_prefix[row_index] = 0;
                            first_element[row_index] = i;
                            len_low[row_index] = 1;
                            len_high[row_index] = 0;
                            row_index++;
                        }
                            // if (i <= 55) {
                            //     range_0_55[i] = 1;
                            //     range_55_127[i] = 0;
                            //     range_128_183[i] = 0;
                            //     range_184_191[i] = 0;
                            //     range_192_247[i] = 0;
                            //     range_248_255[i] = 0;
                            // } else if (i <= 127) {
                            //     range_0_55[i] = 0;
                            //     range_55_127[i] = 1;
                            //     range_128_183[i] = 0;
                            //     range_184_191[i] = 0;
                            //     range_192_247[i] = 0;
                            //     range_248_255[i] = 0;
                            // } else if (i <= 183) {
                            //     range_0_55[i] = 0;
                            //     range_55_127[i] = 0;
                            //     range_128_183[i] = 1;
                            //     range_184_191[i] = 0;
                            //     range_192_247[i] = 0;
                            //     range_248_255[i] = 0;
                            // } else if (i <= 191) {
                            //     range_0_55[i] = 0;
                            //     range_55_127[i] = 0;
                            //     range_128_183[i] = 0;
                            //     range_184_191[i] = 1;
                            //     range_192_247[i] = 0;
                            //     range_248_255[i] = 0;
                            // } else if (i <= 247) {
                            //     range_0_55[i] = 0;
                            //     range_55_127[i] = 0;
                            //     range_128_183[i] = 0;
                            //     range_184_191[i] = 0;
                            //     range_192_247[i] = 1;
                            //     range_248_255[i] = 0;
                            // } else {
                            //     range_0_55[i] = 0;
                            //     range_55_127[i] = 0;
                            //     range_128_183[i] = 0;
                            //     range_184_191[i] = 0;
                            //     range_192_247[i] = 0;
                            //     range_248_255[i] = 1;
                            // }
                        // }
                        for (size_t i = 0; i < 128; i++) {
                            rlp_prefix[row_index] = 0x80 + 1;
                            first_element[row_index] = i;
                            len_low[row_index] = 2;
                            len_high[row_index] = 0;
                            row_index++;
                        }
                        for (size_t i = 3; i <= 55; i++) {
                            for (size_t j = 0; j < 256; j++)
                            {
                                rlp_prefix[row_index] = 0xC0 + i;
                                first_element[row_index] = j; // It can be arbitrary number
                                len_low[row_index] = i;
                                len_high[row_index] = 0;
                                row_index++;
                            }
                        }
                        for (size_t i = 56; i < 256; i++) {
                            rlp_prefix[row_index] = 0xB7 + 1;
                            first_element[row_index] = i;
                            len_low[row_index] = i;
                            len_high[row_index] = 0;
                            row_index++;
                        }
                        for (size_t i = 256; i <= 529; i++) { // 529 is the maximum length of rlp encoded branch node
                            rlp_prefix[row_index] = 0xB7 + 2;
                            first_element[row_index] = i;
                            len_low[row_index] = i & 0xFF;
                            len_high[row_index] = (i >> 8) & 0xFF;
                            row_index++;
                        }
                    }
                    for (size_t i = 0; i < row_index; i++)
                    {
                        allocate(rlp_prefix[i], 0, i);
                        allocate(first_element[i], 1, i);
                        allocate(len_low[i], 2, i);
                        allocate(len_high[i], 3, i);
                    }
                    
                    // for(std::size_t i = 0; i < max_blocks; i++) {
                    //     allocate(number[i],        0, i);
                    //     allocate(range_0_55[i],    1, i);
                    //     allocate(range_55_127[i],  2, i);
                    //     allocate(range_128_183[i], 3, i);
                    //     allocate(range_184_191[i], 4, i);
                    //     allocate(range_192_247[i], 5, i);
                    //     allocate(range_248_255[i], 6, i);
                    // }
                    // declare dynamic lookup table
                    // lookup_table("rlp_table",std::vector<std::size_t>({0, 1, 2, 3, 4, 5, 6}),0,max_blocks);
                    lookup_table("rlp_table",std::vector<std::size_t>({0, 1, 2, 3}),0,max_rows);
                };
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil
