//---------------------------------------------------------------------------//
// Copyright (c) 2024 Amirhossein Khajehpour   <a.khajepour@nil.foundation>
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

                std::size_t max_rows;

                std::vector<TYPE> prefix_first         = std::vector<TYPE>(max_rows);
                std::vector<TYPE> prefix_second_image  = std::vector<TYPE>(max_rows);
                std::vector<TYPE> prefix_third         = std::vector<TYPE>(max_rows);
                // if `prefix_second_flag` is one, `prefix_second_image` should be equal to the real second prefix. 
                // otherwise `prefix_second` is zero and the real second prefix can be arbitrary. 
                // when prefix_second_flag is zero, len_image will be zero and the real len_imagegth is prefix_second * 0x100 + prefix_third
                std::vector<TYPE> prefix_second_flag  = std::vector<TYPE>(max_rows);
                
                // the following are only for conveniences 
                std::vector<TYPE> prefix_first_exists  = std::vector<TYPE>(max_rows);
                std::vector<TYPE> prefix_second_exists = std::vector<TYPE>(max_rows);
                // if prefix_third_exists is zero, len_image must be equal to real length, otherwise the real length is prefix_second * 0x100 + prefix_third
                std::vector<TYPE> prefix_third_exists  = std::vector<TYPE>(max_rows);
                
                // if `first_element_flag` is one, `first_element_image` should be equal to the real first element. 
                // otherwise `first_element` is zero and the real first element can be arbitrary
                std::vector<TYPE> first_element_flag  = std::vector<TYPE>(max_rows);
                std::vector<TYPE> first_element_image = std::vector<TYPE>(max_rows);
                std::vector<TYPE> element_type        = std::vector<TYPE>(max_rows); // 0 for array (used in node encoding) and 1 for string (used in child encoding)
                std::vector<TYPE> len_image           = std::vector<TYPE>(max_rows); // len_image

                static std::size_t get_witness_amount(){
                    return 8;
                }

                constexpr std::size_t get_rows_amount() {
                    return 1168;
                }

                rlp_table(context_type &context_object) :
                    max_rows(get_rows_amount()),
                    generic_component<FieldType,stage>(context_object) {
                    size_t row_index = 0;
                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        
                        // string encoding with zero len_image
                        prefix_first_exists[row_index] = 1;
                        prefix_second_exists[row_index] = 0;
                        prefix_third_exists[row_index] = 0;

                        prefix_first[row_index] = 0x80;
                        prefix_second_image[row_index] = 0;
                        prefix_second_flag[row_index] = 1;
                        prefix_third[row_index] = 0;
                        first_element_image[row_index] = 0;
                        first_element_flag[row_index] = 0;
                        element_type[row_index] = 1;
                        len_image[row_index] = 0;
                        row_index++;

                        // string encoding with single bytes and value less than 128
                        for (size_t i = 0; i < 128; i++) {
                            prefix_first_exists[row_index] = 0;
                            prefix_second_exists[row_index] = 0;
                            prefix_third_exists[row_index] = 0;

                            prefix_first[row_index] = 0;
                            prefix_second_image[row_index] = 0;
                            prefix_second_flag[row_index] = 1;
                            prefix_third[row_index] = 0;
                            first_element_image[row_index] = i;
                            first_element_flag[row_index] = 1;
                            element_type[row_index] = 1;
                            if (i == 0)
                                len_image[row_index] = 0;
                            else
                                len_image[row_index] = 1;
                            row_index++;
                        }

                        // string encoding with single bytes and value between 128 and 256
                        for (size_t i = 128; i < 256; i++) {
                            prefix_first_exists[row_index] = 1;
                            prefix_second_exists[row_index] = 0;
                            prefix_third_exists[row_index] = 0;

                            prefix_first[row_index] = 0x81;
                            prefix_second_image[row_index] = 0;
                            prefix_second_flag[row_index] = 1;
                            prefix_third[row_index] = 0;
                            first_element_image[row_index] = i;
                            first_element_flag[row_index] = 1;
                            element_type[row_index] = 1;
                            len_image[row_index] = 1;
                            row_index++;
                        }

                        // string encoding with len_image between 2 to 55 bytes
                        for (size_t i = 2; i < 56; i++) {
                            prefix_first_exists[row_index] = 1;
                            prefix_second_exists[row_index] = 0;
                            prefix_third_exists[row_index] = 0;

                            prefix_first[row_index] = 0x80 + i;
                            prefix_second_image[row_index] = 0;
                            prefix_second_flag[row_index] = 1;
                            prefix_third[row_index] = 0;
                            first_element_image[row_index] = 0;
                            first_element_flag[row_index] = 0;
                            element_type[row_index] = 1;
                            len_image[row_index] = i;
                            row_index++;
                        }

                        // string encoding with length between 56 and 255
                        for (size_t i = 56; i < 256; i++) {
                            prefix_first_exists[row_index] = 1;
                            prefix_second_exists[row_index] = 1;
                            prefix_third_exists[row_index] = 0;

                            prefix_first[row_index] = 0xB7 + 1;
                            prefix_second_image[row_index] = i;
                            prefix_second_flag[row_index] = 1;

                            prefix_third[row_index] = 0;
                            first_element_image[row_index] = 0;
                            first_element_flag[row_index] = 0;
                            element_type[row_index] = 1;
                            len_image[row_index] = i;
                            row_index++;
                        }

                        // string encoding with length between 255 and 65535
                        for (size_t i = 56; i < 256; i++) {
                            prefix_first_exists[row_index] = 1;
                            prefix_second_exists[row_index] = 1;
                            prefix_third_exists[row_index] = 1;

                            prefix_first[row_index] = 0xB7 + 2;
                            prefix_second_image[row_index] = 0;
                            prefix_second_flag[row_index] = 0;

                            prefix_third[row_index] = i;
                            first_element_image[row_index] = 0;
                            first_element_flag[row_index] = 0;
                            element_type[row_index] = 1;
                            len_image[row_index] = 0;
                            row_index++;
                        }

                        // array encoding with lenth less than 56 bytes
                        for (size_t i = 0; i < 56; i++) {
                            prefix_first_exists[row_index] = 1;
                            prefix_second_exists[row_index] = 0;
                            prefix_third_exists[row_index] = 0;

                            prefix_first[row_index] = 0xC0 + i;
                            prefix_second_image[row_index] = 0;
                            prefix_second_flag[row_index] = 1;
                            prefix_third[row_index] = 0;
                            first_element_image[row_index] = 0;
                            first_element_flag[row_index] = 0;
                            element_type[row_index] = 0;
                            len_image[row_index] = i;
                            row_index++;
                        }

                        // array encoding with len_imagegth between 56 and 255
                        for (size_t i = 56; i < 256; i++) {
                            prefix_first_exists[row_index] = 1;
                            prefix_second_exists[row_index] = 1;
                            prefix_third_exists[row_index] = 0;

                            prefix_first[row_index] = 0xF7 + 1;
                            prefix_second_image[row_index] = i;
                            prefix_second_flag[row_index] = 1;

                            prefix_third[row_index] = 0;
                            first_element_image[row_index] = 0;
                            first_element_flag[row_index] = 0;
                            element_type[row_index] = 0;
                            len_image[row_index] = i;
                            row_index++;
                        }

                        // array encoding with len_imagegth between 256 and 65535
                        for (size_t i = 56; i < 256; i++) {
                            prefix_first_exists[row_index] = 1;
                            prefix_second_exists[row_index] = 1;
                            prefix_third_exists[row_index] = 1;

                            prefix_first[row_index] = 0xF7 + 2;
                            prefix_second_image[row_index] = 0;
                            prefix_second_flag[row_index] = 0;

                            prefix_third[row_index] = i;
                            first_element_image[row_index] = 0;
                            first_element_flag[row_index] = 0;
                            element_type[row_index] = 0;
                            len_image[row_index] = 0;
                            row_index++;
                        }


                        for (size_t i = 0; i < row_index; i++) {
                            allocate(prefix_first[i],        0, i);
                            allocate(prefix_second_image[i], 1, i);
                            allocate(prefix_third[i],        2, i);
                            allocate(prefix_second_flag[i],  3, i);
                            allocate(first_element_flag[i],  4, i);
                            allocate(first_element_image[i], 5, i);
                            allocate(element_type[i],        6, i);
                            allocate(len_image[i],           7, i);
                        }
                    }
                    lookup_table("rlp_table",std::vector<std::size_t>({0, 1, 2, 3, 4, 5, 6, 7}),0,max_rows);
                };
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil
