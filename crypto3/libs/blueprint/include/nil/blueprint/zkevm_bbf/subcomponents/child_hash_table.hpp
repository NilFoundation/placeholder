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

#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/types/hashed_buffers.hpp>

using namespace nil::crypto3::hashes::detail;

namespace nil {
    namespace blueprint {
        namespace bbf {
            // Component for child hash table
            template<typename FieldType, GenerationStage stage>
            class child_hash_table : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;

            public:
                using typename generic_component<FieldType,stage>::TYPE;
                using input_type = typename std::conditional<stage == GenerationStage::ASSIGNMENT, std::vector<TYPE>, std::nullptr_t>::type;
                // struct input_type{
                //     std::vector<TYPE> input;
                // };
                std::size_t max_rows;

                // interfaces for interaction with other components:
                std::vector<TYPE> path_num = std::vector<TYPE>(max_rows);
                // std::vector<TYPE> node_type = std::vector<TYPE>(max_rows);
                std::array<std::vector<TYPE>,32> key_accumulated;
                std::vector<std::size_t> table_lookup_area;
                std::array<std::vector<TYPE>,32> child_hash;

                static std::size_t get_witness_amount(){
                    return 33;
                }

                child_hash_table(context_type &context_object,
                    const input_type input,
                    std::size_t max_rows_
                ) :
                    max_rows(max_rows_),
                    generic_component<FieldType,stage>(context_object) {

                    using value_type = typename FieldType::value_type;

                    for(std::size_t i = 0; i < 32; i++) {
                        child_hash[i].resize(max_rows);
                        key_accumulated[i].resize(max_rows);
                    }
                        
                    std::cout << "Child hash table:" << std::endl;

                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        std::cout << "input_size = " << input.size() << std::endl;

                        size_t i = 0, row = 0;
                        while ( i < input.size() ) {
                            path_num[row] = input[i];
                            for (std::size_t b = 0; b < 32; b++) {
                                key_accumulated[b][row] = input[i + b + 1];
                                // child_hash[b][row] = input[i + b + 33];
                            }
                            i = i + 33; row++;
                        }
                    }

                    for(std::size_t i = 0; i < max_rows; i++) {
                        allocate(path_num[i], 0, i);
                        // allocate(node_type[i], 1, i);
                        // allocate(key[i], 2, i);
                        for (std::size_t b = 0; b < 32; b++) {
                            allocate(key_accumulated[b][i], b + 1, i);
                            // allocate(child_hash[b][i], b + 33, i);
                        }
                    }

                    // // declare dynamic lookup table
                    for(std::size_t i = 0; i < 33; i++) {
                        table_lookup_area.push_back(i);
                    }
                    lookup_table("child_hash_table", table_lookup_area, 0, max_rows);
                    std::cout << "Child hash table - finished" << std::endl;
                };
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil