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
// @file Declaration of interfaces for PLONK BBF opcode_poc component class
//---------------------------------------------------------------------------//

#pragma once

#include <functional>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/bbf/generic.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            template<typename FieldType, GenerationStage stage>
            class dummy_block: public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::constrain;
            public:
                using typename generic_component<FieldType,stage>::TYPE;
                std::size_t block_size;
                dummy_block(context_type &context_object, std::size_t _block_size):
                    generic_component<FieldType,stage>(context_object)
                {
                    block_size = _block_size;
                    std::vector<TYPE> A(block_size);
                    for( std::size_t i = 0; i < block_size; i++){
                        if( stage == GenerationStage::ASSIGNMENT ){
                            A[i] = i;
//                            std::cout << "\t" << i << std::endl;
                        }
                        allocate(A[i], 0, i);
                        constrain(A[i] - i);
                    }
                }
            };

            template<typename FieldType, GenerationStage stage>
            class opcode_poc : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::constrain;

            public:
                using typename generic_component<FieldType,stage>::TYPE;
                using typename generic_component<FieldType,stage>::table_params;

                using input_type = std::conditional_t<
                    stage == GenerationStage::ASSIGNMENT,
                    std::vector<std::uint8_t>, std::monostate>;

            public:
                static nil::crypto3::zk::snark::plonk_table_description<FieldType>  get_table_description(std::size_t max_rows_amount){
                    nil::crypto3::zk::snark::plonk_table_description<FieldType> desc(11, 1, 0, 10);
                    desc.usable_rows_amount = max_rows_amount;
                    return desc;
                }

                static table_params get_minimal_requirements(std::size_t max_rows_amount) {
                     return {11,1,0,max_rows_amount};
                }

                static void allocate_public_inputs(
                    context_type &, input_type &, std::size_t max_rows) {}

                opcode_poc(context_type &context_object, const input_type &input, std::size_t max_rows) :
                    generic_component<FieldType,stage>(context_object) {

                    std::vector<std::uint8_t> block_list;
                    std::vector<std::array<TYPE, 5>> block_selector(max_rows);
                    std::vector<std::array<TYPE, 5>> block_row_selector(max_rows);
                    std::array<std::unordered_map<row_selector<>, std::vector<std::pair<TYPE, std::string>>>, 5> block_constraints;

                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        std::cout << "Opcode POC assignment" << std::endl;
                        block_list = input;
                        std::size_t current_row = 0;
                        for( std::size_t i = 0; i < block_list.size(); i++){
                            for( std::size_t j = 0; j < block_list[i];j++, current_row++ ){
                                block_selector[current_row][block_list[i] - 1] = 1;
                                block_row_selector[current_row][j] = 1;
                            }
                        }
                    } else {
                        std::cout << "Opcode POC constraints" << std::endl;
                        for( std::uint8_t i = 0; i < 5; i++){
                            block_list.push_back(i+1);
                        }
                    }

                    std::size_t curr_row = 0;
                    for( std::size_t i = 0; i < block_list.size(); i++ ){
                        std::vector<std::size_t> block_area = {0};
                        context_type fresh_ct = context_object.fresh_subcontext(block_area, curr_row, curr_row + block_list[i]);
                        dummy_block<FieldType, stage> block(fresh_ct, block_list[i]);
                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            curr_row += block.block_size;
                            //std::cout << "curr_row = " << curr_row << std::endl;
                        } else {
                            block_constraints[i] = fresh_ct.get_constraints();
                            // std::cout << "Block type " << i << std::endl;
                            // for( auto &constr_list: block_constraints[i]){
                            //     for( auto &constr: constr_list.first){
                            //         std::cout << "\t" << constr << ": ";
                            //         for( auto row: constr_list.second){
                            //             std::cout << row << " ";
                            //         }
                            //         std::cout << std::endl;
                            //     }
                            // }
                        }
                    }
                    for( std::size_t i = 0; i < max_rows-1; i++){
                        for( std::size_t j = 0; j < 5; j++ ){
                            allocate(block_selector[i][j], j+1, i);
                            allocate(block_row_selector[i][j], j+6, i);
                        }
                        for( std::size_t block_type = 0; block_type < 5; block_type++ ){
                            for( std::size_t block_row = 0; block_row < block_type + 1; block_row ++){
                                if constexpr (stage == GenerationStage::CONSTRAINTS) {
                                    TYPE pair_selector = block_selector[i][block_type] * block_row_selector[i][block_row];
                                    //std::cout << "Pair_selector = " << pair_selector << std::endl;
                                    TYPE pair_selector_relative = context_object.relativize(pair_selector, -i);
                                    //std::cout << "Pair_selector_relative = " << pair_selector_relative << std::endl;
                                    for( auto & constr_list: block_constraints[block_type] ){
                                        if( !constr_list.first.is_set(block_row) ) continue;
                                        for( auto &constr: constr_list.second ){
                                            //std::cout << pair_selector_relative * constr << std::endl;
                                            context_object.relative_constrain(pair_selector_relative * constr.first, i, constr.second);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil
