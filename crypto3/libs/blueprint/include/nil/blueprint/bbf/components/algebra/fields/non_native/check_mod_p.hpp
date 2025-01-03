//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
// Copyright (c) 2024 Antoine Cyr <antoine.cyr@nil.foundation>
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
// @file Declaration of interfaces for FRI verification array swapping component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BBF_COMPONENTS_CHECK_MOD_P_HPP
#define CRYPTO3_BBF_COMPONENTS_CHECK_MOD_P_HPP

#include <functional>
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/bbf/components/detail/range_check_multi.hpp>
#include <nil/blueprint/bbf/components/detail/carry_on_addition.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            namespace components {
                // Parameters: num_chunks = k, bit_size_chunk = b
                // Checking that x is in the interval [0;p-1]
                // operates on k-chunked x and p' = 2^(kb) - p
                // Input: x[0], ..., x[k-1], pp[0], ..., pp[k-1]
                // Output: none

                template<typename FieldType>
                struct check_mod_p_raw_input {
                    using TYPE = typename FieldType::value_type;
                    std::vector<TYPE> x;
                    std::vector<TYPE> pp;
                    TYPE zero;
                };

                template<typename FieldType, GenerationStage stage>
                class check_mod_p : public generic_component<FieldType, stage> {
                    using generic_component<FieldType, stage>::allocate;
                    using generic_component<FieldType, stage>::copy_constrain;
                    using generic_component<FieldType, stage>::constrain;
                    using generic_component<FieldType, stage>::lookup;
                    using component_type = generic_component<FieldType, stage>;

                  public:
                    using typename generic_component<FieldType, stage>::TYPE;
                    using typename generic_component<FieldType, stage>::context_type;
                    using typename generic_component<FieldType, stage>::table_params;
                    using raw_input_type =
                        typename std::conditional<stage == GenerationStage::ASSIGNMENT,
                                                  check_mod_p_raw_input<FieldType>,
                                                  std::tuple<>>::type;
                  public:
                    std::vector<TYPE> inp_x;
                    std::vector<TYPE> inp_pp;
                    TYPE inp_zero;
                    TYPE output;

                    static table_params get_minimal_requirements(std::size_t num_chunks,
                                                                 std::size_t bit_size_chunk,
                                                                 bool expect_output) {
                        static const std::size_t bit_size_rc = 16;
                        std::size_t num_rc_chunks = (bit_size_chunk / bit_size_rc) + (bit_size_chunk % bit_size_rc > 0);

                        // Same witness columns as range_check_multi
                        std::size_t witness = (num_rc_chunks+1)/2 + 1;
                        constexpr std::size_t public_inputs = 1;
                        constexpr std::size_t constants = 0;
                        //rows = 4096-1 so that lookup table is not too hard to fit and padding doesn't inflate the table
                        constexpr std::size_t rows = 4095;
                        return {witness, public_inputs, constants, rows};
                    }

                    static std::tuple<std::vector<TYPE>,std::vector<TYPE>,TYPE> form_input(context_type &context_object,
                                                                    raw_input_type raw_input,
                                                                    std::size_t num_chunks,
                                                                    std::size_t bit_size_chunk,
                                                                    bool expect_output) {
                        std::vector<TYPE> input_x(num_chunks);
                        std::vector<TYPE> input_pp(num_chunks);
                        TYPE input_zero;
                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            for (std::size_t i = 0; i < num_chunks; i++) {
                                input_x[i] = raw_input.x[i];
                                input_pp[i] = raw_input.pp[i];
                            }
                            input_zero =raw_input.zero;
                        }
                        for (std::size_t i = 0; i < num_chunks; i++)
                        {
                            context_object.allocate(input_x[i], 0, i, column_type::public_input);
                            context_object.allocate(input_pp[i], 0, i+num_chunks, column_type::public_input);
                        }
                        context_object.allocate(input_zero,0,2*num_chunks + 1,column_type::public_input);
                        return std::make_tuple(input_x,input_pp,input_zero);
                    }

                    check_mod_p(context_type &context_object, std::vector<TYPE> input_x, std::vector<TYPE> input_pp, TYPE input_zero,
                                      std::size_t num_chunks, std::size_t bit_size_chunk,bool expect_output,
                                      bool make_links = true)
                        : generic_component<FieldType, stage>(context_object) {
                        using integral_type = typename FieldType::integral_type;

                        using Carry_On_Addition = typename bbf::components::carry_on_addition<FieldType,stage>;
                        using Range_Check = typename bbf::components::range_check_multi<FieldType,stage>;

                        Carry_On_Addition ca = Carry_On_Addition(context_object,input_x,input_pp,num_chunks,bit_size_chunk);
                        Range_Check rc = Range_Check(context_object, ca.res_z,num_chunks,bit_size_chunk);
                        
                        if(expect_output){
                            output = ca.res_c;
                        }
                        else{
                            copy_constrain(ca.res_c,input_zero);
                        }

                        for (std::size_t i = 0; i < num_chunks; i++) {
                            inp_x.push_back(input_x[i]);
                            inp_pp.push_back(input_pp[i]);
                            inp_zero = input_zero;
                        }

                    }
                };

            }  // namespace components
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil

#endif  // CRYPTO3_BBF_COMPONENTS_CHECK_MOD_P_HPP
