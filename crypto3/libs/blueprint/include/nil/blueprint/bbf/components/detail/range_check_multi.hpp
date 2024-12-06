//---------------------------------------------------------------------------//
// Copyright (c) 2024 Polina Chernyshova <pockvokhbtra@nil.foundation>
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

#ifndef CRYPTO3_BBF_COMPONENTS_RANGE_CHECK_MULTI_HPP
#define CRYPTO3_BBF_COMPONENTS_RANGE_CHECK_MULTI_HPP

#include <algorithm>
#include <functional>
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <numeric>

namespace nil {
    namespace blueprint {
        namespace bbf {
            namespace components {

                template<typename FieldType>
                struct range_check_multi_raw_input {
                    using TYPE = typename FieldType::value_type;
                    std::vector<TYPE> state;
                };

                template<typename FieldType, GenerationStage stage,std::size_t num_chunks_,
                                      std::size_t bit_size_chunk_>
                class range_check_multi : public generic_component<FieldType, stage> {
                    using generic_component<FieldType, stage>::allocate;
                    using generic_component<FieldType, stage>::copy_constrain;
                    using generic_component<FieldType, stage>::constrain;
                    using component_type = generic_component<FieldType, stage>;

                  public:
                    using typename generic_component<FieldType, stage>::TYPE;
                    using typename generic_component<FieldType, stage>::context_type;
                    using typename generic_component<FieldType,stage>::table_params;
                    using raw_input_type = typename std::conditional<stage == GenerationStage::ASSIGNMENT,
                                               range_check_multi_raw_input<FieldType>,std::tuple<>>::type;

                  public:
                  std::vector<TYPE> input_state;

                    //TODO
                     static table_params get_minimal_requirements() {
                        constexpr std::size_t witness = 10;
                        constexpr std::size_t total_cells = 10;
                        constexpr std::size_t public_inputs = 1;
                        constexpr std::size_t constants = 0;
                        std::size_t rows = (total_cells + witness - 1) / witness;
                        return {witness, public_inputs, constants, rows};
                    }

                    static std::tuple<std::vector<TYPE>> form_input(context_type &context_object, raw_input_type raw_input) {
                       std::vector<TYPE> input_state;
                       for(std::size_t i = 0; i < num_chunks_; i++) {
                           if constexpr (stage == GenerationStage::ASSIGNMENT) {
                               input_state[i] = raw_input.state[i];
                           }
                           context_object.allocate(input_state[i],0,i,column_type::public_input);
                       }
                       return std::make_tuple(input_state);
                    }

                    range_check_multi(context_type &context_object,
                                      std::vector<TYPE> input_state, bool make_links = true)
                        : generic_component<FieldType, stage>(context_object) {
                            using integral_type = boost::multiprecision::number<
                        boost::multiprecision::backends::cpp_int_modular_backend<257>>;

                        static const std::size_t num_chunks = num_chunks_;
                        static const std::size_t bit_size_chunk = bit_size_chunk_;

                        static const std::size_t bit_size_rc = 16;
                        static const std::size_t num_rc_chunks =
                            (bit_size_chunk / bit_size_rc) + (bit_size_chunk % bit_size_rc > 0);
                        static const std::size_t first_chunk_size = bit_size_chunk % bit_size_rc;

                        TYPE y[num_chunks][num_rc_chunks];
                        TYPE y_integral_type[num_chunks];
                        TYPE x[num_chunks];
                        TYPE constr[num_chunks];

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            integral_type x_integral;
                            integral_type y_integral;
                            integral_type mask = (1 << bit_size_rc) - 1;
                            for (std::size_t i = 0; i < num_chunks; ++i) {
                                x[num_chunks] = input_state[i];
                                x_integral = integral_type(input_state[i]);

                                for (std::size_t j = 0; j < num_rc_chunks; ++j) {
                                    y_integral = x_integral & mask;
                                    y[i][j] = y_integral;
                                    x_integral >>= bit_size_rc;
                                }
                                if (first_chunk_size != 0) {
                                    y_integral_type[i] =
                                        integral_type(y[i][num_rc_chunks - 1]) *
                                        (integral_type(1) << (bit_size_rc - first_chunk_size));
                                }
                            }
                        }
                        for (std::size_t i = 0; i < num_chunks; ++i) {
                            allocate(x[i]);
                            allocate(y[i]);

                            integral_type power = 1;
                            constr[i] = x[i];
                            for (std::size_t j = 0; j < num_rc_chunks; ++j) {
                                constr -= y[i][j];
                                power <<= bit_size_rc;
                                lookup(y[i][j], "chunk_16_bits/full");
                            }
                            constraint(constr);
                            
                            if(first_chunk_size!=0){
                                allocate(y_integral_type[i]);
                                lookup(y_integral_type[i], "chunk_16_bits/full");
                                constrain(y_integral_type[i] - integral_type(y[i][num_rc_chunks - 1]) *
                                        (integral_type(1) << (bit_size_rc - first_chunk_size)));
                            }
                            if (make_links){
                                copy_constrain(x[i], input_state[i]);
                            }
                        }

                    }
                };

            }  // namespace components
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil

#endif  // CRYPTO3_BBF_COMPONENTS_RANGE_CHECK_MULTI_HPP
