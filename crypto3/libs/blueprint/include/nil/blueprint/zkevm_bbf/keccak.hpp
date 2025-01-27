//---------------------------------------------------------------------------//
// Elena Tatuzova
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

#include <nil/blueprint/zkevm_bbf/subcomponents/keccak_table.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            template<typename FieldType, GenerationStage stage>
            class keccak : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;

            public:
                using typename generic_component<FieldType, stage>::table_params;
                using typename generic_component<FieldType,stage>::TYPE;

                using private_input_type = std::conditional_t<
                    stage == GenerationStage::ASSIGNMENT,
                    std::size_t, std::monostate
                >;

                struct input_type{
                    TYPE rlc_challenge;
                    private_input_type private_input;
                };
                using raw_input_type = input_type;

                static table_params get_minimal_requirements() {
                    return {
                        .witnesses = 20,
                        .public_inputs = 1,
                        .constants = 3,
                        .rows = 300
                    };
                }

                static std::tuple<input_type> form_input(context_type &context,
                                                         raw_input_type input) {
                    context.allocate(input.rlc_challenge, 0, 0, column_type::public_input);
                    return {input};
                }

                keccak(context_type &context_object, const input_type &input) :generic_component<FieldType,stage>(context_object) {
                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        std::cout << "Keccak assign = " << input.private_input << std::endl;
                    }
                }
            };
        }
    }
}
