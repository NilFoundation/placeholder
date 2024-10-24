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
#pragma once

#include <functional>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
//#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/bbf/generic.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf{
            template<typename FieldType, GenerationStage stage>
            class zkevm : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;
            public:
                using typename generic_component<FieldType,stage>::TYPE;
                using private_input_type = typename std::conditional<stage == GenerationStage::ASSIGNMENT, std::size_t, std::nullptr_t>::type;
                struct input_type{
                    private_input_type b;
                };
            public:
                static nil::crypto3::zk::snark::plonk_table_description<FieldType> get_table_description(
                    std::size_t _max_zkevm_rows,
                    std::size_t _max_bytecode_size,
                    std::size_t _max_rw_size
                ){
                    nil::crypto3::zk::snark::plonk_table_description<FieldType> desc(15,1, 6,8);
                    desc.usable_rows_amount = std::max(std::max(_max_zkevm_rows, _max_bytecode_size), _max_rw_size);
                    return desc;
                }

                zkevm(
                    context_type &context_object,
                    const input_type &input,
                    std::size_t _max_zkevm_rows,
                    std::size_t _max_bytecode_size,
                    std::size_t _max_rw_size
                ) :generic_component<FieldType,stage>(context_object) {
                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        std::cout << "ZKEVM assign " << input.b << std::endl;
                    } else
                        std::cout << "ZKEVM circuit" << std::endl;
                }
            };
        }
    }
}