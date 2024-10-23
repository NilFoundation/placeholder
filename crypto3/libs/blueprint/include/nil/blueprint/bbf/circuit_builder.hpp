//---------------------------------------------------------------------------//
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
// @file Declaration of interfaces for BBF-components' circuit builder class
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_PLONK_BBF_CIRCUIT_BUILDER_HPP
#define CRYPTO3_BLUEPRINT_PLONK_BBF_CIRCUIT_BUILDER_HPP

#include <functional>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/bbf/generic.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_table_definition.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {

            template<typename CircuitFieldType, template<typename FieldType, GenerationStage stage> class Component>
            class circuit_builder {
                public:
                circuit_builder(std::size_t witnesses, std::size_t public_inputs, std::size_t user_constants, std::size_t rows) {
                    using generator = Component<CircuitFieldType,GenerationStage::CONSTRAINTS>;
                    typename generator::table_params min_params = generator::get_minimal_requirements();
                    if (witnesses < min_params.witnesses) {
                        std::stringstream error;
                        error << "Number of witnesses = " << witnesses
                            << " is below the minimal number of witnesses (" << min_params.witnesses << ") for the component.";
                        throw std::out_of_range(error.str());
                    }
                    if (public_inputs < min_params.public_inputs) {
                        std::stringstream error;
                        error << "Number of public inputs = " << public_inputs
                            << " is below the minimal number of public inputs (" << min_params.public_inputs << ") for the component.";
                        throw std::out_of_range(error.str());
                    }
                    if (user_constants < min_params.constants) {
                        std::stringstream error;
                        error << "Number of constants = " << user_constants
                            << " is below the minimal number of constants (" << min_params.constants << ") for the component.";
                        throw std::out_of_range(error.str());
                    }
                    if (rows < min_params.rows) {
                        std::stringstream error;
                        error << "Number of rows = " << rows
                            << " is below the minimal number of rows (" << min_params.rows << ") for the component.";
                        throw std::out_of_range(error.str());
                    }
                    // TODO: initialize params according to arguments
                }

                // typical setup: 1 PI column, 0 constant columns, witnesses × rows
                circuit_builder(std::size_t witnesses, std::size_t rows) {
                    circuit_builder(witnesses,1,0,rows);
                }

                // query component for minimal requirements
                circuit_builder() {
                    using generator = Component<CircuitFieldType,GenerationStage::CONSTRAINTS>;
                    typename generator::table_params min_params = generator::get_minimal_requirements();
                    circuit_builder(min_params.witnesses,min_params.public_inputs,min_params.constants,min_params.rows);
                }

                void generate_constraints() {
                    using generator = Component<CircuitFieldType,GenerationStage::CONSTRAINTS>;

                }

                void generate_assignment() {
                    using generator = Component<CircuitFieldType,GenerationStage::ASSIGNMENT>;

                }
            };

        }  // namespace bbf
    }   // namespace blueprint
}    // namespace nil
#endif    // CRYPTO3_BLUEPRINT_PLONK_BBF_WRAPPER_HPP
