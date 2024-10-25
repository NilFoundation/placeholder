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

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include "../test_plonk_component.hpp"

using namespace nil::crypto3;
using namespace nil::blueprint;

std::vector<std::uint8_t> hex_string_to_bytes(std::string const &hex_string) {
    std::vector<std::uint8_t> bytes;
    for (std::size_t i = 2; i < hex_string.size(); i += 2) {
        std::string byte_string = hex_string.substr(i, 2);
        bytes.push_back(std::stoi(byte_string, nullptr, 16));
    }
    return bytes;
}

template <
    typename BlueprintFieldType,
    template<typename, nil::blueprint::bbf::GenerationStage> typename BBFType,
    typename... ComponentStaticInfoArgs
>
void test_l1_wrapper(
    std::vector<typename BlueprintFieldType::value_type> public_input,
    typename BBFType<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type assignment_input,
    typename BBFType<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::CONSTRAINTS>::input_type constraint_input,
    ComponentStaticInfoArgs... component_static_info_args
) {
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = assignment<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = components::plonk_l1_wrapper<BlueprintFieldType, BBFType, ComponentStaticInfoArgs...>;
    auto desc = component_type::get_table_description(component_static_info_args...);
    AssignmentType assignment(desc);
    nil::blueprint::circuit<ArithmetizationType> bp;

    std::size_t start_row = 1;

    std::vector<std::size_t> witnesses;
    for( std::size_t i = 0; i < desc.witness_columns; i++) witnesses.push_back(i);
    std::vector<std::size_t> public_inputs = {0};
    for( std::size_t i = 0; i < desc.public_input_columns; i++) public_inputs.push_back(i);
    std::vector<std::size_t> constants;
    for( std::size_t i = 0; i < desc.constant_columns; i++) constants.push_back(i);

    component_type component_instance(witnesses, public_inputs, constants);

    nil::blueprint::components::generate_circuit<BlueprintFieldType, BBFType, ComponentStaticInfoArgs...>(
        component_instance, bp, assignment, constraint_input, start_row, component_static_info_args...
    );
    zk::snark::pack_lookup_tables_horizontal(
        bp.get_reserved_indices(),
        bp.get_reserved_tables(),
        bp.get_reserved_dynamic_tables(),
        bp, assignment,
        assignment.rows_amount(),
        100000
    );

    nil::blueprint::components::generate_assignments<BlueprintFieldType, BBFType, ComponentStaticInfoArgs...>(
        component_instance, assignment, assignment_input, start_row, component_static_info_args...
    );

    BOOST_ASSERT(is_satisfied(bp, assignment) == true);
    std::cout << std::endl;
}
