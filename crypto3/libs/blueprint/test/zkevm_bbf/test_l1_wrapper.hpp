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

#include <nil/blueprint/zkevm_bbf/input_generators/opcode_tester.hpp>
#include <nil/blueprint/zkevm_bbf/input_generators/opcode_tester_input_generator.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/blueprint/bbf/l1_wrapper.hpp>

#include "../test_plonk_component.hpp"

using namespace nil::crypto3;
using namespace nil::blueprint;
using namespace nil::blueprint::bbf;

struct l1_size_restrictions{
    std::size_t max_exponentiations;
    std::size_t max_keccak_blocks;
    std::size_t max_bytecode;
    std::size_t max_mpt;
    std::size_t max_rw;
    std::size_t max_copy;
    std::size_t max_zkevm_rows;
    std::size_t max_exp_rows;
};

std::vector<std::uint8_t> hex_string_to_bytes(std::string const &hex_string) {
    std::vector<std::uint8_t> bytes;
    for (std::size_t i = 2; i < hex_string.size(); i += 2) {
        std::string byte_string = hex_string.substr(i, 2);
        bytes.push_back(std::stoi(byte_string, nullptr, 16));
    }
    return bytes;
}

boost::property_tree::ptree load_hardhat_input(std::string path){
    std::ifstream ss;
    std::cout << "Open file " << std::string(TEST_DATA_DIR) + path << std::endl;
    ss.open(std::string(TEST_DATA_DIR) + path);
    boost::property_tree::ptree pt;
    boost::property_tree::read_json(ss, pt);
    ss.close();

    return pt;
}

template <typename BlueprintFieldType>
bool check_proof(
    nil::blueprint::circuit<zk::snark::plonk_constraint_system<BlueprintFieldType>> bp,
    assignment<zk::snark::plonk_constraint_system<BlueprintFieldType>> assignment,
    zk::snark::plonk_table_description<BlueprintFieldType> desc
) {
    std::size_t Lambda = 9;

    typedef nil::crypto3::zk::snark::placeholder_circuit_params<BlueprintFieldType> circuit_params;
    using transcript_hash_type = nil::crypto3::hashes::keccak_1600<256>;
    using merkle_hash_type = nil::crypto3::hashes::keccak_1600<256>;
    using transcript_type = typename nil::crypto3::zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;
    using lpc_params_type = nil::crypto3::zk::commitments::list_polynomial_commitment_params<
        merkle_hash_type,
        transcript_hash_type,
        2 //m
    >;

    using lpc_type = nil::crypto3::zk::commitments::list_polynomial_commitment<BlueprintFieldType, lpc_params_type>;
    using lpc_scheme_type = typename nil::crypto3::zk::commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    typename lpc_type::fri_type::params_type fri_params(1, std::ceil(log2(assignment.rows_amount())), Lambda, 2);
    lpc_scheme_type lpc_scheme(fri_params);

    std::cout << "Public preprocessor" << std::endl;
    typename nil::crypto3::zk::snark::placeholder_public_preprocessor<BlueprintFieldType, lpc_placeholder_params_type>::preprocessed_data_type
            lpc_preprocessed_public_data = nil::crypto3::zk::snark::placeholder_public_preprocessor<BlueprintFieldType, lpc_placeholder_params_type>::process(
            bp, assignment.public_table(), desc, lpc_scheme, 10);

    std::cout << "Private preprocessor" << std::endl;
    typename nil::crypto3::zk::snark::placeholder_private_preprocessor<BlueprintFieldType, lpc_placeholder_params_type>::preprocessed_data_type
            lpc_preprocessed_private_data = nil::crypto3::zk::snark::placeholder_private_preprocessor<BlueprintFieldType, lpc_placeholder_params_type>::process(
            bp, assignment.private_table(), desc);

    std::cout << "Prover" << std::endl;
    auto lpc_proof = nil::crypto3::zk::snark::placeholder_prover<BlueprintFieldType, lpc_placeholder_params_type>::process(
            lpc_preprocessed_public_data, std::move(lpc_preprocessed_private_data), desc, bp,
            lpc_scheme);

    // We must not use the same instance of lpc_scheme.
    lpc_scheme_type verifier_lpc_scheme(fri_params);

    std::cout << "Verifier" << std::endl;
    bool verifier_res = nil::crypto3::zk::snark::placeholder_verifier<BlueprintFieldType, lpc_placeholder_params_type>::process(
            *lpc_preprocessed_public_data.common_data, lpc_proof, desc, bp, verifier_lpc_scheme);
    return verifier_res;
}

template <
    typename BlueprintFieldType,
    template<typename, nil::blueprint::bbf::GenerationStage> typename BBFType,
    typename... ComponentStaticInfoArgs
>
std::tuple<
    nil::blueprint::circuit<zk::snark::plonk_constraint_system<BlueprintFieldType>>,
    assignment<zk::snark::plonk_constraint_system<BlueprintFieldType>>,
    zk::snark::plonk_table_description<BlueprintFieldType>
>
prepare_table_and_circuit(
    std::vector<typename BlueprintFieldType::value_type> public_input,
    typename BBFType<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type assignment_input,
    typename BBFType<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::CONSTRAINTS>::input_type constraint_input,
    ComponentStaticInfoArgs... component_static_info_args
){
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = assignment<ArithmetizationType>;
    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
    using component_type = components::plonk_l1_wrapper<BlueprintFieldType, BBFType, ComponentStaticInfoArgs...>;

    auto desc = component_type::get_table_description(component_static_info_args...);
    AssignmentType assignment(desc);
    nil::blueprint::circuit<ArithmetizationType> bp;

    std::size_t start_row = 0;

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

    desc.usable_rows_amount = assignment.rows_amount();
    nil::crypto3::zk::snark::basic_padding(assignment);
    desc.rows_amount = assignment.rows_amount();
    return {bp, assignment, desc};
}

template <
    typename BlueprintFieldType,
    template<typename, nil::blueprint::bbf::GenerationStage> typename BBFType,
    typename... ComponentStaticInfoArgs
>
bool test_l1_wrapper(
    std::vector<typename BlueprintFieldType::value_type> public_input,
    typename BBFType<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type assignment_input,
    typename BBFType<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::CONSTRAINTS>::input_type constraint_input,
    ComponentStaticInfoArgs... component_static_info_args
) {
    auto [bp, assignment, desc] = prepare_table_and_circuit<BlueprintFieldType, BBFType, ComponentStaticInfoArgs...>(
        public_input, assignment_input, constraint_input, component_static_info_args...
    );
    return is_satisfied(bp, assignment) == true;
}

template <
    typename BlueprintFieldType,
    template<typename, nil::blueprint::bbf::GenerationStage> typename BBFType,
    typename... ComponentStaticInfoArgs
>
bool test_l1_wrapper_with_proof_verification(
    std::vector<typename BlueprintFieldType::value_type> public_input,
    typename BBFType<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type assignment_input,
    typename BBFType<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::CONSTRAINTS>::input_type constraint_input,
    ComponentStaticInfoArgs... component_static_info_args
) {
    auto [bp, assignment, desc] = prepare_table_and_circuit<BlueprintFieldType, BBFType, ComponentStaticInfoArgs...>(
        public_input, assignment_input, constraint_input, component_static_info_args...
    );
    bool sat = is_satisfied(bp, assignment);
    std::cout << "Desc.rows_amount = " << desc.rows_amount << std::endl;
    std::cout << "Desc.usable_rows_amount = " << desc.usable_rows_amount << std::endl;

    if (sat )
        std::cout << "Circuit is satisfied" << std::endl;
    else
        std::cout << "Circuit is not satisfied" << std::endl;

    return check_proof<BlueprintFieldType>(bp, assignment, desc);
}

class BBFTestFixture
{
public:
    explicit BBFTestFixture(){
        check_satisfiability = true;
        generate_proof = false;
        print_to_file = false;

        std::size_t argc = boost::unit_test::framework::master_test_suite().argc;
        auto &argv = boost::unit_test::framework::master_test_suite().argv;
        for( std::size_t i = 0; i < argc; i++ ){
            if( std::string(argv[i]) == "--print" ) print_to_file = true;
            if( std::string(argv[i]) == "--no-sat-check" ) check_satisfiability = false;
            if( std::string(argv[i]) == "--proof" ) generate_proof = true;
        }
        std::string suite(boost::unit_test::framework::get<boost::unit_test::test_suite>(boost::unit_test::framework::current_test_case().p_parent_id).p_name);
        std::string test(boost::unit_test::framework::current_test_case().p_name);
        output_file = print_to_file ? std::string("./") + suite + "_" + test: "";
    }

    ~BBFTestFixture(){}

    template <
        typename field_type,
        template<typename, nil::blueprint::bbf::GenerationStage> typename BBFType,
        typename... ComponentStaticInfoArgs
    >
    bool test_bbf_component(
        std::string circuit_name,
        std::vector<typename field_type::value_type> public_input,
        typename BBFType<field_type, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type assignment_input,
        typename BBFType<field_type, nil::blueprint::bbf::GenerationStage::CONSTRAINTS>::input_type constraint_input,
        ComponentStaticInfoArgs... component_static_info_args
    ){
        // Max_copy, Max_rw, Max_keccak, Max_bytecode
        auto [bp, assignment, desc] = prepare_table_and_circuit<field_type, BBFType, ComponentStaticInfoArgs...>(
            public_input, assignment_input, constraint_input,
            component_static_info_args...
        );
        if( print_to_file ){
            print_bp_circuit_and_table_to_file(output_file + "_" + circuit_name, bp, desc, assignment);
        }
        bool result = true;
        if( check_satisfiability ){
            result = result & is_satisfied(bp, assignment);
            std::cout << std::endl;
        }
        // It's debug mode. Prover from non-satisfied circuit will throw asserts
        if( result && generate_proof ){
            result = result & check_proof(bp, assignment, desc);
            std::cout << std::endl;
        }
        return result;
    }

    bool check_satisfiability;
    bool generate_proof;
    bool print_to_file;
    std::string output_file;
};

