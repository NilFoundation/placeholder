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

// #include <nil/blueprint/zkevm_bbf/input_generators/opcode_tester.hpp>
// #include <nil/blueprint/zkevm_bbf/input_generators/opcode_tester_input_generator.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/blueprint/bbf/circuit_builder.hpp>

#include "../test_plonk_component.hpp"

#include <boost/algorithm/string.hpp>

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
    std::size_t max_call_commits = 500;
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
    const nil::blueprint::circuit<zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
    const crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType> &assignment,
    const zk::snark::plonk_table_description<BlueprintFieldType> &desc
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

class CircuitTestFixture {
  public:
    explicit CircuitTestFixture() {
        check_satisfiability = true;
        generate_proof = false;
        print_to_file = false;

        std::size_t argc = boost::unit_test::framework::master_test_suite().argc;
        auto &argv = boost::unit_test::framework::master_test_suite().argv;
        for( std::size_t i = 0; i < argc; i++ ){
            std::string arg(argv[i]);
            if(arg == "--print" ) {
                print_to_file = true;
            }
            if(arg == "--no-sat-check" ) {
                check_satisfiability = false;
            }
            if(arg == "--proof" ) {
                generate_proof = true;
            }
            constexpr std::string_view prefix = "--run-for-circuits=";
            if (arg.starts_with(prefix)) {
                std::vector<std::string> circuits;
                std::string arg_value = arg.substr(prefix.size());
                boost::algorithm::split(circuits, arg_value, boost::is_any_of(","));
                for (const auto &circuit : circuits) {
                    std::cout << "Running circuit '" << circuit << "'" << std::endl;
                    circuits_to_run.insert(circuit);
                }
            }
        }
        std::string suite(boost::unit_test::framework::get<boost::unit_test::test_suite>(boost::unit_test::framework::current_test_case().p_parent_id).p_name);
        std::string test(boost::unit_test::framework::current_test_case().p_name);
        output_file = print_to_file ? std::string("./") + suite + "_" + test: "";
    }

    ~CircuitTestFixture() {}

    template <
        typename field_type,
        template<typename, nil::blueprint::bbf::GenerationStage> typename BBFType,
        typename... ComponentStaticInfoArgs
    >
    bool test_bbf_component(
        std::string circuit_name,
        std::vector<typename field_type::value_type> public_input,
        typename BBFType<field_type, GenerationStage::ASSIGNMENT>::input_type assignment_input,
        ComponentStaticInfoArgs... component_static_info_args
    ) {
        // Max_copy, Max_rw, Max_keccak, Max_bytecode
        circuit_builder<field_type, BBFType, ComponentStaticInfoArgs...> builder(component_static_info_args...);
        auto &bp = builder.get_circuit();
        auto [assignment, component, desc] = builder.assign(assignment_input);
        if (print_to_file) {
            print_zk_circuit_and_table_to_file(output_file + "_" + circuit_name, bp, desc, assignment);
        }
        bool result = true;
        if (check_satisfiability) {
            result = result & builder.is_satisfied(assignment, satisfiability_check_options{
                .verbose = true
            });
        }
        // It's debug mode. Prover from non-satisfied circuit will throw asserts
        if (result && generate_proof) {
            result = result & check_proof(bp, assignment, desc);
            std::cout << std::endl;
        }
        return result;
    }

    // all circuits are run by default
    inline bool should_run_circuit(const std::string &circuit_name){
        return circuits_to_run.empty() || circuits_to_run.find(circuit_name) != circuits_to_run.end();
    }


    bool check_satisfiability;
    bool generate_proof;
    bool print_to_file;
    std::string output_file;
    std::unordered_set<std::string> circuits_to_run;
};
