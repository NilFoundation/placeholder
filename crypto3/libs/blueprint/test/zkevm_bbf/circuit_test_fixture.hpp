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

#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/bench/scoped_profiler.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/blueprint/bbf/circuit_builder.hpp>

#include <nil/crypto3/math/polynomial/polymorphic_polynomial_dfs.hpp>

#include <nil/blueprint/utils/constraint_system_stat.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks/sync_frontend.hpp>
#include <boost/log/sinks/text_ostream_backend.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/utility/formatting_ostream.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/attributes/value_extraction.hpp>
#include <boost/log/utility/setup/console.hpp>
#include "../test_plonk_component.hpp"

using namespace nil::crypto3;
using namespace nil::blueprint;
using namespace nil::blueprint::bbf;

// Log-related classes
void file_formatter(boost::log::record_view const& rec, boost::log::formatting_ostream& strm){
    // Finally, put the record message to the stream
    if( rec[boost::log::trivial::severity] > boost::log::trivial::info) {
        strm  << "[" << rec[boost::log::trivial::severity] << "] " << rec[boost::log::expressions::smessage];
    } else {
        strm  << rec[boost::log::expressions::smessage];
    }
}


void colored_formatter(boost::log::record_view const& rec, boost::log::formatting_ostream& strm){
    // Colored output looks nice in terminal, but not in files.
    // Use --color-log to enable colored output in terminal.
    if( rec[boost::log::trivial::severity] == boost::log::trivial::fatal) {
        strm  << "[\x1B[91m" << rec[boost::log::trivial::severity] << "\x1B[0m] " << rec[boost::log::expressions::smessage];
    } else if( rec[boost::log::trivial::severity] == boost::log::trivial::error) {
        strm  << "[\x1B[38;2;255;165;0m" << rec[boost::log::trivial::severity] << "\x1B[0m] " << rec[boost::log::expressions::smessage];
    } else if( rec[boost::log::trivial::severity] == boost::log::trivial::warning) {
        strm  << "[\x1B[33m" << rec[boost::log::trivial::severity] << "\x1B[0m] " << rec[boost::log::expressions::smessage];
    } else if( rec[boost::log::trivial::severity] == boost::log::trivial::info) {
        strm  << "[\x1B[32m" << rec[boost::log::trivial::severity] << "\x1B[0m] " << rec[boost::log::expressions::smessage];
    } else {
        strm  << rec[boost::log::expressions::smessage];
    }
}


class zkEVMGlobalFixture {
public:
    zkEVMGlobalFixture() {
        // Initialize the logging system
        boost::log::trivial::severity_level log_level = boost::log::trivial::info;
        bool is_color = false;

        std::size_t argc = boost::unit_test::framework::master_test_suite().argc;
        auto &argv = boost::unit_test::framework::master_test_suite().argv;
        for( std::size_t i = 0; i < argc; i++ ){
            std::string arg(argv[i]);
            if( arg == "--log-level=trace"){
                log_level = boost::log::trivial::trace;
            }
            if( arg == "--log-level=debug"){
                log_level = boost::log::trivial::debug;
            }
            if( arg == "--log-level=info"){
                log_level = boost::log::trivial::info;
            }
            if( arg == "--log-level=warning"){
                log_level = boost::log::trivial::warning;
            }
            if( arg == "--log-level=error"){
                log_level = boost::log::trivial::error;
            }
            if( arg == "--no-log" ){
                log_level = boost::log::trivial::fatal;
            }
            if( arg == "--color-log" ){
                is_color = true;
            }
        }

        typedef boost::log::sinks::synchronous_sink< boost::log::sinks::text_ostream_backend > text_sink;
        boost::shared_ptr< text_sink > sink = boost::make_shared< text_sink >();

        sink->locked_backend()->add_stream(boost::shared_ptr< std::ostream >(&std::cout, boost::null_deleter()));
        if (is_color) {
            sink->set_formatter(&colored_formatter);
        } else {
            sink->set_formatter(&file_formatter);
        }
        sink->locked_backend()->auto_flush(true);
        boost::log::core::get()->add_sink(sink);

        sink->set_filter(
            boost::log::trivial::severity >= log_level
        );
    }
};

// Circuit-related fixture
struct l1_size_restrictions{
    std::size_t max_exponentiations;
    std::size_t max_keccak_blocks;

    std::size_t max_bytecode;
    std::size_t instances_bytecode = 1;

    std::size_t max_rw;
    std::size_t instances_rw_8 = 3;
    std::size_t instances_rw_256 = 2;

    std::size_t max_copy_events = 50;
    std::size_t max_copy;
    std::size_t max_copy_small_field_rows = 0;
    std::size_t instances_copy = 2;

    std::size_t max_zkevm_rows;
    std::size_t max_zkevm_small_field_rows = 0;
    std::size_t max_exp_rows;
    std::size_t max_state = 500;
    std::size_t max_bytecodes_amount = 50;
    std::size_t max_mpt;
};

std::vector<std::uint8_t> hex_string_to_bytes(std::string const &hex_string) {
    std::vector<std::uint8_t> bytes;
    for (std::size_t i = 2; i < hex_string.size(); i += 2) {
        std::string byte_string = hex_string.substr(i, 2);
        bytes.push_back(std::stoi(byte_string, nullptr, 16));
    }
    return bytes;
}

template<typename FieldType>
bool check_proof(
    const nil::blueprint::circuit<
        zk::snark::plonk_constraint_system<typename FieldType::small_subfield>> &bp,
    const crypto3::zk::snark::plonk_assignment_table<typename FieldType::small_subfield>
        &assignment,
    const zk::snark::plonk_table_description<typename FieldType::small_subfield> &desc) {
    using SmallFieldType = typename FieldType::small_subfield;

    std::size_t max_step = std::getenv("NIL_CO3_TEST_MAX_STEP")
                               ? std::stoi(std::getenv("NIL_CO3_TEST_MAX_STEP"))
                               : 1;
    std::size_t lambda = std::getenv("NIL_CO3_TEST_LAMBDA")
                             ? std::stoi(std::getenv("NIL_CO3_TEST_LAMBDA"))
                             : 9;
    std::size_t log_blowup = std::getenv("NIL_CO3_TEST_LOG_BLOWUP")
                                 ? std::stoi(std::getenv("NIL_CO3_TEST_LOG_BLOWUP"))
                                 : 2;
    std::size_t max_quotient_poly_chunks =
        std::getenv("NIL_CO3_TEST_LOG_MAX_QUOTIENT_POLY_CHUNKS")
            ? std::stoi(std::getenv("NIL_CO3_TEST_LOG_MAX_QUOTIENT_POLY_CHUNKS"))
            : 10;

    std::size_t grinding_bits = std::getenv("NIL_CO3_TEST_GRINDING_BITS")
                                    ? std::stoi(std::getenv("NIL_CO3_TEST_GRINDING_BITS"))
                                    : 0;

    typedef nil::crypto3::zk::snark::placeholder_circuit_params<SmallFieldType>
        circuit_params;
    using transcript_hash_type = nil::crypto3::hashes::keccak_1600<256>;
    using merkle_hash_type = nil::crypto3::hashes::keccak_1600<256>;
    using transcript_type = typename nil::crypto3::zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;
    using lpc_params_type = nil::crypto3::zk::commitments::list_polynomial_commitment_params<
        merkle_hash_type,
        transcript_hash_type,
        2 //m
    >;

    using lpc_type =
        nil::crypto3::zk::commitments::list_polynomial_commitment<FieldType,
                                                                  lpc_params_type>;
    using lpc_scheme_type = typename nil::crypto3::zk::commitments::lpc_commitment_scheme<
        lpc_type, std::conditional_t<std::is_same_v<FieldType, SmallFieldType>,
                                     polynomial_dfs<typename FieldType::value_type>,
                                     polymorphic_polynomial_dfs<FieldType>>>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    typename lpc_type::fri_type::params_type fri_params(
        max_step, std::ceil(log2(assignment.rows_amount())), lambda, log_blowup,
        grinding_bits != 0, grinding_bits);
    lpc_scheme_type lpc_scheme(fri_params);

    SCOPED_LOG("Public preprocessor");
    typename nil::crypto3::zk::snark::placeholder_public_preprocessor<
        SmallFieldType, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_public_data =
            nil::crypto3::zk::snark::placeholder_public_preprocessor<
                SmallFieldType,
                lpc_placeholder_params_type>::process(bp, assignment.public_table(), desc,
                                                      lpc_scheme,
                                                      max_quotient_poly_chunks);

    SCOPED_LOG("Private preprocessor");
    typename nil::crypto3::zk::snark::placeholder_private_preprocessor<
        SmallFieldType, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_private_data =
            nil::crypto3::zk::snark::placeholder_private_preprocessor<
                SmallFieldType,
                lpc_placeholder_params_type>::process(bp, assignment.private_table(),
                                                      desc);

    SCOPED_LOG("Prover");
    auto lpc_proof = nil::crypto3::zk::snark::
        placeholder_prover<FieldType, lpc_placeholder_params_type>::process(
            lpc_preprocessed_public_data, std::move(lpc_preprocessed_private_data), desc,
            bp, lpc_scheme);

    // We must not use the same instance of lpc_scheme.
    lpc_scheme_type verifier_lpc_scheme(fri_params);

    SCOPED_LOG("Verifier");
    bool verifier_res = nil::crypto3::zk::snark::
        placeholder_verifier<FieldType, lpc_placeholder_params_type>::process(
            *lpc_preprocessed_public_data.common_data, lpc_proof, desc, bp,
            verifier_lpc_scheme);
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

    template<typename FieldType,
             template<typename, nil::blueprint::bbf::GenerationStage> typename BBFType,
             typename... ComponentStaticInfoArgs>
    bool test_bbf_component(
        std::string circuit_name,
        std::vector<typename FieldType::small_subfield::value_type> public_input,
        typename BBFType<typename FieldType::small_subfield,
                         GenerationStage::ASSIGNMENT>::input_type assignment_input,
        ComponentStaticInfoArgs... component_static_info_args) {
        using SmallFieldType = typename FieldType::small_subfield;
        circuit_builder<SmallFieldType, BBFType, ComponentStaticInfoArgs...> builder(
            component_static_info_args...);

        auto &bp = builder.get_circuit();
        BOOST_LOG_TRIVIAL(info) << constrain_system_stat<SmallFieldType>(bp);

        auto [assignment, component, desc] = builder.assign(assignment_input);
        if (print_to_file) {
            print_zk_circuit_and_table_to_file(output_file + "_" + circuit_name, bp, desc, assignment);
        }
        bool result = true;
        if (check_satisfiability) {
            result =
                result && builder.is_satisfied(
                              assignment, satisfiability_check_options{.verbose = true});
        }
        // It's debug mode. Prover from non-satisfied circuit will throw asserts
        if (result && generate_proof) {
            result = result && check_proof<FieldType>(bp, assignment, desc);
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