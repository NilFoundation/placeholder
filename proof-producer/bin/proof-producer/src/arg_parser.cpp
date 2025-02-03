//---------------------------------------------------------------------------//
// Copyright (c) 2024 Iosif (x-mass) <x-mass@nil.foundation>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//---------------------------------------------------------------------------//

#include <arg_parser.hpp>

#include <nil/proof-generator/arithmetization_params.hpp>
#include <nil/proof-generator/output_artifacts/output_artifacts.hpp>

#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <type_traits>

#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>

namespace nil {
    namespace proof_producer {
        namespace po = boost::program_options;

        void check_exclusive_options(const po::variables_map& vm, const std::vector<std::string>& opts) {
            std::vector<std::string> found_opts;
            for (const auto& opt : opts) {
                if (vm.count(opt) && !vm[opt].defaulted()) {
                    found_opts.push_back(opt);
                }
            }
            if (found_opts.size() > 1) {
                throw std::logic_error("Conflicting options: " + boost::algorithm::join(found_opts, " and "));
            }
        }

        template<typename T>
        po::typed_value<T>* make_defaulted_option(T& variable) {
            return po::value(&variable)->default_value(variable);
        }

        void register_circuits_limits_cli_args(CircuitsLimits& circuits_limits, po::options_description& cli_options) {
                cli_options.add_options()
                ("max-copy", make_defaulted_option(circuits_limits.max_copy), "Maximum copy events")
                ("max-rw-size", make_defaulted_option(circuits_limits.max_rw_size), "Maximum rw operations")
                ("max-keccak-blocks", make_defaulted_option(circuits_limits.max_keccak_blocks), "Maximum keccak blocks")
                ("max-bytecode-size", make_defaulted_option(circuits_limits.max_bytecode_size), "Maximum size of bytecode")
                ("max-rows", make_defaulted_option(circuits_limits.max_rows), "Maximum rows of assignemnt table")
                ("max-mpt-size", make_defaulted_option(circuits_limits.max_mpt_size), "Maximum MPT operations")
                ("max-zkevm-rows", make_defaulted_option(circuits_limits.max_zkevm_rows), "Maximum zkevm states")
                ("max_exp_rows", make_defaulted_option(circuits_limits.max_exp_rows), "Maximum number of exponent operations")
                ("RLC-CHALLENGE", make_defaulted_option(circuits_limits.RLC_CHALLENGE), "RLC_CHALLENGE (7 by default)");
        }

        std::optional<ProverOptions> parse_args(int argc, char* argv[]) {
            po::options_description options("Nil; Proof Generator Options");
            // Declare a group of options that will be
            // allowed only on command line
            po::options_description generic("CLI options");
            // clang-format off
            generic.add_options()
                ("help,h", "Produce help message")
                ("version,v", "Print version string")
                ("config,c", po::value<std::string>(), "Config file path");
            // clang-format on

            ProverOptions prover_options;

            // Declare a group of options that will be
            // allowed both on command line and in
            // config file
            po::options_description config(
                "Configuration",
                /*line_length=*/120,
                /*min_description_length=*/60
            );
            // clang-format off
            auto options_appender = config.add_options()
                ("stage", make_defaulted_option(prover_options.stage),
                 "Stage of the prover to run, one of (all, preprocess, prove, verify, generate-aggregated-challenge, generate-combined-Q, aggregated-FRI, consistency-checks). Defaults to 'all'.")
                ("proof,p", make_defaulted_option(prover_options.proof_file_path), "Proof file")
                ("json,j", make_defaulted_option(prover_options.json_file_path), "JSON proof file")
                ("common-data", make_defaulted_option(prover_options.preprocessed_common_data_path), "Preprocessed common data file")
                ("preprocessed-data", make_defaulted_option(prover_options.preprocessed_public_data_path), "Preprocessed public data file")
                ("commitment-state-file", make_defaulted_option(prover_options.commitment_scheme_state_path), "Commitment state data file")
                ("updated-commitment-state-file", make_defaulted_option(prover_options.updated_commitment_scheme_state_path), "Updated commitment state data file")
                ("trace", po::value(&prover_options.trace_base_path), "Base path for EVM trace files")
                ("circuit", po::value(&prover_options.circuit_file_path), "Circuit input file")
                ("circuit-name", po::value(&prover_options.circuit_name), "Target circuit name")
                ("assignment-table,t", po::value(&prover_options.assignment_table_file_path), "Assignment table input file")
                ("assignment-description-file", po::value(&prover_options.assignment_description_file_path), "Assignment description file")
                ("log-level,l", make_defaulted_option(prover_options.log_level), "Log level (trace, debug, info, warning, error, fatal)") // TODO is does not work
                ("elliptic-curve-type,e", make_defaulted_option(prover_options.elliptic_curve_type), "Elliptic curve type (pallas)")
                ("hash-type", make_defaulted_option(prover_options.hash_type), "Hash type (keccak, poseidon, sha256)")
                ("lambda-param", make_defaulted_option(prover_options.lambda), "Lambda param (9)")
                ("grind-param", make_defaulted_option(prover_options.grind), "Grind param (0)")
                ("expand-factor,x", make_defaulted_option(prover_options.expand_factor), "Expand factor")
                ("max-quotient-chunks,q", make_defaulted_option(prover_options.max_quotient_chunks), "Maximum quotient polynomial parts amount")
                ("evm-verifier", make_defaulted_option(prover_options.evm_verifier_path), "Output folder for EVM verifier")
                ("input-challenge-files,u", po::value<std::vector<boost::filesystem::path>>(&prover_options.input_challenge_files)->multitoken(),
                 "Input challenge files. Used with 'generate-aggregated-challenge' stage.")
                ("challenge-file", po::value<boost::filesystem::path>(&prover_options.challenge_file_path),
                 "Input challenge files. Used with 'generate-aggregated-challenge' stage.")
                ("theta-power-file", po::value<boost::filesystem::path>(&prover_options.theta_power_file_path),
                 "File to output theta power. Used by main prover to arrange starting powers of Q")
                ("aggregated-challenge-file", po::value<boost::filesystem::path>(&prover_options.aggregated_challenge_file),
                 "Aggregated challenge file. Used with 'generate-aggregated-challenge' stage")
                ("consistency-checks-challenges-file", po::value<boost::filesystem::path>(&prover_options.consistency_checks_challenges_file),
                 "A file containing 'lambda' challenges generated by stage 'aggregated-FRI' and used in the stage 'FRI_consistency_checks'.")
                ("combined-Q-polynomial-file", po::value<boost::filesystem::path>(&prover_options.combined_Q_polynomial_file),
                 "File containing the polynomial combined-Q, generated on a single prover.")
                ("combined-Q-starting-power", po::value<std::size_t>(&prover_options.combined_Q_starting_power),
                 "The starting power for combined-Q polynomial for the current prover.")
                ("partial-proof", po::value<std::vector<boost::filesystem::path>>(&prover_options.partial_proof_files)->multitoken(),
                 "Partial proofs. Used with 'merge-proofs' stage.")
                ("aggregated-proof", po::value<std::vector<boost::filesystem::path>>(&prover_options.aggregated_proof_files)->multitoken(),
                 "Parts of aggregated proof. Used with 'merge-proofs' stage.")
                ("initial-proof", po::value<std::vector<boost::filesystem::path>>(&prover_options.initial_proof_files)->multitoken(),
                 "Inital proofs, produced by consistency-check stage. Used with 'merge-proofs' stage.")
                ("aggregated-FRI-proof", po::value<boost::filesystem::path>(&prover_options.aggregated_FRI_proof_file),
                 "Aggregated FRI proof part of the final proof. Used with 'merge-proofs' stage.")
                ("input-combined-Q-polynomial-files", po::value<std::vector<boost::filesystem::path>>(&prover_options.input_combined_Q_polynomial_files),
                 "Files containing polynomials combined-Q, 1 per prover instance.")
                ("proof-of-work-file", make_defaulted_option(prover_options.proof_of_work_output_file), "File with proof of work.");

            register_output_artifacts_cli_args(prover_options.output_artifacts, config);
            register_circuits_limits_cli_args(prover_options.circuits_limits, config);

            // clang-format on
            po::options_description cmdline_options("nil; Proof Producer");
            cmdline_options.add(generic).add(config);

            po::variables_map vm;
            try {
                po::store(parse_command_line(argc, argv, cmdline_options), vm);
            } catch (const po::validation_error& e) {
                std::cerr << e.what() << std::endl;
                std::cout << cmdline_options << std::endl;
                throw e;
            }

            if (vm.count("help")) {
                std::cout << cmdline_options << std::endl;
                return std::nullopt;
            }

            if (vm.count("version")) {
#ifdef PROOF_GENERATOR_VERSION
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
                std::cout << TOSTRING(PROOF_GENERATOR_VERSION) << std::endl;
#undef STRINGIFY
#undef TOSTRING
#else
                std::cout << "undefined" << std::endl;
#endif
                return std::nullopt;
            }

            // Parse configuration file. Args from CLI will not be overwritten
            if (vm.count("config")) {
                std::ifstream ifs(vm["config"].as<std::string>().c_str());
                if (ifs) {
                    store(parse_config_file(ifs, config), vm);
                } else {
                    throw std::runtime_error("Cannot open config file: " + vm["config"].as<std::string>());
                }
            }

            // Calling notify(vm) after handling no-op cases prevent parser from alarming
            // about absence of required args
            try {
                notify(vm);
            } catch (const po::required_option& e) {
                std::cerr << e.what() << std::endl;
                std::cout << cmdline_options << std::endl;
                throw e;
            }

            try {
                check_exclusive_options(vm, {"verification-only", "skip-verification"});
            } catch (const std::logic_error& e) {
                std::cerr << e.what() << std::endl;
                std::cout << cmdline_options << std::endl;
                throw e;
            }

            return prover_options;
        }

// Here we have generators of read and write operators for options holding
// types. Don't forget to adjust help message when add new type - name mapping.
// Examples below.
#define GENERATE_WRITE_OPERATOR(TYPE_TO_STRING_LINES, VARIANT_TYPE)             \
    std::ostream& operator<<(std::ostream& strm, const VARIANT_TYPE& variant) { \
        strm << std::visit(                                                     \
            [&strm](auto&& arg) -> std::string {                                \
                using SelectedType = std::decay_t<decltype(arg)>;               \
                TYPE_TO_STRING_LINES                                            \
                strm.setstate(std::ios_base::failbit);                          \
                return "";                                                      \
            },                                                                  \
            variant                                                             \
        );                                                                      \
        return strm;                                                            \
    }
#define TYPE_TO_STRING(TYPE, NAME)                                   \
    if constexpr (std::is_same_v<SelectedType, type_identity<TYPE>>) \
        return NAME;

#define GENERATE_READ_OPERATOR(STRING_TO_TYPE_LINES, VARIANT_TYPE)        \
    std::istream& operator>>(std::istream& strm, VARIANT_TYPE& variant) { \
        std::string str;                                                  \
        strm >> str;                                                      \
        auto l = [&str, &strm]() -> VARIANT_TYPE {                        \
            STRING_TO_TYPE_LINES                                          \
            strm.setstate(std::ios_base::failbit);                        \
            return VARIANT_TYPE();                                        \
        };                                                                \
        variant = l();                                                    \
        return strm;                                                      \
    }
#define STRING_TO_TYPE(TYPE, NAME) \
    if (NAME == str)               \
        return type_identity<TYPE>{};

#define CURVE_TYPES X(nil::crypto3::algebra::curves::pallas, "pallas")
#define X(type, name) TYPE_TO_STRING(type, name)
        GENERATE_WRITE_OPERATOR(CURVE_TYPES, CurvesVariant)
#undef X
#define X(type, name) STRING_TO_TYPE(type, name)
        GENERATE_READ_OPERATOR(CURVE_TYPES, CurvesVariant)
#undef X

#define HASH_TYPES                                                                       \
    X(nil::crypto3::hashes::keccak_1600<256>, "keccak")                                  \
    X(nil::crypto3::hashes::poseidon<nil::crypto3::hashes::detail::pasta_poseidon_policy< \
          typename nil::crypto3::algebra::curves::pallas::base_field_type>>,             \
      "poseidon")                                                                        \
    X(nil::crypto3::hashes::sha2<256>, "sha256")
#define X(type, name) TYPE_TO_STRING(type, name)
        GENERATE_WRITE_OPERATOR(HASH_TYPES, HashesVariant)
#undef X
#define X(type, name) STRING_TO_TYPE(type, name)
        GENERATE_READ_OPERATOR(HASH_TYPES, HashesVariant)
#undef X

    } // namespace proof_producer
} // namespace nil
