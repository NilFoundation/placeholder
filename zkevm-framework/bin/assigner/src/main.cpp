#include <expected>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <chrono>

#ifndef BOOST_FILESYSTEM_NO_DEPRECATED
#define BOOST_FILESYSTEM_NO_DEPRECATED
#endif
#ifndef BOOST_SYSTEM_NO_DEPRECATED
#define BOOST_SYSTEM_NO_DEPRECATED
#endif

#include <boost/log/trivial.hpp>
#include <boost/program_options.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/ed25519.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/proof-generator/prover.hpp>
#include <unordered_map>

#include "checks.hpp"
#include "zkevm_framework/assigner_runner/runner.hpp"
#include "zkevm_framework/preset/preset.hpp"
#include "zkevm_framework/assigner_runner/write_assignments.hpp"
#include "zkevm_framework/assigner_runner/write_circuits.hpp"

template<typename Endianness, typename ArithmetizationType, typename BlueprintFieldType>
std::optional<std::string> write_circuit(nil::evm_assigner::zkevm_circuit idx,
                                         const std::unordered_map<nil::evm_assigner::zkevm_circuit, nil::blueprint::assignment<ArithmetizationType>>& assignments,
                                         const nil::blueprint::circuit<ArithmetizationType> circuit,
                                         const std::string& concrete_circuit_file_name) {
    const auto find_it = assignments.find(idx);
    if (find_it == assignments.end()) {
        return "Can't find assignment table";
    }
    std::vector<std::size_t> public_input_column_sizes;
    const auto public_input_size = find_it->second.public_inputs_amount();
    for (std::uint32_t i = 0; i < public_input_size; i++) {
        public_input_column_sizes.push_back(find_it->second.public_input_column_size(i));
    }
    return write_binary_circuit<Endianness, ArithmetizationType, BlueprintFieldType>(circuit, public_input_column_sizes, concrete_circuit_file_name);
}

template<typename BlueprintFieldType, typename ArithmetizationType>
std::optional<std::string> setup_prover(const std::optional<std::string>& circuit_file_name,
                                        const std::optional<std::string>& assignment_table_file_name,
                                        std::unordered_map<nil::evm_assigner::zkevm_circuit, nil::blueprint::assignment<ArithmetizationType>>& assignments,
                                        zkevm_circuits<ArithmetizationType>& circuits) {
    auto start = std::chrono::high_resolution_clock::now();

    using Endianness = nil::marshalling::option::big_endian;

    auto init_start = std::chrono::high_resolution_clock::now();
    auto err = initialize_circuits<BlueprintFieldType>(circuits, assignments);
    if (err) {
        return "Preset step failed: " + err.value();
    }
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - init_start);
    std::cout << "INITIALIZE: " << duration.count() << " ms\n";

    if (circuit_file_name) {
        auto write_circuits_start = std::chrono::high_resolution_clock::now();
        const auto& circuit_names = circuits.get_circuit_names();
        for (const auto& circuit_name : circuit_names) {
            std::string concrete_circuit_file_name = circuit_file_name.value() + "." + std::to_string(circuits.get_index(circuit_name));
            if (circuit_name == "bytecode") {
                err = write_circuit<Endianness, ArithmetizationType, BlueprintFieldType>(circuits.get_index(circuit_name),
                                                                                        assignments,
                                                                                        circuits.m_bytecode_circuit,
                                                                                        concrete_circuit_file_name);
            } else if (circuit_name == "sha256") {
                err = write_circuit<Endianness, ArithmetizationType, BlueprintFieldType>(circuits.get_index(circuit_name),
                                                                                        assignments,
                                                                                        circuits.m_sha256_circuit,
                                                                                        concrete_circuit_file_name);
            } else if (circuit_name == "add") {
                err = write_circuit<Endianness, ArithmetizationType, BlueprintFieldType>(circuits.get_index(circuit_name),
                                                                                        assignments,
                                                                                        circuits.m_add_circuit,
                                                                                        concrete_circuit_file_name);
            }
            if (err) {
                return "Write circuits failed: " + err.value();
            }
        }
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - write_circuits_start);
        std::cout << "WRITE CIRCUITS: " << duration.count() << " ms\n";
    }

    if (assignment_table_file_name) {
        auto write_assignments_start = std::chrono::high_resolution_clock::now();
        auto err = write_binary_assignments<Endianness, ArithmetizationType, BlueprintFieldType>(
            assignments, assignment_table_file_name.value());
        if (err) {
            return "Write assignments failed: " + err.value();
        }
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - write_assignments_start);
        std::cout << "WRITE ASSIGNMENT TABLES: " << duration.count() << " ms\n";
    }

    duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "SETUP: " << duration.count() << " ms\n";

    return {};
}

template<typename ArithmetizationType>
void set_paddnig(nil::blueprint::assignment<ArithmetizationType>& assignments) {
    std::uint32_t used_rows_amount = assignments.rows_amount();

    std::uint32_t padded_rows_amount = std::pow(2, std::ceil(std::log2(used_rows_amount)));
    if (padded_rows_amount == used_rows_amount) {
        padded_rows_amount *= 2;
    }
    if (padded_rows_amount < 8) {
        padded_rows_amount = 8;
    }

    for (std::uint32_t i = 0; i < assignments.witnesses_amount(); i++) {
        for (std::uint32_t j = assignments.witness_column_size(i); j < padded_rows_amount; j++) {
            assignments.witness(i, j) = 0;
        }
    }
    for (std::uint32_t i = 0; i < assignments.public_inputs_amount(); i++) {
        for (std::uint32_t j = assignments.public_input_column_size(i); j < padded_rows_amount; j++) {
            assignments.public_input(i, j) = 0;
        }
    }
    for (std::uint32_t i = 0; i < assignments.constants_amount(); i++) {
        for (std::uint32_t j = assignments.constant_column_size(i); j < padded_rows_amount; j++) {
            assignments.constant(i, j) = 0;
        }
    }
    for (std::uint32_t i = 0; i < assignments.selectors_amount(); i++) {
        for (std::uint32_t j = assignments.selector_column_size(i); j < padded_rows_amount; j++) {
            assignments.selector(i, j) = 0;
        }
    }
}

template<typename BlueprintFieldType, typename ArithmetizationType>
std::optional<std::string> fill_sha256_table(nil::blueprint::assignment<ArithmetizationType>& sha256_table,
                                             const std::vector<std::string>& input) {
    using component_type =
        nil::blueprint::components::sha256<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

    // Prepare witness container to make an instance of the component
    typename component_type::manifest_type m = component_type::get_manifest();
    size_t witness_amount = *(m.witness_amount->begin());
    std::vector<std::uint32_t> witnesses(witness_amount);
    std::iota(witnesses.begin(), witnesses.end(), 0);  // fill 0, 1, ...

    component_type component_instance = component_type(
        witnesses, std::array<std::uint32_t, 1>{0}, std::array<std::uint32_t, 1>{0});

    constexpr const std::int32_t block_size = 2;
    constexpr const std::int32_t input_blocks_amount = 2;

    const auto& row_idx = sha256_table.public_input_column_size(0);
    std::array<typename component_type::var, input_blocks_amount * block_size> input_block_vars = {
        typename component_type::var(0, row_idx, false, component_type::var::column_type::public_input),
        typename component_type::var(0, row_idx + 1, false, component_type::var::column_type::public_input),
        typename component_type::var(0, row_idx + 2, false, component_type::var::column_type::public_input),
        typename component_type::var(0, row_idx + 3, false, component_type::var::column_type::public_input)
    };
    typename component_type::input_type component_input = {input_block_vars};
    //set input values
    sha256_table.public_input(0, row_idx) = typename BlueprintFieldType::extended_integral_type(input[0].c_str());
    sha256_table.public_input(0, row_idx + 1) = typename BlueprintFieldType::extended_integral_type(input[1].c_str());
    sha256_table.public_input(0, row_idx + 2) = typename BlueprintFieldType::extended_integral_type(input[2].c_str());
    sha256_table.public_input(0, row_idx + 3) = typename BlueprintFieldType::extended_integral_type(input[3].c_str());

    nil::blueprint::components::generate_assignments(component_instance, sha256_table, component_input, 0);

    return {};
}

template<typename BlueprintFieldType, typename ArithmetizationType>
std::optional<std::string> fill_add_table(nil::blueprint::assignment<ArithmetizationType>& add_table,
                                          const std::vector<std::string>& input) {
    using component_type =
        nil::blueprint::components::addition<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                                             BlueprintFieldType, nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    // Prepare witness container to make an instance of the component
    typename component_type::manifest_type m = component_type::get_manifest();
    size_t witness_amount = *(m.witness_amount->begin());
    std::vector<std::uint32_t> witnesses(witness_amount);
    std::iota(witnesses.begin(), witnesses.end(), 0);  // fill 0, 1, ...

    component_type component_instance = component_type(
        witnesses, std::array<std::uint32_t, 1>{0}, std::array<std::uint32_t, 1>{0});

    const auto& row_idx = add_table.public_input_column_size(0);
    auto v0 = typename component_type::var(0, row_idx, false, component_type::var::column_type::public_input);
    auto v1 = typename component_type::var(0, row_idx + 1, false, component_type::var::column_type::public_input);
    typename component_type::input_type component_input = {v0, v1};
    //set input values
    add_table.public_input(0, row_idx) = typename BlueprintFieldType::extended_integral_type(input[0].c_str());
    add_table.public_input(0, row_idx + 1) = typename BlueprintFieldType::extended_integral_type(input[1].c_str());

    nil::blueprint::components::generate_assignments(component_instance, add_table, component_input, 0);

    return {};
}

template<typename BlueprintFieldType, typename ArithmetizationType>
std::optional<std::string> fill_assignment_tables(std::unordered_map<nil::evm_assigner::zkevm_circuit,
                                                                     nil::blueprint::assignment<ArithmetizationType>>& assignments,
                                                  const std::optional<uint64_t>& shardId,
                                                  const std::optional<std::string>& blockHash,
                                                  const std::optional<std::string>& block_file_name,
                                                  const std::optional<std::string>& account_storage_file_name,
                                                  const std::vector<std::string>& input,
                                                  const zkevm_circuits<ArithmetizationType>& circuits,
                                                  const std::optional<OutputArtifacts>& artifacts,
                                                  boost::log::trivial::severity_level log_level) {
    using Endianness = nil::marshalling::option::big_endian;

    auto start = std::chrono::high_resolution_clock::now();

    // generate assignments for sha256
    auto find_it = assignments.find(circuits.get_index("sha256"));
    if (find_it != assignments.end()) {
        auto& sha256_table = find_it->second;
        return fill_sha256_table<BlueprintFieldType, ArithmetizationType>(sha256_table, input);
    }
    find_it = assignments.find(circuits.get_index("add"));
    if (find_it != assignments.end()) {
        auto& add_table = find_it->second;
        return fill_add_table<BlueprintFieldType, ArithmetizationType>(add_table, input);
    }
    return "Can't find assignment table for sha256";


    // TODO enable after implement filling assignment tables from tracer
    /*single_thread_runner<BlueprintFieldType> runner(assignments, shardId,
                                                    circuit_names, log_level);

    auto err = runner.extract_block_with_messages(blockHash, block_file_name);
    if (err) {
        return "Extract input block failed: " + err.value();
    }

    err = runner.extract_accounts_with_storage(account_storage_file_name);
    if (err) {
        return "Extract account storage failed: " + err.value();
    }

    err = runner.run(assignment_table_file_name, artifacts);
    if (err) {
        return "Assigner run failed: " + err.value();
    }*/

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "FILL ASSIGNMENT TABLES: " << duration.count() << " ms\n";

    return {};
}

template<typename BlueprintFieldType>
int curve_dependent_main(const std::optional<uint64_t>& shardId,
                         const std::optional<std::string>& blockHash,
                         const std::optional<std::string>& block_file_name,
                         const std::optional<std::string>& account_storage_file_name,
                         const std::optional<std::string>& assignment_table_file_name,
                         const std::optional<std::string>& circuit_file_name,
                         const std::optional<OutputArtifacts>& artifacts,
                         const std::vector<std::string>& target_circuits,
                         const std::vector<std::string>& input,
                         const std::optional<std::string>& path,
                         boost::log::trivial::severity_level log_level) {
    using ArithmetizationType =
        nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;

    boost::log::core::get()->set_filter(boost::log::trivial::severity >= log_level);

    zkevm_circuits<ArithmetizationType> circuits;
    // TODO just for check sha256, should be removed ater add regular zk EVM circuits
    std::optional<std::string> circuit_file_index;
    if (target_circuits.size() == 1 && target_circuits[0].find("sha256") != std::string::npos) {
        circuit_file_index = target_circuits[0].substr(7);
        circuits.m_names = {"sha256"};
    } else if (target_circuits.size() == 1 && target_circuits[0].find("add") != std::string::npos) {
        circuit_file_index = target_circuits[0].substr(4);
        circuits.m_names = {"add"};
    }else {
        circuits.m_names = target_circuits;
    }

    std::unordered_map<nil::evm_assigner::zkevm_circuit,
                       nil::blueprint::assignment<ArithmetizationType>>
        assignments;

    BOOST_LOG_TRIVIAL(debug) << "SetUp prover\n";
    auto err = setup_prover<BlueprintFieldType, ArithmetizationType>(circuit_file_name, assignment_table_file_name, assignments, circuits);
    if (err) {
        std::cerr << "Failed set up prover " << err.value() << std::endl;
        return 1;
    }

    BOOST_LOG_TRIVIAL(debug) << "Fill assignment tables\n";
    err = fill_assignment_tables<BlueprintFieldType, ArithmetizationType>(
        assignments, shardId, blockHash, block_file_name,
        account_storage_file_name, input, circuits, artifacts, log_level);
    if (err) {
        std::cerr << "Failed fill assignment tables " << err.value() << std::endl;
        return 1;
    }

    using CurveType = nil::crypto3::algebra::curves::pallas;
    using HashType = nil::crypto3::hashes::keccak_1600<256>;

    auto prover = nil::proof_generator::Prover<CurveType, HashType>(
            9,  //lambda
            2,  //expand_factor
            0,  //max_quotient_chunks
            69  //grind
        );

    // for each circuit
    const auto& circuit_names = circuits.get_circuit_names();
    for(const auto& circuit_name : circuit_names) {
        const auto circuit_index = circuits.get_index(circuit_name);
        auto start = std::chrono::high_resolution_clock::now();
        if (circuit_name == "sha256") {
            prover.set_circuit(circuits.m_sha256_circuit);
            auto find_it = assignments.find(circuits.get_index("sha256"));
            if (find_it == assignments.end()) {
                std::cerr << "Can't find assignment table for sha256" << std::endl;
                return 1;
            }
            auto& sha256_table = find_it->second;
            std::size_t used_rows_amount = sha256_table.rows_amount();
            set_paddnig<ArithmetizationType>(sha256_table);
            prover.set_assignment_table(sha256_table, used_rows_amount);
        } else if (circuit_name == "add") {
            prover.set_circuit(circuits.m_add_circuit);
            auto find_it = assignments.find(circuits.get_index("add"));
            if (find_it == assignments.end()) {
                std::cerr << "Can't find assignment table for add" << std::endl;
                return 1;
            }
            auto& add_table = find_it->second;
            std::size_t used_rows_amount = add_table.rows_amount();
            set_paddnig<ArithmetizationType>(add_table);
            prover.set_assignment_table(add_table, used_rows_amount);
        }
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
        std::cout << "SET PROOF PRODUCER INPUTS: " << duration.count() << " ms\n";

        auto process_public_data_start = std::chrono::high_resolution_clock::now();
        if (!prover.preprocess_public_data()) {
            std::cerr << "Failed preprocess public data" << std::endl;
            return 1;
        }
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - process_public_data_start);
        std::cout << "PROCESS PUBLIC DATA: " << duration.count() << " ms\n";

        auto process_private_data_start = std::chrono::high_resolution_clock::now();
        if (!prover.preprocess_private_data()) {
            std::cerr << "Failed preproces private data" << std::endl;
            return 1;
        }
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - process_private_data_start);
        std::cout << "PREPROCESS PRIVATE DATA: " << duration.count() << " ms\n";

        std::string file_name_suffix = circuit_file_index.has_value() ? circuit_file_index.value() : std::to_string(circuit_index);
        if (shardId) {
            file_name_suffix += "." + std::to_string(shardId.value());
        }
        if (blockHash) {
            file_name_suffix += "." + blockHash.value();
        }
        std::string file_root_path = path.has_value() ? path.value() : "";
        auto partial_proof_start = std::chrono::high_resolution_clock::now();
        if (!prover.generate_partial_proof_to_file(file_root_path + "proof." + file_name_suffix,
                                                   file_root_path + "challenge." + file_name_suffix,
                                                   file_root_path + "theta_power." + file_name_suffix)) {
            std::cerr << "Failed generation partial proof" << std::endl;
            return 1;
        }
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - partial_proof_start);
        std::cout << "PARTIAL PROOF: " << duration.count() << " ms\n";

        auto write_commitment_state_start = std::chrono::high_resolution_clock::now();
        if (!prover.save_commitment_state_to_file(file_root_path + "commitment_state." + file_name_suffix)) {
            std::cerr << "Failed write commitment state" << std::endl;
            return 1;
        }
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - write_commitment_state_start);
        std::cout << "WRITE COMMITMENT STATE: " << duration.count() << " ms\n";

        if (!prover.save_assignment_description(file_root_path + "assignment_table_description." + file_name_suffix)) {
            std::cerr << "Failed write assignment table description" << std::endl;
            return 1;
        }
    }



    // Check if bytecode table is satisfied to the bytecode constraints
    /*auto it = assignments.find(nil::evm_assigner::zkevm_circuit::BYTECODE);
    if (it == assignments.end()) {
        std::cerr << "Can;t find bytecode assignment table\n";
        return 1;
    }
    auto& bytecode_table = it->second;
    if (!::is_satisfied<BlueprintFieldType>(circuits.m_bytecode_circuit, bytecode_table)) {
        std::cerr << "Bytecode table is not satisfied!" << std::endl;
        return 0;  // Do not produce failure for now
    }*/
    return 0;
}

int main(int argc, char* argv[]) {
    boost::program_options::options_description options_desc("zkEVM assigner");

    // clang-format off
    options_desc.add_options()("help,h", "Display help message")
            ("version,v", "Display version")
            ("assignment-tables,t", boost::program_options::value<std::string>(), "Assignment tables output files")
            ("circuits,c", boost::program_options::value<std::string>(), "Circuits output files")
            ("output-text", boost::program_options::value<std::string>(), "Output assignment table in readable format. "
                                                                          "Filename or `-` for stdout. "
                                                                          "Using this enables options --tables, --rows, --columns")
            ("tables", boost::program_options::value<std::string>(), "Assignment table indices to output. "
                                                                     "Format is --tables N|N-|-N|N-M(,N|N-|-N|N-M)*. "
                                                                     "If not specified, outputs all generated tables")
            ("rows", boost::program_options::value<std::string>(), "Range of rows of the table to output. "
                                                                   "Format is --rows N|N-|-N|N-M(,N|N-|-N|N-M)*. "
                                                                   "If not specified, outputs all rows")
            ("columns", boost::program_options::value<std::vector<std::string>>(), "Range of columns of the table to output. "
                                                                                   "Format is --columns <name>N|N-|-N|N-M(,N|N-|-N|N-M)*, where <name> is public_input|witness|constant|selector."
                                                                                   "If not specified, outputs all columns. "
                                                                                   "May be provided multiple times with different column types")
            ("shard-id", boost::program_options::value<uint64_t>(), "ID of the shard where executed block")
            ("block-hash", boost::program_options::value<std::string>(), "Hash of the input block")
            ("block-file,b", boost::program_options::value<std::string>(), "Predefined input block with messages")
            ("account-storage,s", boost::program_options::value<std::string>(), "Account storage config file")
            ("elliptic-curve-type,e", boost::program_options::value<std::string>(), "Native elliptic curve type (pallas, vesta, ed25519, bls12381)")
            ("target-circuits", boost::program_options::value<std::vector<std::string>>(), "Fill assignment table only for certain circuits. If not set - fill assignments for all")
            ("input", boost::program_options::value<std::vector<std::string>>(), "sha256 input val00 val01, val10, val11")
            ("path", boost::program_options::value<std::string>(), "Path to the output folder")
            ("log-level,l", boost::program_options::value<std::string>(), "Log level (trace, debug, info, warning, error, fatal)");
    // clang-format on

    boost::program_options::variables_map vm;
    try {
        boost::program_options::store(
            boost::program_options::command_line_parser(argc, argv).options(options_desc).run(),
            vm);
        boost::program_options::notify(vm);
    } catch (const boost::program_options::unknown_option& e) {
        std::cerr << "Invalid command line argument: " << e.what() << std::endl;
        std::cout << options_desc << std::endl;
        return 1;
    }

    if (vm.count("help")) {
        std::cout << options_desc << std::endl;
        return 0;
    }

    if (vm.count("version")) {
#ifdef ASSIGNER_VERSION
#define xstr(s) str(s)
#define str(s) #s
        std::cout << xstr(ASSIGNER_VERSION) << std::endl;
#else
        std::cout << "Version is not defined" << std::endl;
#endif
        return 0;
    }

    std::optional<uint64_t> shardId = std::nullopt;
    std::optional<std::string> assignment_table_file_name = std::nullopt;
    std::optional<std::string> circuit_file_name = std::nullopt;
    std::optional<std::string> blockHash = std::nullopt;
    std::optional<std::string> block_file_name = std::nullopt;
    std::optional<std::string> account_storage_file_name = std::nullopt;
    std::optional<std::string> path = std::nullopt;
    std::string elliptic_curve;
    std::string log_level;
    std::vector<std::string> target_circuits;
    std::vector<std::string> input;

    if (vm.count("assignment-tables")) {
        assignment_table_file_name = vm["assignment-tables"].as<std::string>();
    }

    if (vm.count("circuits")) {
        circuit_file_name = vm["circuits"].as<std::string>();
    }

    if (vm.count("block-file")) {
        block_file_name = vm["block-file"].as<std::string>();
    }

    if (vm.count("shard-id")) {
        shardId = vm["shard-id"].as<uint64_t>();
    }

    if (vm.count("block-hash")) {
        blockHash = vm["block-hash"].as<std::string>();
    }

    if (vm.count("account-storage")) {
        account_storage_file_name = vm["account-storage"].as<std::string>();
    }

    std::optional<OutputArtifacts> artifacts = std::nullopt;
    if (vm.count("output-text")) {
        auto maybe_artifacts = OutputArtifacts::from_program_options(vm);
        if (!maybe_artifacts.has_value()) {
            std::cerr << maybe_artifacts.error() << std::endl;
            std::cout << options_desc << std::endl;
            return 1;
        }
        artifacts = maybe_artifacts.value();
    }

    if (vm.count("elliptic-curve-type")) {
        elliptic_curve = vm["elliptic-curve-type"].as<std::string>();
    } else {
        elliptic_curve = "pallas";
    }

    if (vm.count("target-circuits")) {
        target_circuits = vm["target-circuits"].as<std::vector<std::string>>();
    }

    if (vm.count("input")) {
        input = vm["input"].as<std::vector<std::string>>();
        if (input.size() != 4) {
            std::cerr << "wrong input, should has 4 values" << std::endl;
            return 1;
        }
    } else {
        std::cerr << "input is required" << std::endl;
        return 1;
    }

    if (vm.count("path")) {
        path = vm["path"].as<std::string>();
    }

    if (vm.count("log-level")) {
        log_level = vm["log-level"].as<std::string>();
    } else {
        log_level = "info";
    }
    // We use Boost log trivial severity levels, these are string representations of their names
    std::map<std::string, boost::log::trivial::severity_level> log_options{
        {"trace", boost::log::trivial::trace}, {"debug", boost::log::trivial::debug},
        {"info", boost::log::trivial::info},   {"warning", boost::log::trivial::warning},
        {"error", boost::log::trivial::error}, {"fatal", boost::log::trivial::fatal}};

    if (log_options.find(log_level) == log_options.end()) {
        std::cerr << "Invalid command line argument -l (log level): " << log_level << std::endl;
        std::cout << options_desc << std::endl;
        return 1;
    }

    std::map<std::string, int> curve_options{
        {"pallas", 0},
        {"vesta", 1},
        {"ed25519", 2},
        {"bls12381", 3},
    };

    if (curve_options.find(elliptic_curve) == curve_options.end()) {
        std::cerr << "Invalid command line argument -e (Native elliptic curve type): "
                  << elliptic_curve << std::endl;
        std::cout << options_desc << std::endl;
        return 1;
    }

    switch (curve_options[elliptic_curve]) {
        case 0: {
            return curve_dependent_main<
                typename nil::crypto3::algebra::curves::pallas::base_field_type>(
                shardId, blockHash, block_file_name, account_storage_file_name,
                assignment_table_file_name, circuit_file_name, artifacts, target_circuits, input, path, log_options[log_level]);
            break;
        }
        case 1: {
            std::cerr << "vesta curve based circuits are not supported yet\n";
            break;
        }
        case 2: {
            std::cerr << "ed25519 curve based circuits are not supported yet\n";
            break;
        }
        case 3: {
            std::cerr << "bls12 curve based circuits are not supported yet\n";
            break;
        }
    };

    return 0;
}
