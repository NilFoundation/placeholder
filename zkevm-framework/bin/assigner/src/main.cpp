#include <expected>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <string>

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
#include <unordered_map>

#include "checks.hpp"
#include "zkevm_framework/assigner_runner/runner.hpp"
#include "zkevm_framework/preset/preset.hpp"

template<typename BlueprintFieldType>
int curve_dependent_main(uint64_t shardId, const std::string& blockHash,
                         const std::string& block_file_name,
                         const std::string& account_storage_file_name,
                         const std::string& assignment_table_file_name,
                         const std::optional<OutputArtifacts>& artifacts,
                         const std::vector<std::string>& target_circuits,
                         boost::log::trivial::severity_level log_level) {
    using ArithmetizationType =
        nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;

    boost::log::core::get()->set_filter(boost::log::trivial::severity >= log_level);

    zkevm_circuits<ArithmetizationType> circuits;
    circuits.m_names = target_circuits;

    std::unordered_map<nil::evm_assigner::zkevm_circuit,
                       nil::blueprint::assignment<ArithmetizationType>>
        assignments;

    auto err = initialize_circuits<BlueprintFieldType>(circuits, assignments);
    if (err) {
        std::cerr << "Preset step failed: " << err.value() << std::endl;
        return 1;
    }

    single_thread_runner<BlueprintFieldType> runner(assignments, shardId,
                                                    circuits.get_circuit_names(), log_level);

    err = runner.extract_block_with_messages(blockHash, block_file_name);
    if (err) {
        std::cerr << "Extract input block failed: " << err.value() << std::endl;
        return 1;
    }

    err = runner.extract_accounts_with_storage(account_storage_file_name);
    if (err) {
        std::cerr << "Extract account storage failed: " << err.value() << std::endl;
        return 1;
    }

    err = runner.run(assignment_table_file_name, artifacts);
    if (err.has_value()) {
        std::cerr << "Assigner run failed: " << err.value() << std::endl;
        return 1;
    }

    // Check if bytecode table is satisfied to the bytecode constraints
    auto it = assignments.find(nil::evm_assigner::zkevm_circuit::BYTECODE);
    if (it == assignments.end()) {
        std::cerr << "Can;t find bytecode assignment table\n";
        return 1;
    }
    auto& bytecode_table = it->second;
    if (!::is_satisfied<BlueprintFieldType>(circuits.m_bytecode_circuit, bytecode_table)) {
        std::cerr << "Bytecode table is not satisfied!" << std::endl;
        return 0;  // Do not produce failure for now
    }
    return 0;
}

int main(int argc, char* argv[]) {
    boost::program_options::options_description options_desc("zkEVM1 assigner");

    // clang-format off
    options_desc.add_options()("help,h", "Display help message")
            ("version,v", "Display version")
            ("assignment-tables,t", boost::program_options::value<std::string>(), "Assignment table output files")
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

    uint64_t shardId = 0;
    std::string assignment_table_file_name;
    std::string blockHash;
    std::string block_file_name;
    std::string account_storage_file_name;
    std::string elliptic_curve;
    std::string log_level;
    std::vector<std::string> target_circuits;

    if (vm.count("assignment-tables")) {
        assignment_table_file_name = vm["assignment-tables"].as<std::string>();
    } else {
        std::cerr << "Invalid command line argument - assignment table file name is not specified"
                  << std::endl;
        std::cout << options_desc << std::endl;
        return 1;
    }

    if (vm.count("block-file")) {
        block_file_name = vm["block-file"].as<std::string>();
    } else {
        block_file_name = "";
        if (vm.count("shard-id")) {
            shardId = vm["shard-id"].as<uint64_t>();
        } else {
            std::cerr << "Invalid command line argument - shard-id or block-file must be specified"
                      << std::endl;
            std::cout << options_desc << std::endl;
            return 1;
        }

        if (vm.count("block-hash")) {
            blockHash = vm["block-hash"].as<std::string>();
        } else {
            std::cerr
                << "Invalid command line argument - block-hash or block-file must be specified"
                << std::endl;
            std::cout << options_desc << std::endl;
            return 1;
        }
    }

    if (vm.count("account-storage")) {
        account_storage_file_name = vm["account-storage"].as<std::string>();
    } else {
        account_storage_file_name = "";
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
                assignment_table_file_name, artifacts, target_circuits, log_options[log_level]);
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
            return curve_dependent_main<
                typename nil::crypto3::algebra::fields::bls12_base_field<381>>(
                shardId, blockHash, block_file_name, account_storage_file_name,
                assignment_table_file_name, artifacts, target_circuits, log_options[log_level]);
            break;
        }
    };

    return 0;
}
