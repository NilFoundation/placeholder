#ifndef ZKEMV_FRAMEWORK_LIBS_ASSIGNER_RUNNER_INCLUDE_ZKEVM_FRAMEWORK_ASSIGNER_RUNNER_RUNNER_HPP_
#define ZKEMV_FRAMEWORK_LIBS_ASSIGNER_RUNNER_INCLUDE_ZKEVM_FRAMEWORK_ASSIGNER_RUNNER_RUNNER_HPP_

#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <unordered_map>

#include "output_artifacts.hpp"
#include "zkevm_framework/assigner_runner/ext_vm_host.hpp"
#include "zkevm_framework/assigner_runner/utils.hpp"
#include "zkevm_framework/core/types/block.hpp"
#include "zkevm_framework/rpc/data_extractor.hpp"

template<typename BlueprintFieldType>
class single_thread_runner {
  public:
    using ArithmetizationType =
        nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;

    /// @brief Initialize runner with empty input block and account storage
    single_thread_runner(
        std::unordered_map<nil::evm_assigner::zkevm_circuit,
                           nil::blueprint::assignment<ArithmetizationType>>& assignments,
        uint64_t shard_id = 0, const std::vector<std::string>& target_circuits = {},
        boost::log::trivial::severity_level log_level = boost::log::trivial::info)
        : m_assignments(assignments),
          m_target_circuits(target_circuits),
          m_log_level(log_level),
          m_extractor("127.0.0.1", 8529, shard_id) {}

    /// @brief Execute one block
    std::optional<std::string> run(const std::string& assignment_table_file_name,
                                   const std::optional<OutputArtifacts>& artifacts);

    /// @brief Load account storage from file
    std::optional<std::string> extract_accounts_with_storage(
        const std::string& account_storage_config_name);

    /// @brief Load input block with messages from RPC or file
    std::optional<std::string> extract_block_with_messages(const std::string& blockHash,
                                                           const std::string& block_file_name);

  private:
    std::optional<std::string> fill_assignments();

    std::unordered_map<nil::evm_assigner::zkevm_circuit,
                       nil::blueprint::assignment<ArithmetizationType>>& m_assignments;

    std::vector<std::string> m_target_circuits;
    boost::log::trivial::severity_level m_log_level;
    data_extractor m_extractor;
    evmc::accounts m_account_storage;
    core::types::Block m_current_block;
    std::vector<core::types::Message> m_input_messages;
};

#endif  // ZKEMV_FRAMEWORK_LIBS_ASSIGNER_RUNNER_INCLUDE_ZKEVM_FRAMEWORK_ASSIGNER_RUNNER_RUNNER_HPP_
