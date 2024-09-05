#ifndef ZKEMV_FRAMEWORK_LIBS_ASSIGNER_RUNNER_INCLUDE_ZKEVM_FRAMEWORK_ASSIGNER_RUNNER_STATE_PARSER_HPP_
#define ZKEMV_FRAMEWORK_LIBS_ASSIGNER_RUNNER_INCLUDE_ZKEVM_FRAMEWORK_ASSIGNER_RUNNER_STATE_PARSER_HPP_

#include <istream>
#include <optional>
#include <string>

#include "vm_host.hpp"

/// @brief Fill account storage by config from input stream
std::optional<std::string> init_account_storage(evmc::accounts &account_storage,
                                                std::istream &config);

/// @brief Fill account storage by config from file
std::optional<std::string> init_account_storage(evmc::accounts &account_storage,
                                                const std::string &account_storage_config_name);

/// @brief Fill account and storage from RPC response
std::optional<std::string> load_account_with_storage(evmc::account &account,
                                                     std::istream &account_data);

#endif  // ZKEMV_FRAMEWORK_LIBS_ASSIGNER_RUNNER_INCLUDE_ZKEVM_FRAMEWORK_ASSIGNER_RUNNER_STATE_PARSER_HPP_
