#ifndef ZKEMV_FRAMEWORK_LIBS_ASSIGNER_RUNNER_INCLUDE_ZKEVM_FRAMEWORK_ASSIGNER_RUNNER_UTILS_HPP_
#define ZKEMV_FRAMEWORK_LIBS_ASSIGNER_RUNNER_INCLUDE_ZKEVM_FRAMEWORK_ASSIGNER_RUNNER_UTILS_HPP_

#include <evmc.h>

#include <execution_state.hpp>
#include <instructions_opcodes.hpp>

#include "zkevm_framework/core/common.hpp"
#include "zkevm_framework/core/types/address.hpp"

static evmc::uint256be to_uint256be(intx::uint256 v) { return intx::be::store<evmc::uint256be>(v); }

evmc_call_kind evmc_msg_kind(const std::bitset<8>& type);
evmc_address to_evmc_address(const core::types::Address& v);

std::string to_str(const evmc_address& v);
std::string to_str(const core::types::Address& v);
std::string to_str(const evmc_bytes32& v);
std::string to_str(const std::vector<uint8_t>& code);
std::string to_str(const std::bitset<8>& type);
std::string to_str(evmc_status_code code);
std::string to_str(const core::Hash& v);

#endif  // ZKEMV_FRAMEWORK_LIBS_ASSIGNER_RUNNER_INCLUDE_ZKEVM_FRAMEWORK_ASSIGNER_RUNNER_UTILS_HPP_
