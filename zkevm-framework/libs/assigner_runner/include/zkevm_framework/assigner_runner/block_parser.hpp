#ifndef ZKEMV_FRAMEWORK_LIBS_ASSIGNER_RUNNER_INCLUDE_ZKEVM_FRAMEWORK_ASSIGNER_RUNNER_BLOCK_PARSER_HPP_
#define ZKEMV_FRAMEWORK_LIBS_ASSIGNER_RUNNER_INCLUDE_ZKEVM_FRAMEWORK_ASSIGNER_RUNNER_BLOCK_PARSER_HPP_

#include <istream>
#include <optional>
#include <string>

#include "zkevm_framework/core/types/block.hpp"
#include "zkevm_framework/core/types/message.hpp"

/// @brief Fill block and input messages from input stream
std::optional<std::string> load_block_with_messages(core::types::Block& block,
                                                    std::vector<core::types::Message>& messages,
                                                    std::istream& block_data);

/// @brief Fill block and input messages from input stream which contains serialized block and
/// messages
std::optional<std::string> load_raw_block_with_messages(core::types::Block& block,
                                                        std::vector<core::types::Message>& messages,
                                                        std::istream& block_data);

#endif  // ZKEMV_FRAMEWORK_LIBS_ASSIGNER_RUNNER_INCLUDE_ZKEVM_FRAMEWORK_ASSIGNER_RUNNER_BLOCK_PARSER_HPP_
