#ifndef ZKEMV_FRAMEWORK_LIBS_RPC_DATA_EXTRACTOR_HPP_
#define ZKEMV_FRAMEWORK_LIBS_RPC_DATA_EXTRACTOR_HPP_

#include <istream>
#include <optional>
#include <string>

#include "zkevm_framework/core/types/account.hpp"
#include "zkevm_framework/core/types/block.hpp"

class data_extractor {
  public:
    data_extractor(std::string host, int port, uint64_t shard_id)
        : m_host(host), m_port(port), m_shard_id(shard_id) {}
    std::optional<std::string> get_block_with_messages(const std::string& blockHash,
                                                       std::stringstream& block_data) const;
    std::optional<std::string> get_account_with_storage(const std::string& address,
                                                        const std::string& blockHash,
                                                        std::stringstream& account_data) const;

  private:
    std::string m_host;
    int m_port;
    uint64_t m_shard_id;
};

#endif  // ZKEMV_FRAMEWORK_LIBS_RPC_DATA_EXTRACTOR_HPP_
