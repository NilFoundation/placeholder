#ifndef ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_BLOCK_HPP_
#define ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_BLOCK_HPP_

#include <cstdint>

#include "zkevm_framework/core/common.hpp"
#include "zkevm_framework/core/types/bloom.hpp"
#include "zkevm_framework/core/types/message.hpp"

namespace core {
    namespace types {
        using BlockNumber = std::uint64_t;

        struct Block : ssz::ssz_container {
            BlockNumber m_id;
            Hash m_prev_block;
            Hash m_smart_contracts_root;
            Hash m_in_messages_root;
            Hash m_out_messages_root;
            MessageIndex m_out_messages_num;
            Hash m_receipts_root;
            Hash m_child_blocks_root_hash;
            Hash m_master_chain_hash;
            Bloom m_logs_bloom;
            std::uint64_t m_timestamp;
            Value m_gasPrice;

            SSZ_CONT(m_id, m_prev_block, m_smart_contracts_root, m_in_messages_root,
                     m_out_messages_root, m_out_messages_num, m_receipts_root,
                     m_child_blocks_root_hash, m_master_chain_hash, m_logs_bloom, m_timestamp,
                     m_gasPrice)
        };
    }  // namespace types
}  // namespace core

#endif  // ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_BLOCK_HPP_
