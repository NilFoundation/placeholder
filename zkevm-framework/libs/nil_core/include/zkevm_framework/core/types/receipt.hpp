#ifndef ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_RECEIPT_HPP_
#define ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_RECEIPT_HPP_

#include "ssz++.hpp"
#include "zkevm_framework/core/common.hpp"
#include "zkevm_framework/core/types/address.hpp"
#include "zkevm_framework/core/types/bloom.hpp"
#include "zkevm_framework/core/types/gas.hpp"
#include "zkevm_framework/core/types/log.hpp"
#include "zkevm_framework/core/types/message.hpp"

namespace core {
    namespace types {
        struct Receipt : ssz::ssz_variable_size_container {
            bool m_success;
            MessageStatus m_status;
            Gas m_gas_used;
            Bloom m_bloom;
            ssz::list<Log, 1000> m_logs;
            std::uint32_t m_out_msg_index;
            std::uint32_t m_out_msg_num;
            Hash m_msg_hash;
            Address m_contract_address;

            SSZ_CONT(m_success, m_status, m_gas_used, m_bloom, m_logs, m_out_msg_index,
                     m_out_msg_num, m_msg_hash, m_contract_address)
        };
    }  // namespace types
}  // namespace core

#endif  // ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_RECEIPT_HPP_
