#ifndef ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_ACCOUNT_HPP_
#define ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_ACCOUNT_HPP_

#include <array>
#include <cstddef>

#include "ssz++.hpp"
#include "zkevm_framework/core/common.hpp"
#include "zkevm_framework/core/types/address.hpp"
#include "zkevm_framework/core/types/message.hpp"
#include "zkevm_framework/core/types/value.hpp"

namespace core {
    namespace types {
        constexpr std::size_t PUBLIC_KEY_SIZE = 33;

        using PublicKey = std::array<std::byte, PUBLIC_KEY_SIZE>;

        struct SmartContract : ssz::ssz_container {
            Address m_address;
            bool m_initialised;
            Value m_balance;
            Hash m_currency_root;
            Hash m_storage_root;
            Hash m_code_hash;
            Seqno m_seqno;
            Seqno m_ext_seqno;
            PublicKey m_public_key;

            SSZ_CONT(m_address, m_initialised, m_balance, m_currency_root, m_storage_root,
                     m_code_hash, m_seqno, m_ext_seqno, m_public_key)
        };
    }  // namespace types
}  // namespace core

#endif  // ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_ACCOUNT_HPP_
