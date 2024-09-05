#ifndef ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_MESSAGE_HPP_
#define ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_MESSAGE_HPP_

#include <bitset>
#include <cstdint>

#include "zkevm_framework/core/types/address.hpp"
#include "zkevm_framework/core/types/code.hpp"
#include "zkevm_framework/core/types/currency.hpp"
#include "zkevm_framework/core/types/gas.hpp"
#include "zkevm_framework/core/types/signature.hpp"
#include "zkevm_framework/core/types/value.hpp"

namespace core {
    namespace types {
        enum class MessageKind : std::uint8_t {
            Internal,
            Deploy,
            Refund,
            Bounce,
        };

        using Seqno = std::uint64_t;

        using MessageIndex = std::uint64_t;

        using ChainId = std::uint64_t;

        struct Message : ssz::ssz_variable_size_container {
            std::bitset<8> m_flags;
            ChainId m_chain_id;
            Seqno m_seqno;
            Value m_feeCredit;
            Address m_from;
            Address m_to;
            Address m_refund_to;
            Address m_bounce_to;
            Value m_value;
            ssz::list<CurrencyBalance, 256> m_currency;
            Code<24576> m_data;
            Signature<256> m_signature;

            SSZ_CONT(m_flags, m_chain_id, m_seqno, m_feeCredit, m_from, m_to, m_refund_to,
                     m_bounce_to, m_value, m_currency, m_data, m_signature)
        };

        using MessageStatus = std::uint32_t;

        struct ExternalMessage : ssz::ssz_variable_size_container {
            // Enums are not serializable in SSZ++ so we have to use integer type here.
            // To get enum, use `kind()` method.
            std::uint8_t m_kind;
            Address m_to;
            ChainId m_chain_id;
            Seqno m_seqno;
            Code<24576> m_data;
            Signature<256> m_auth_data;

            SSZ_CONT(m_kind, m_to, m_chain_id, m_seqno, m_data, m_auth_data)

            MessageKind kind() const { return static_cast<MessageKind>(m_kind); }
        };
    }  // namespace types
}  // namespace core

#endif  // ZKEMV_FRAMEWORK_LIBS_NIL_CORE_INCLUDE_ZKEVM_FRAMEWORK_CORE_TYPES_MESSAGE_HPP_
