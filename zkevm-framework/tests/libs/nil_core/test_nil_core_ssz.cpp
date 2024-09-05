#include <cstddef>
#include <cstdint>
#include <vector>

#include "gtest/gtest.h"
#include "ssz++.hpp"
#include "zkevm_framework/core/common.hpp"
#include "zkevm_framework/core/types/account.hpp"
#include "zkevm_framework/core/types/address.hpp"
#include "zkevm_framework/core/types/block.hpp"
#include "zkevm_framework/core/types/bloom.hpp"
#include "zkevm_framework/core/types/currency.hpp"
#include "zkevm_framework/core/types/log.hpp"
#include "zkevm_framework/core/types/message.hpp"
#include "zkevm_framework/core/types/receipt.hpp"
#include "zkevm_framework/core/types/value.hpp"

using namespace core;
using namespace core::types;

// serialize -> deserialize -> serialize again -> compare two byte vectors
template<typename T>
void test_serialization(const T& obj) {
    std::vector<std::byte> bytes = ssz::serialize(obj);
    T new_obj = ssz::deserialize<T>(bytes);
    std::vector<std::byte> new_bytes = ssz::serialize(new_obj);
    ASSERT_EQ(bytes, new_bytes);
}

TEST(NilCoreSSZTests, Hash) {
    Hash x = {std::byte{0xAA}};
    test_serialization(x);
}

TEST(NilCoreSSZTests, SmartContract) {
    SmartContract x{};
    x.m_address = {std::byte{0xAA}};
    x.m_balance = Value{.m_value = 42};
    x.m_code_hash = {std::byte{0xBB}};
    x.m_currency_root = {std::byte{0xCC}};
    x.m_ext_seqno = 43;
    x.m_initialised = true;
    x.m_public_key = {std::byte{0xDD}};
    x.m_seqno = 44;
    x.m_storage_root = {std::byte{0xEE}};
    test_serialization(x);
}

TEST(NilCoreSSZTests, Address) {
    Address x = {std::byte{0xAA}};
    test_serialization(x);
}

TEST(NilCoreSSZTests, Block) {
    Block x{};
    x.m_child_blocks_root_hash = {std::byte{0xAA}};
    x.m_id = 42;
    x.m_in_messages_root = {std::byte{0xBB}};
    x.m_logs_bloom = {std::byte{0xCC}};
    x.m_master_chain_hash = {std::byte{0xDD}};
    x.m_out_messages_num = 43;
    x.m_out_messages_root = {std::byte{0xEE}};
    x.m_prev_block = {std::byte{0xFF}};
    x.m_receipts_root = {std::byte{0x11}};
    x.m_smart_contracts_root = {std::byte{0x22}};
    x.m_timestamp = 44;
    x.m_gasPrice = Value{.m_value = 100};
    test_serialization(x);
}

TEST(NilCoreSSZTests, Bloom) {
    Bloom x = {std::byte{0xAA}};
    test_serialization(x);
}

TEST(NilCoreSSZTests, CurrencyBalance) {
    CurrencyBalance x{};
    x.m_balance = Value{.m_value = 42};
    x.m_currency = {std::byte{0xAA}};
    test_serialization(x);
}

TEST(NilCoreSSZTests, Log) {
    Log x{};
    x.m_address = {std::byte{0xAA}};
    x.m_data = std::vector{std::byte{0xBB}, std::byte{0xBB}, std::byte{0xBB}};
    x.m_topics = {std::byte{0xCC}};
    test_serialization(x);
}

TEST(NilCoreSSZTests, Message) {
    Message x{};
    x.m_flags = 0b10101010;
    x.m_chain_id = 42;
    x.m_seqno = 47;
    x.m_feeCredit = Value{.m_value = 2000000};
    x.m_from = {std::byte{0xEE}};
    x.m_to = {std::byte{0x22}};
    x.m_refund_to = {std::byte{0xFF}};
    x.m_bounce_to = {std::byte{0xFF}};
    x.m_value = Value{.m_value = 100};
    x.m_currency = std::vector{CurrencyBalance{}, CurrencyBalance{}};
    x.m_currency[0].m_balance = Value{.m_value = 43};
    x.m_currency[0].m_currency = {std::byte{0xBB}};
    x.m_currency[1].m_balance = Value{.m_value = 44};
    x.m_currency[1].m_currency = {std::byte{0xCC}};
    x.m_data = {{std::vector{std::byte{0xDD}, std::byte{0xDD}, std::byte{0xDD}}}};
    x.m_signature = {{std::vector{std::byte{0x11}, std::byte{0x11}, std::byte{0x11}}}};
    test_serialization(x);
}

TEST(NilCoreSSZTests, ExternalMessage) {
    ExternalMessage x{};
    x.m_kind = static_cast<std::uint8_t>(MessageKind::Deploy);
    x.m_to = {std::byte{0xCC}};
    x.m_chain_id = 42;
    x.m_seqno = 43;
    x.m_data = {{std::vector{std::byte{0xBB}, std::byte{0xBB}, std::byte{0xBB}}}};
    x.m_auth_data = {{std::vector{std::byte{0xAA}, std::byte{0xAA}, std::byte{0xAA}}}};
    test_serialization(x);
}

TEST(NilCoreSSZTests, Receipt) {
    Receipt x{};
    x.m_bloom = {std::byte{0xAA}};
    x.m_contract_address = {std::byte{0xBB}};
    x.m_gas_used = 42;
    x.m_logs = std::vector{Log{}};
    x.m_logs[0].m_address = {std::byte{0xCC}};
    x.m_logs[0].m_data = {{std::vector{std::byte{0xDD}, std::byte{0xDD}, std::byte{0xDD}}}};
    x.m_logs[0].m_topics = {std::byte{0xEE}};
    x.m_msg_hash = {std::byte{0xFF}};
    x.m_out_msg_index = 43;
    x.m_out_msg_num = 44;
    x.m_status = 45;
    x.m_success = true;
    test_serialization(x);
}

TEST(NilCoreSSZTests, Value) {
    Value x{.m_value = 42};
    test_serialization(x);
}
