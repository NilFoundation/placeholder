#ifndef EVM_ASSIGNER_LIB_ASSIGNER_INCLUDE_VM_HOST_H_
#define EVM_ASSIGNER_LIB_ASSIGNER_INCLUDE_VM_HOST_H_

// Based on example host

#include <evmc.hpp>
#include <ethash/keccak.hpp>

#include <algorithm>
#include <map>
#include <vector>
#include <memory>

#include <assigner.hpp>
#include <zkevm_word.hpp>

using namespace evmc::literals;

namespace evmc
{
struct account
{
    virtual ~account() = default;

    evmc::uint256be balance = {};
    std::vector<uint8_t> code;
    std::map<evmc::bytes32, evmc::bytes32> storage;
    std::map<evmc::bytes32, evmc::bytes32> transient_storage;

    virtual evmc::bytes32 code_hash() const
    {
        // Extremely dumb "hash" function.
        evmc::bytes32 ret{};
        for (const auto v : code)
            ret.bytes[v % sizeof(ret.bytes)] ^= v;
        return ret;
    }
};

using accounts = std::map<evmc::address, account>;

}  // namespace evmc

template<typename BlueprintFieldType>
class VMHost : public evmc::Host
{
public:
    VMHost() = default;
    explicit VMHost(evmc_tx_context& _tx_context, std::shared_ptr<nil::evm_assigner::assigner<BlueprintFieldType>> _assigner, const std::string& _target_circuit = "") noexcept
      : tx_context{_tx_context}, assigner{_assigner}, target_circuit{_target_circuit}
    {}

    VMHost(evmc_tx_context& _tx_context, evmc::accounts& _accounts, std::shared_ptr<nil::evm_assigner::assigner<BlueprintFieldType>> _assigner, const std::string& _target_circuit = "") noexcept
      : accounts{_accounts}, tx_context{_tx_context}, assigner{_assigner}, target_circuit{_target_circuit}
    {}

    bool account_exists(const evmc::address& addr) noexcept final
    {
        auto account_iter = get_account(addr);
        return account_iter != accounts.end();
    }

    evmc::bytes32 get_storage(const evmc::address& addr,
                              const evmc::bytes32& key) noexcept final
    {
        auto account_iter = get_account(addr);
        if (account_iter == accounts.end()) {
            return {};
        }
        const auto storage_iter = account_iter->second.storage.find(key);
        if (storage_iter != account_iter->second.storage.end()) {
            return storage_iter->second;
        }
        return {};
    }

    evmc_storage_status set_storage(const evmc::address& addr,
                                    const evmc::bytes32& key,
                                    const evmc::bytes32& value) noexcept final
    {
        auto account_iter = get_account(addr);
        if (account_iter == accounts.end()) {
            return EVMC_STORAGE_DELETED;
        }

        auto storage_iter = account_iter->second.storage.find(key);
        if (storage_iter == account_iter->second.storage.end()) {
            return EVMC_STORAGE_DELETED;
        }
        auto prev_value = storage_iter->second;
        storage_iter->second = value;

        return (prev_value == value) ? EVMC_STORAGE_ASSIGNED : EVMC_STORAGE_MODIFIED;
    }

    evmc::uint256be get_balance(const evmc::address& addr) noexcept final
    {
        auto account_iter = get_account(addr);
        if (account_iter == accounts.end()) {
            return {};
        }
        return account_iter->second.balance;
    }

    size_t get_code_size(const evmc::address& addr) noexcept final
    {
        auto account_iter = get_account(addr);
        if (account_iter == accounts.end()) {
            return 0;
        }
        return account_iter->second.code.size();
    }

    evmc::bytes32 get_code_hash(const evmc::address& addr) noexcept final
    {
        auto account_iter = get_account(addr);
        if (account_iter == accounts.end()) {
            return {};
        }
        return account_iter->second.code_hash();
    }

    size_t copy_code(const evmc::address& addr,
                     size_t code_offset,
                     uint8_t* buffer_data,
                     size_t buffer_size) noexcept final
    {
        auto account_iter = get_account(addr);
        if (account_iter == accounts.end()) {
            return 0;
        }

        const auto& code = account_iter->second.code;

        if (code_offset >= code.size())
            return 0;

        const auto n = std::min(buffer_size, code.size() - code_offset);

        if (n > 0)
            std::copy_n(&code[code_offset], n, buffer_data);
        return n;
    }

    bool selfdestruct(const evmc::address& addr, const evmc::address& beneficiary) noexcept final
    {
        (void)addr;
        (void)beneficiary;
        return false;
    }

    evmc::Result call(const evmc_message& msg) noexcept final
    {
        switch (msg.kind)
        {
        case EVMC_CALL:
        case EVMC_CALLCODE:
        case EVMC_DELEGATECALL:
            return handle_call(msg);
        case EVMC_CREATE:
        case EVMC_CREATE2:
            return handle_create(msg);
        default:
            // Unexpected opcode
            return evmc::Result{EVMC_INTERNAL_ERROR};
        }
    }

    evmc_tx_context get_tx_context() const noexcept final { return tx_context; }

    // NOLINTNEXTLINE(bugprone-exception-escape)
    evmc::bytes32 get_block_hash(int64_t number) const noexcept final
    {
        const int64_t current_block_number = get_tx_context().block_number;

        return (number < current_block_number && number >= current_block_number - 256) ?
                   0xb10c8a5fb10c8a5fb10c8a5fb10c8a5fb10c8a5fb10c8a5fb10c8a5fb10c8a5f_bytes32 :
                   0x0000000000000000000000000000000000000000000000000000000000000000_bytes32;
    }

    void emit_log(const evmc::address& addr,
                  const uint8_t* data,
                  size_t data_size,
                  const evmc::bytes32 topics[],
                  size_t topics_count) noexcept final
    {
        (void)addr;
        (void)data;
        (void)data_size;
        (void)topics;
        (void)topics_count;
    }

    evmc_access_status access_account(const evmc::address& addr) noexcept final
    {
        (void)addr;
        return EVMC_ACCESS_COLD;
    }

    evmc_access_status access_storage(const evmc::address& addr,
                                      const evmc::bytes32& key) noexcept final
    {
        (void)addr;
        (void)key;
        return EVMC_ACCESS_COLD;
    }

    evmc::bytes32 get_transient_storage(const evmc::address& addr,
                                        const evmc::bytes32& key) noexcept override
    {
        auto account_iter = get_account(addr);
        if (account_iter == accounts.end()) {
            return {};
        }

        const auto transient_storage_iter = account_iter->second.transient_storage.find(key);
        if (transient_storage_iter != account_iter->second.transient_storage.end())
            return transient_storage_iter->second;
        return {};
    }

    void set_transient_storage(const evmc::address& addr,
                               const evmc::bytes32& key,
                               const evmc::bytes32& value) noexcept override
    {
        auto account_iter = get_account(addr);
        if (account_iter == accounts.end()) {
            return;
        }
        account_iter->second.transient_storage[key] = value;
    }

protected:
    evmc::accounts accounts;

    virtual evmc::accounts::iterator get_account(const evmc::address& addr) noexcept {
        return accounts.find(addr);
    }
private:
    evmc_tx_context tx_context{};
    std::shared_ptr<nil::evm_assigner::assigner<BlueprintFieldType>> assigner;
    std::string target_circuit;

    evmc::Result handle_call(const evmc_message& msg) {
        auto sender_iter = get_account(msg.sender);
        if (sender_iter == accounts.end())
        {
            // Sender account does not exist
            return evmc::Result{EVMC_INTERNAL_ERROR};
        }
        auto &sender_acc = sender_iter->second;
        auto account_iter = get_account(msg.code_address);
        if (account_iter == accounts.end())
        {
            // Create account
            accounts[msg.code_address] = {};
        }
        auto& acc = accounts[msg.code_address];
        if (msg.kind == EVMC_CALL) {
            auto value_to_transfer = nil::evm_assigner::zkevm_word<BlueprintFieldType>(msg.value);
            auto balance = nil::evm_assigner::zkevm_word<BlueprintFieldType>(sender_acc.balance);
            // Balance was already checked in evmone, so simply adjust it
            sender_acc.balance = (balance - value_to_transfer).to_uint256be();
            acc.balance = (value_to_transfer + nil::evm_assigner::zkevm_word<BlueprintFieldType>(acc.balance)).to_uint256be();
        }
        if (acc.code.empty())
        {
            return evmc::Result{EVMC_SUCCESS, msg.gas, 0, msg.input_data, msg.input_size};
        }
        // TODO: handle precompiled contracts
        evmc::Result res = nil::evm_assigner::evaluate<BlueprintFieldType>(&get_interface(), to_context(),
                                                                        EVMC_LATEST_STABLE_REVISION, &msg, acc.code.data(), acc.code.size(), assigner, target_circuit);
        return res;
    }

    evmc::Result handle_create(const evmc_message& msg) {
        evmc::address new_contract_address = calculate_address(msg);
        if (get_account(new_contract_address) != accounts.end())
        {
            // Address collision
            return evmc::Result{EVMC_FAILURE};
        }
        accounts[new_contract_address] = {};
        if (msg.input_size == 0)
        {
            return evmc::Result{EVMC_SUCCESS, msg.gas, 0, new_contract_address};
        }
        evmc_message init_msg(msg);
        init_msg.kind = EVMC_CALL;
        init_msg.recipient = new_contract_address;
        init_msg.sender = msg.sender;
        init_msg.input_size = 0;
        evmc::Result res = nil::evm_assigner::evaluate<BlueprintFieldType>(&get_interface(), to_context(),
                                                                        EVMC_LATEST_STABLE_REVISION, &init_msg, msg.input_data, msg.input_size, assigner, target_circuit);
        if (res.status_code == EVMC_SUCCESS)
        {
            accounts[new_contract_address].code =
                std::vector<uint8_t>(res.output_data, res.output_data + res.output_size);
        }
        res.create_address = new_contract_address;
        return res;
    }

    evmc::address calculate_address(const evmc_message& msg) {
        // TODO: Implement for CREATE opcode, for now the result is only correct for CREATE2
        // CREATE requires rlp encoding
        auto seed = nil::evm_assigner::zkevm_word<BlueprintFieldType>(msg.create2_salt);
        auto hash = nil::evm_assigner::zkevm_word<BlueprintFieldType>(ethash::keccak256(msg.input_data, msg.input_size));
        auto sender = nil::evm_assigner::zkevm_word<BlueprintFieldType>(msg.sender);
        auto sum = nil::evm_assigner::zkevm_word<BlueprintFieldType>(0xff) + seed + hash + sender;
        auto rehash = ethash::keccak256(reinterpret_cast<const uint8_t*>(&sum.get_value()),
            nil::evm_assigner::zkevm_word<BlueprintFieldType>::size);
        // Result address is the last 20 bytes of the hash
        evmc::address res;
        std::memcpy(res.bytes, rehash.bytes + 12, 20);
        return res;
    }
};

template<typename BlueprintFieldType>
evmc_host_context* vm_host_create_context(evmc_tx_context tx_context, std::shared_ptr<nil::evm_assigner::assigner<BlueprintFieldType>> assigner) {
    auto host = new VMHost<BlueprintFieldType>{tx_context, assigner};
    return host->to_context();
}

template<typename BlueprintFieldType>
void vm_host_destroy_context(evmc_host_context* context) {
     delete evmc::Host::from_context<VMHost<BlueprintFieldType>>(context);
}


#endif  // EVM_ASSIGNER_LIB_ASSIGNER_INCLUDE_VM_HOST_H_
