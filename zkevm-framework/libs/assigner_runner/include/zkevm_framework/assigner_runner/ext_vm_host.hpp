#ifndef ZKEMV_FRAMEWORK_LIBS_ASSIGNER_RUNNER_INCLUDE_ZKEVM_FRAMEWORK_ASSIGNER_RUNNER_EXT_VM_HOST_HPP_
#define ZKEMV_FRAMEWORK_LIBS_ASSIGNER_RUNNER_INCLUDE_ZKEVM_FRAMEWORK_ASSIGNER_RUNNER_EXT_VM_HOST_HPP_

#include <vm_host.hpp>

#include "zkevm_framework/assigner_runner/state_parser.hpp"
#include "zkevm_framework/assigner_runner/utils.hpp"
#include "zkevm_framework/rpc/data_extractor.hpp"

template<typename BlueprintFieldType>
class ExtVMHost : public VMHost<BlueprintFieldType> {
  public:
    ExtVMHost(const data_extractor& extractor, const std::string& prevBlockHash)
        : VMHost<BlueprintFieldType>(), m_extractor(extractor), m_prevBlockHash(prevBlockHash){};

    explicit ExtVMHost(const data_extractor& extractor, const std::string& prevBlockHash,
                       evmc_tx_context& _tx_context,
                       std::shared_ptr<nil::evm_assigner::assigner<BlueprintFieldType>> _assigner,
                       const std::string& _target_circuit = "") noexcept
        : VMHost<BlueprintFieldType>(_tx_context, _assigner, _target_circuit),
          m_extractor(extractor),
          m_prevBlockHash(prevBlockHash) {}

    ExtVMHost(const data_extractor& extractor, const std::string& prevBlockHash,
              evmc_tx_context& _tx_context, evmc::accounts& _accounts,
              std::shared_ptr<nil::evm_assigner::assigner<BlueprintFieldType>> _assigner,
              const std::string& _target_circuit = "") noexcept
        : VMHost<BlueprintFieldType>(_tx_context, _accounts, _assigner, _target_circuit),
          m_extractor(extractor),
          m_prevBlockHash(prevBlockHash) {}

  protected:
    evmc::accounts::iterator get_account(const evmc::address& addr) noexcept override {
        const auto find_it = this->accounts.find(addr);
        if (find_it != this->accounts.end()) {
            return find_it;
        }
        BOOST_LOG_TRIVIAL(debug) << "Get account (" << to_str(addr) << ") via RPC";
        std::stringstream account_data;
        auto err =
            m_extractor.get_account_with_storage(to_str(addr), m_prevBlockHash, account_data);
        if (err) {
            BOOST_LOG_TRIVIAL(error) << "Failed getting account RPC request: " << err.value();
            return this->accounts.end();
        }
        evmc::account new_account;
        err = load_account_with_storage(new_account, account_data);
        if (err) {
            BOOST_LOG_TRIVIAL(error) << "Failed parsing account data: " << err.value();
            return this->accounts.end();
        }
        const auto insert_res = this->accounts.insert({addr, new_account});
        if (!insert_res.second) {
            BOOST_LOG_TRIVIAL(error) << "Failed add new account";
            return this->accounts.end();
        }
        return insert_res.first;
    }

  private:
    const data_extractor& m_extractor;
    const std::string m_prevBlockHash;
};

#endif  // ZKEMV_FRAMEWORK_LIBS_ASSIGNER_RUNNER_INCLUDE_ZKEVM_FRAMEWORK_ASSIGNER_RUNNER_EXT_VM_HOST_HPP_
