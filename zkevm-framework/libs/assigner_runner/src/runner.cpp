#include "zkevm_framework/assigner_runner/runner.hpp"

#include <assigner.hpp>
#include <nil/blueprint/zkevm/bytecode.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <optional>
#include <sstream>
#include <string>

#include "zkevm_framework/assigner_runner/block_parser.hpp"
#include "zkevm_framework/assigner_runner/state_parser.hpp"
#include "zkevm_framework/assigner_runner/utils.hpp"
#include "zkevm_framework/assigner_runner/write_assignments.hpp"

template<typename BlueprintFieldType>
std::optional<std::string> single_thread_runner<BlueprintFieldType>::run(
    const std::string& assignment_table_file_name,
    const std::optional<OutputArtifacts>& artifacts) {
    fill_assignments();

    BOOST_LOG_TRIVIAL(debug) << "print assignment tables " << m_assignments.size() << "\n";

    using Endianness = nil::marshalling::option::big_endian;

    auto err = write_binary_assignments<Endianness, ArithmetizationType, BlueprintFieldType>(
        m_assignments, assignment_table_file_name);
    if (err) {
        return err;
    }

    if (artifacts.has_value()) {
        std::optional<std::string> err =
            write_output_artifacts<Endianness, ArithmetizationType, BlueprintFieldType>(
                m_assignments, artifacts.value());
        if (err) {
            return err;
        }
    }

    return {};
}

template<typename BlueprintFieldType>
std::optional<std::string> single_thread_runner<BlueprintFieldType>::extract_block_with_messages(
    const std::string& blockHash, const std::string& block_file_name) {
    if (!block_file_name.empty()) {
        BOOST_LOG_TRIVIAL(debug) << "Try load input block from file " << block_file_name << "\n";
        std::ifstream block_data(block_file_name);
        if (!block_data.is_open()) {
            return "Could not open the input block file: '" + block_file_name + "'";
        }
        const auto err = load_block_with_messages(m_current_block, m_input_messages, block_data);
        if (err) {
            return err;
        }
    } else {
        BOOST_LOG_TRIVIAL(debug) << "Try get input block from RPC\n";
        std::stringstream block_data;
        auto err = m_extractor.get_block_with_messages(blockHash, block_data);
        if (err) {
            return err;
        }
        err = load_raw_block_with_messages(m_current_block, m_input_messages, block_data);
        if (err) {
            return err;
        }
    }
    return {};
}

template<typename BlueprintFieldType>
std::optional<std::string> single_thread_runner<BlueprintFieldType>::extract_accounts_with_storage(
    const std::string& account_storage_config_name) {
    if (!account_storage_config_name.empty()) {
        BOOST_LOG_TRIVIAL(debug) << "Try load account storage from file "
                                 << account_storage_config_name << "\n";
        auto init_err = init_account_storage(m_account_storage, account_storage_config_name);
        if (init_err) {
            return init_err.value();
        }
    }
    return {};
}

template<typename BlueprintFieldType>
std::optional<std::string> single_thread_runner<BlueprintFieldType>::fill_assignments() {
    std::ostringstream error;

    // create assigner instance
    auto assigner_ptr =
        std::make_shared<nil::evm_assigner::assigner<BlueprintFieldType>>(m_assignments);

    evmc_revision rev = {};

    BOOST_LOG_TRIVIAL(debug)
        << "Input Block:\n"
        << "  block number = " << m_current_block.m_id << "\n"
        << "  prev m_current_block = " << to_str(m_current_block.m_prev_block) << "\n"
        << "  smart contract root = " << to_str(m_current_block.m_smart_contracts_root) << "\n"
        << "  in message root = " << to_str(m_current_block.m_in_messages_root) << "\n"
        << "  out message root = " << to_str(m_current_block.m_out_messages_root) << "\n"
        << "  out message num = " << m_current_block.m_out_messages_num << "\n"
        << "  receipt root = " << to_str(m_current_block.m_receipts_root) << "\n"
        << "  child block root hash = " << to_str(m_current_block.m_child_blocks_root_hash) << "\n"
        << "  master chain hash = " << to_str(m_current_block.m_master_chain_hash) << "\n"
        << "  timestamp = " << m_current_block.m_timestamp << "\n"
        << "  gas price = " << m_current_block.m_gasPrice.m_value[0] << "\n"
        << "\n";

    if (m_log_level <= boost::log::trivial::debug) {
        BOOST_LOG_TRIVIAL(debug) << "Account storage initialized with " << m_account_storage.size()
                                 << " accounts: \n";
        for (const auto& [addr, acc] : m_account_storage) {
            BOOST_LOG_TRIVIAL(debug) << "\tAddress: " << to_str(addr) << '\n'
                                     << "\tBalance: " << to_str(acc.balance) << '\n';
            if (!acc.code.empty()) {
                BOOST_LOG_TRIVIAL(debug) << "\tCode: " << to_str(acc.code);
            }
            if (!acc.storage.empty()) {
                BOOST_LOG_TRIVIAL(debug) << "\tStorage:\n";
                for (const auto& [key, value] : acc.storage) {
                    BOOST_LOG_TRIVIAL(debug)
                        << "[ " << to_str(key) << " ] = " << to_str(value) << "\n";
                }
            }
            BOOST_LOG_TRIVIAL(debug) << std::endl;
        }
    }

    evmc_address zero_address{0};
    evmc::uint256be zero_value{0};
    // transaction and block data for execution
    struct evmc_tx_context tx_context = {
        // per transaction value
        .tx_gas_price = {{0}}, /**< The transaction gas price. */

        // per account block value
        .tx_origin = zero_address, /**< The transaction origin account. */

        .block_coinbase = zero_address,                /**< The miner of the block. */
        .block_number = (int64_t)m_current_block.m_id, /**< The block number. */
        .block_timestamp =
            (int64_t)m_current_block.m_timestamp, /**< The m_current_block timestamp. */
        .block_gas_limit = 0,                     /**< The m_current_block gas limit. */
        .block_prev_randao = zero_value,
        .chain_id = zero_value, /**< The m_current_blockchain's ChainID. */
        .block_base_fee =
            zero_value, /**< The m_current_block base fee per gas (EIP-1559, EIP-3198). */
        .blob_base_fee = zero_value, /**< The blob base fee (EIP-7516). */
        .blob_hashes = nullptr,      /**< The array of blob hashes (EIP-4844). */
        .blob_hashes_count = 0,      /**< The number of blob hashes (EIP-4844). */
    };

    // default interface for access to the host
    const struct evmc_host_interface* host_interface = &evmc::Host::get_interface();

    // TODO support multi target circuits in evm-assigner
    std::string target_circuit = m_target_circuits.size() > 0 ? m_target_circuits[0] : "";
    ExtVMHost host(m_extractor, to_str(m_current_block.m_prev_block), tx_context, m_account_storage,
                   assigner_ptr, target_circuit);

    struct evmc_host_context* ctx = host.to_context();

    // run EVM per transactions
    for (const auto& input_msg : m_input_messages) {
        const evmc_address origin_addr = to_evmc_address(input_msg.m_from);
        tx_context.tx_origin = origin_addr;

        BOOST_LOG_TRIVIAL(debug) << "process CALL message\n  from " << to_str(input_msg.m_from)
                                 << " to " << to_str(input_msg.m_to) << "\n";

        if (!input_msg.m_flags.test(std::size_t(core::types::MessageKind::Internal)) &&
            input_msg.m_flags.test(std::size_t(core::types::MessageKind::Deploy))) {
            BOOST_LOG_TRIVIAL(debug) << "skip transaction " << input_msg.m_seqno << "("
                                     << to_str(input_msg.m_flags) << "). Nothing to do\n";
            continue;
        }

        // set tansaction related fields
        // tx_context.tx_gas_price =
        // intx::be::store<evmc::uint256be>(input_msg.m_gas_price.m_value);
        auto msg_calldata = input_msg.m_data;
        std::vector<uint8_t> calldata(msg_calldata.size());
        size_t count = 0;
        std::for_each(msg_calldata.begin(), msg_calldata.end(),
                      [&count, &calldata](const std::byte& v) {
                          calldata[count] = to_integer<uint8_t>(v);
                          count++;
                      });
        if (count != calldata.size()) {
            error << "Failed copy calldata: expected size = " << calldata.size()
                  << ", real = " << count;
            return error.str();
        }

        // init messge associated with transaction
        const evmc_uint256be value = to_uint256be(input_msg.m_value.m_value);
        const evmc_address sender_addr = to_evmc_address(input_msg.m_from);
        const evmc_address recipient_addr = to_evmc_address(input_msg.m_to);
        const int64_t gas =
            (input_msg.m_feeCredit.m_value / (m_current_block.m_gasPrice.m_value[0]))[0];
        const uint8_t input[] = "";
        struct evmc_message msg = {.kind = evmc_msg_kind(input_msg.m_flags),
                                   .flags = uint32_t{0},
                                   .depth = 0,
                                   .gas = gas,
                                   .recipient = recipient_addr,
                                   .sender = sender_addr,
                                   .input_data = calldata.data(),
                                   .input_size = calldata.size(),
                                   .value = value,
                                   .create2_salt = {0},
                                   .code_address = origin_addr};

        std::vector<uint8_t> contract_code;
        contract_code.resize(host.get_code_size(recipient_addr));
        const auto copy_size =
            host.copy_code(recipient_addr, 0, contract_code.data(), contract_code.size());
        if (copy_size != contract_code.size()) {
            error << "Failed copy contract code: expected size = " << contract_code.size()
                  << ", real = " << copy_size;
            return error.str();
        }

        BOOST_LOG_TRIVIAL(debug) << "evaluate transaction\n"
                                 << "  type = " << to_str(input_msg.m_flags) << "\n"
                                 << "  value = " << input_msg.m_value.m_value[0] << "\n"
                                 << "  gas price = " << m_current_block.m_gasPrice.m_value[0]
                                 << "\n"
                                 << "  free credit = " << input_msg.m_feeCredit.m_value[0] << "\n"
                                 << "  gas = " << gas << "\n"
                                 << "  code size = " << contract_code.size() << "\n";

        auto res = nil::evm_assigner::evaluate(host_interface, ctx, rev, &msg, contract_code.data(),
                                               contract_code.size(), assigner_ptr, target_circuit);

        BOOST_LOG_TRIVIAL(debug) << "evaluate result = " << to_str(res.status_code) << "\n";
        if (res.status_code == EVMC_SUCCESS) {
            BOOST_LOG_TRIVIAL(debug) << "create_address = " << to_str(res.create_address) << "\n"
                                     << "gas_left = " << res.gas_left << "\n"
                                     << "gas_refund = " << res.gas_refund << "\n"
                                     << "output size = " << res.output_size << "\n";
        }
    }
    return {};
}

// Instantiate runner for required field types

using pallas_base_field = typename nil::crypto3::algebra::curves::pallas::base_field_type;
template class single_thread_runner<pallas_base_field>;

using bls_base_field = typename nil::crypto3::algebra::fields::bls12_base_field<381>;
template class single_thread_runner<bls_base_field>;
