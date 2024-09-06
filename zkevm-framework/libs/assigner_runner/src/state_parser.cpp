#include "zkevm_framework/assigner_runner/state_parser.hpp"

#include <boost/algorithm/hex.hpp>
#include <boost/endian.hpp>
#include <boost/endian/conversion.hpp>
#include <cstring>
#include <fstream>

#include "state_schema.def"
#include "zkevm_framework/assigner_runner/utils.hpp"
#include "zkevm_framework/core/types/account.hpp"
#include "zkevm_framework/json_helpers/json_helpers.hpp"

static std::optional<std::string> handle_code(std::string &code_str, evmc::account &account) {
    if (auto parse_err = json_helpers::to_bytes(code_str, account.code)) {
        return "Parsing get code response is failed: " + parse_err.value();
    }
    return {};
}

static std::optional<std::string> handle_storage(const boost::json::array &storage_json,
                                                 evmc::account &account) {
    auto &storage = account.storage;
    for (const auto &item : storage_json) {
        const boost::json::object &storage_elem = item.as_object();
        if (!storage_elem.contains("Key") || !storage_elem.contains("Val")) {
            return "Invalid storage in the JSON";
        }
        const auto key_str = storage_elem.at("Key").as_string().c_str();
        const auto val_str = storage_elem.at("Val").as_string().c_str();
        evmc::bytes32 key = to_uint256be(intx::from_string<intx::uint256>(key_str));
        evmc::bytes32 value = to_uint256be(intx::from_string<intx::uint256>(val_str));
        storage.emplace(key, value);
    }
    return {};
}

static std::optional<std::string> handle_account(std::string &contract_str, evmc::account &account,
                                                 evmc::address &address) {
    core::types::SmartContract contract;
    std::vector<std::byte> contract_data;
    auto parse_err = json_helpers::to_std_bytes(contract_str, contract_data);
    if (parse_err) {
        return "Parse contract failed: \n\t" + parse_err.value();
    }
    contract = ssz::deserialize<core::types::SmartContract>(contract_data);
    account.balance = to_uint256be(contract.m_balance.m_value);
    address = to_evmc_address(contract.m_address);
    return {};
}

std::optional<std::string> init_account_storage(evmc::accounts &account_storage,
                                                std::istream &config) {
    auto config_json = json_helpers::parse_json(config);
    if (!config_json) {
        return "Error while parsing state config file: " + config_json.error();
    }
    std::stringstream schema_stream;
    schema_stream << state_schema;
    auto schema_json = json_helpers::parse_json(schema_stream);
    if (!schema_json) {
        std::cerr << "Wrong schema" << std::endl;
        return "Error while parsing state schema: " + schema_json.error();
    }
    auto validation_err = json_helpers::validate_json(schema_json.value(), config_json.value());
    if (validation_err) {
        return "Config file validation failed: \n\t" + validation_err.value();
    }
    const auto &account_array = config_json->as_object().at("accounts").as_array();
    for (const auto &item : account_array) {
        const boost::json::object &account_json = item.as_object();
        evmc::account account;
        evmc::address account_address;
        std::string code_str = account_json.at("code").as_string().c_str();
        auto parse_err = handle_code(code_str, account);
        if (parse_err) {
            return "Parse code failed: \n\t" + parse_err.value();
        }
        std::string contract_str = account_json.at("contract").as_string().c_str();
        parse_err = handle_account(contract_str, account, account_address);
        if (parse_err) {
            return "Parse account failed: \n\t" + parse_err.value();
        }
        parse_err = handle_storage(account_json.at("storage").as_array(), account);
        if (parse_err) {
            return "Parse storage failed: \n\t" + parse_err.value();
        }
        account_storage[account_address] = account;
    }
    return {};
}

std::optional<std::string> init_account_storage(evmc::accounts &account_storage,
                                                const std::string &account_storage_config_name) {
    std::ifstream asc_stream(account_storage_config_name);
    if (!asc_stream.is_open()) {
        return "Could not open the account storage config: '" + account_storage_config_name + "'";
    }
    return init_account_storage(account_storage, asc_stream);
}

std::optional<std::string> load_account_with_storage(evmc::account &account,
                                                     std::istream &account_data) {
    auto account_json = json_helpers::parse_json(account_data);
    if (!account_json) {
        return "Error while parsing accounts data: " + account_json.error();
    }
    if (!account_json.value().as_object().contains("result") ||
        !account_json.value().at("result").as_object().contains("code")) {
        return "Account code is not found in the JSON";
    }
    std::string code_str = account_json.value().at("result").at("code").as_string().c_str();
    auto parse_err = handle_code(code_str, account);
    if (parse_err) {
        return "Parse code failed: \n\t" + parse_err.value();
    }

    if (!account_json.value().as_object().contains("result") ||
        !account_json.value().at("result").as_object().contains("contract")) {
        return "Contract data is not found in the JSON";
    }
    std::string contract_str = account_json.value().at("result").at("contract").as_string().c_str();
    evmc::address address;
    parse_err = handle_account(contract_str, account, address);
    if (parse_err) {
        return "Parse account failed: \n\t" + parse_err.value();
    }

    if (!account_json.value().as_object().contains("result") ||
        !account_json.value().at("result").as_object().contains("storage")) {
        return "Storage is not found in the JSON";
    }
    parse_err = handle_storage(account_json.value().at("result").at("storage").as_array(), account);
    if (parse_err) {
        return "Parse account failed: \n\t" + parse_err.value();
    }
    return {};
}
