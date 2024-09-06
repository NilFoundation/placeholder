#include "output_artifacts.hpp"

#include <array>
#include <expected>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "boost/algorithm/string.hpp"
#include "boost/program_options.hpp"
#include "boost/regex.hpp"

Range Range::new_lower(std::size_t lower_) {
    Range r;
    r.lower = lower_;
    return r;
}

Range Range::new_upper(std::size_t upper_) {
    Range r;
    r.upper = upper_;
    return r;
}

std::expected<Range, std::string> Range::parse(const std::string& s) {
    boost::smatch match_results;
    if (boost::regex_match(s, match_results, boost::regex("^\\d+$"))) {
        return Range(std::stoi(match_results.str()));
    } else if (boost::regex_match(s, match_results, boost::regex("^(\\d+)-$"))) {
        return Range::new_lower(std::stoi(match_results[1].str()));
    } else if (boost::regex_match(s, match_results, boost::regex("^-(\\d+)$"))) {
        return Range::new_upper(std::stoi(match_results[1].str()));
    } else if (boost::regex_match(s, match_results, boost::regex("^(\\d+)-(\\d+)$"))) {
        std::size_t lower = std::stoi(match_results[1].str());
        std::size_t upper = std::stoi(match_results[2].str());
        if (upper < lower) {
            return std::unexpected(std::string("Upper index is less than lower index: ") + s);
        }
        return Range(lower, upper);
    }
    return std::unexpected(std::string("Bad index range: ") + s);
}

std::string Range::to_string() const {
    std::string res;
    res += std::to_string(lower);
    if (upper.has_value()) {
        if (upper.value() != lower) {
            res += "-";
            res += std::to_string(upper.value());
        }
    } else {
        res += "-";
    }
    return res;
}

std::expected<Range::ConcreteRange, std::string> Range::concrete_range(int max) const {
    int upper_ = upper.value_or(max);
    if (upper_ > max || upper_ < 0 || lower > upper_) {
        return std::unexpected("index out of bounds");
    }
    return std::make_pair(lower, upper_);
}

std::expected<Ranges, std::string> Ranges::parse(const std::string& s) {
    // TODO: this should probably be implemented cleaner, but I really struggled with
    // repeated captures in Boost Regex and wasn't able to complete that approach

    std::stringstream ss(s);
    std::string token;
    Ranges ranges;
    char delim = ',';
    while (std::getline(ss, token, delim)) {
        if (!token.empty()) {
            auto maybe_range = Range::parse(token);
            if (!maybe_range.has_value()) {
                return std::unexpected(maybe_range.error());
            }
            ranges.push_back(maybe_range.value());
        }
    }
    return ranges;
}

std::string Ranges::to_string() const {
    std::vector<std::string> ranges;
    for (const auto& range : *this) {
        ranges.push_back(range.to_string());
    }
    return boost::algorithm::join(ranges, ",");
}

std::expected<Ranges::ConcreteRanges, std::string> Ranges::concrete_ranges(int max) const {
    ConcreteRanges ranges;
    for (const auto& range : *this) {
        auto maybe_concrete_range = range.concrete_range(max);
        if (!maybe_concrete_range.has_value()) {
            return std::unexpected(maybe_concrete_range.error());
        }
        ranges.push_back(maybe_concrete_range.value());
    }
    return ranges;
}

/// @brief Map column type lable to its index in `parse_columns` return value.
const std::map<std::string, std::size_t> col2idx{
    {"witness", 0}, {"public_input", 1}, {"constant", 2}, {"selector", 3}};

/// @brief Parse columns (order is witness, public input, constant, selector) options and also check
/// that there are duplicated ones. May return error as string if parse fails.
std::expected<std::array<Ranges, 4>, std::string> parse_columns(
    const std::vector<std::string>& columns) {
    std::array<Ranges, 4> result = {Ranges(), Ranges(), Ranges(), Ranges()};

    // Mask of completed column ranges: completed[i] is set to true if corresponding column range
    // was parsed from input. Used to check whether there are duplicated columns.
    std::array<bool, 4> completed = {false, false, false, false};

    for (const auto& column : columns) {
        boost::regex pattern("^(witness|public_input|constant|selector)(.+)$");
        boost::smatch match_results;
        if (boost::regex_match(column, match_results, pattern)) {
            std::string column_type = match_results[1].str();
            std::size_t column_idx = col2idx.at(column_type);
            if (completed[column_idx]) {
                return std::unexpected(std::string("Duplicate columns option: " + column));
            }
            auto maybe_ranges = Ranges::parse(match_results[2].str());
            if (!maybe_ranges.has_value()) {
                return std::unexpected(maybe_ranges.error());
            }
            result[column_idx] = maybe_ranges.value();
            completed[column_idx] = true;
        } else {
            return std::unexpected(std::string("Bad columns option: " + column));
        }
    }
    return result;
}

std::string OutputArtifacts::tables_to_string() const {
    std::string result;
    for (const auto& table : tables) {
        result += " " + std::to_string((int)table) + " ";
    }
    return result;
}

std::expected<std::vector<nil::evm_assigner::zkevm_circuit>, std::string>
OutputArtifacts::parse_tables(const std::vector<std::string>& s) {
    std::vector<nil::evm_assigner::zkevm_circuit> result;
    for (const auto& table_name : s) {
        auto it = nil::evm_assigner::zkevm_circuits_map.find(table_name);
        if (it != nil::evm_assigner::zkevm_circuits_map.end()) {
            result.push_back(it->second);
        } else {
            return std::unexpected(std::string("Unknown table name " + table_name));
        }
    }
    return result;
}

std::expected<OutputArtifacts, std::string> OutputArtifacts::from_program_options(
    boost::program_options::variables_map vm) {
    OutputArtifacts artifacts;
    artifacts.basename = vm["output-text"].as<std::string>();

    if (vm.count("tables")) {
        auto maybe_tables = parse_tables(vm["tables"].as<std::vector<std::string>>());
        if (!maybe_tables.has_value()) {
            return std::unexpected(maybe_tables.error());
        }
        artifacts.tables = maybe_tables.value();
    }

    if (vm.count("rows")) {
        auto maybe_rows = Ranges::parse(vm["rows"].as<std::string>());
        if (!maybe_rows.has_value()) {
            return std::unexpected(maybe_rows.error());
        }
        artifacts.rows = maybe_rows.value();
    }

    if (vm.count("columns")) {
        auto maybe_columns = parse_columns(vm["columns"].as<std::vector<std::string>>());
        if (!maybe_columns.has_value()) {
            return std::unexpected(maybe_columns.error());
        }
        artifacts.witness_columns = maybe_columns.value()[0];
        artifacts.public_input_columns = maybe_columns.value()[1];
        artifacts.constant_columns = maybe_columns.value()[2];
        artifacts.selector_columns = maybe_columns.value()[3];
    }

    return artifacts;
}
