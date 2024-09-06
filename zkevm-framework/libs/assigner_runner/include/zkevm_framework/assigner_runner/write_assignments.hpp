/**
 * @file write_assignments.hpp
 *
 * @brief This file defines functions for writing assignment tables in binary mode.
 */

#ifndef ZKEMV_FRAMEWORK_LIBS_ASSIGNER_RUNNER_INCLUDE_ZKEVM_FRAMEWORK_ASSIGNER_RUNNER_WRITE_ASSIGNMENTS_HPP_
#define ZKEMV_FRAMEWORK_LIBS_ASSIGNER_RUNNER_INCLUDE_ZKEVM_FRAMEWORK_ASSIGNER_RUNNER_WRITE_ASSIGNMENTS_HPP_

#include <array>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "nil/blueprint/blueprint/plonk/assignment.hpp"
#include "nil/crypto3/marshalling/algebra/types/field_element.hpp"
#include "nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp"
#include "nil/marshalling/types/integral.hpp"
#include "output_artifacts.hpp"

/**
 * @brief Write size_t serialized as nil::marshalling::types::integral into output stream.
 */
template<typename Endianness>
void write_size_t(std::size_t input, std::ostream& out) {
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    auto integer_container = nil::marshalling::types::integral<TTypeBase, std::size_t>(input);
    std::array<std::uint8_t, integer_container.length()> char_array{};
    auto write_iter = char_array.begin();
    assert(integer_container.write(write_iter, char_array.size()) ==
           nil::marshalling::status_type::success);
    out.write(reinterpret_cast<char*>(char_array.data()), char_array.size());
}

/**
 * @brief Write zero value serialized as nil::crypto3::marshalling::types::field_element into output
 * stream.
 */
template<typename Endianness, typename ArithmetizationType>
inline void write_zero_field(std::ostream& out) {
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using AssignmentTableType = nil::blueprint::assignment<ArithmetizationType>;
    using field_element = nil::crypto3::marshalling::types::field_element<
        TTypeBase, typename AssignmentTableType::field_type::value_type>;
    std::array<std::uint8_t, field_element().length()> array{};
    out.write(reinterpret_cast<char*>(array.data()), array.size());
}

/**
 * @brief Write field element into output stream.
 */
template<typename Endianness, typename ArithmetizationType>
void write_field(
    const typename nil::blueprint::assignment<ArithmetizationType>::field_type::value_type& input,
    std::ostream& out) {
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using AssignmentTableType = nil::blueprint::assignment<ArithmetizationType>;
    auto field_container = nil::crypto3::marshalling::types::field_element<
        TTypeBase, typename AssignmentTableType::field_type::value_type>(input);
    std::array<std::uint8_t, field_container.length()> char_array{};
    auto write_iter = char_array.begin();
    assert(field_container.write(write_iter, char_array.size()) ==
           nil::marshalling::status_type::success);
    out.write(reinterpret_cast<char*>(char_array.data()), char_array.size());
}

/**
 * @brief Write table column to output stream padding with zeroes up to fixed number of values.
 */
template<typename Endianness, typename ArithmetizationType, typename ColumnType>
void write_vector_value(const std::size_t padded_rows_amount, const ColumnType& table_col,
                        std::ostream& out) {
    for (std::size_t i = 0; i < padded_rows_amount; i++) {
        if (i < table_col.size()) {
            write_field<Endianness, ArithmetizationType>(table_col[i], out);
        } else {
            write_zero_field<Endianness, ArithmetizationType>(out);
        }
    }
}

/**
 * @brief Write assignment table serialized into binary to output stream.
 */
template<typename Endianness, typename ArithmetizationType, typename BlueprintFieldType>
void write_binary_assignment(const nil::blueprint::assignment<ArithmetizationType>& table,
                             std::ostream& out) {
    std::uint32_t public_input_size = table.public_inputs_amount();
    std::uint32_t witness_size = table.witnesses_amount();
    std::uint32_t constant_size = table.constants_amount();
    std::uint32_t selector_size = table.selectors_amount();

    std::uint32_t max_public_inputs_size = 0;
    std::uint32_t max_constant_size = 0;
    std::uint32_t max_selector_size = 0;

    for (std::uint32_t i = 0; i < public_input_size; i++) {
        max_public_inputs_size =
            std::max(max_public_inputs_size, table.public_input_column_size(i));
    }

    std::uint32_t max_witness_size = 0;
    for (std::uint32_t i = 0; i < witness_size; i++) {
        max_witness_size = std::max(max_witness_size, table.witness_column_size(i));
    }
    for (std::uint32_t i = 0; i < constant_size; i++) {
        max_constant_size = std::max(max_constant_size, table.constant_column_size(i));
    }
    for (std::uint32_t i = 0; i < selector_size; i++) {
        max_selector_size = std::max(max_selector_size, table.selector_column_size(i));
    }
    std::uint32_t usable_rows_amount =
        std::max({max_witness_size, max_public_inputs_size, max_constant_size, max_selector_size});

    std::uint32_t padded_rows_amount = std::pow(2, std::ceil(std::log2(usable_rows_amount)));
    if (padded_rows_amount == usable_rows_amount) {
        padded_rows_amount *= 2;
    }
    if (padded_rows_amount < 8) {
        padded_rows_amount = 8;
    }

    using column_type = typename nil::crypto3::zk::snark::plonk_column<BlueprintFieldType>;

    write_size_t<Endianness>(witness_size, out);
    write_size_t<Endianness>(public_input_size, out);
    write_size_t<Endianness>(constant_size, out);
    write_size_t<Endianness>(selector_size, out);
    write_size_t<Endianness>(usable_rows_amount, out);
    write_size_t<Endianness>(padded_rows_amount, out);

    write_size_t<Endianness>(witness_size * padded_rows_amount, out);
    for (std::uint32_t i = 0; i < witness_size; i++) {
        write_vector_value<Endianness, ArithmetizationType, column_type>(padded_rows_amount,
                                                                         table.witness(i), out);
    }

    write_size_t<Endianness>(public_input_size * padded_rows_amount, out);
    for (std::uint32_t i = 0; i < public_input_size; i++) {
        write_vector_value<Endianness, ArithmetizationType, column_type>(
            padded_rows_amount, table.public_input(i), out);
    }

    write_size_t<Endianness>(constant_size * padded_rows_amount, out);
    for (std::uint32_t i = 0; i < constant_size; i++) {
        write_vector_value<Endianness, ArithmetizationType, column_type>(padded_rows_amount,
                                                                         table.constant(i), out);
    }

    write_size_t<Endianness>(selector_size * padded_rows_amount, out);
    for (std::uint32_t i = 0; i < selector_size; i++) {
        write_vector_value<Endianness, ArithmetizationType, column_type>(padded_rows_amount,
                                                                         table.selector(i), out);
    }
}

/**
 * @brief Write assignment tables serialized into binary to output file.
 */
template<typename Endianness, typename ArithmetizationType, typename BlueprintFieldType>
std::optional<std::string> write_binary_assignments(
    const std::unordered_map<nil::evm_assigner::zkevm_circuit,
                             nil::blueprint::assignment<ArithmetizationType>>& assignments,
    const std::string& basefilename) {
    for (const auto& assignment : assignments) {
        std::string filename = basefilename + "." + std::to_string(assignment.first);
        std::ofstream fout(filename, std::ios_base::binary | std::ios_base::out);
        if (!fout.is_open()) {
            return "Cannot open " + filename;
        }
        BOOST_LOG_TRIVIAL(debug) << "writing table " << assignment.first << " into file "
                                 << filename;
        write_binary_assignment<Endianness, ArithmetizationType, BlueprintFieldType>(
            assignment.second, fout);
        fout.close();
    }
    return {};
}

/**
 * @brief Write assignments into output artifacts according to thier description.
 */
template<typename Endianness, typename ArithmetizationType, typename BlueprintFieldType>
std::optional<std::string> write_output_artifacts(
    const std::unordered_map<nil::evm_assigner::zkevm_circuit,
                             nil::blueprint::assignment<ArithmetizationType>>& assignments,
    const OutputArtifacts& artifacts) {
    BOOST_LOG_TRIVIAL(debug) << "\n";
    BOOST_LOG_TRIVIAL(debug) << "writing output artifacts to " << artifacts.basename;
    BOOST_LOG_TRIVIAL(debug) << "tables to print: " << artifacts.tables_to_string();
    BOOST_LOG_TRIVIAL(debug) << "rows to print: " << artifacts.rows.to_string();
    BOOST_LOG_TRIVIAL(debug) << "witness columns to print: "
                             << artifacts.witness_columns.to_string();
    BOOST_LOG_TRIVIAL(debug) << "public input columns to print: "
                             << artifacts.public_input_columns.to_string();
    BOOST_LOG_TRIVIAL(debug) << "constant columns to print: "
                             << artifacts.constant_columns.to_string();
    BOOST_LOG_TRIVIAL(debug) << "selector columns to print: "
                             << artifacts.selector_columns.to_string();
    BOOST_LOG_TRIVIAL(debug) << "\n";

    if (assignments.empty()) {
        return {};
    }

    std::ostringstream error;

    for (const auto& i : artifacts.tables) {
        auto it = assignments.find(i);
        if (it == assignments.end()) {
            return "Can't find assignment table " + std::to_string(i);
        }
        auto assignment = it->second;

        Ranges::ConcreteRanges witnesses = {};
        if (!artifacts.witness_columns.empty()) {
            auto maybe_witnesses =
                artifacts.witness_columns.concrete_ranges((int)assignment.witnesses_amount() - 1);
            if (!maybe_witnesses.has_value()) {
                error << "Table " << i << ": Witnesses: " << maybe_witnesses.error();
                return error.str();
            }
            witnesses = maybe_witnesses.value();
        }

        Ranges::ConcreteRanges public_inputs = {};
        if (!artifacts.public_input_columns.empty()) {
            auto maybe_public_inputs = artifacts.public_input_columns.concrete_ranges(
                (int)assignment.public_inputs_amount() - 1);
            if (!maybe_public_inputs.has_value()) {
                error << "Table " << i << ": Public inputs: " << maybe_public_inputs.error();
                return error.str();
            }
            public_inputs = maybe_public_inputs.value();
        }

        Ranges::ConcreteRanges constants = {};
        if (!artifacts.constant_columns.empty()) {
            auto maybe_constants =
                artifacts.constant_columns.concrete_ranges((int)assignment.constants_amount() - 1);
            if (!maybe_constants.has_value()) {
                error << "Table " << i << ": Constants: " << maybe_constants.error();
                return error.str();
            }
            constants = maybe_constants.value();
        }

        Ranges::ConcreteRanges selectors = {};
        if (!artifacts.selector_columns.empty()) {
            auto maybe_selectors =
                artifacts.selector_columns.concrete_ranges((int)assignment.selectors_amount() - 1);
            if (!maybe_selectors.has_value()) {
                error << "Table " << i << ": Selectors: " << maybe_selectors.error();
                return error.str();
            }
            selectors = maybe_selectors.value();
        }

        Ranges::ConcreteRanges rows = {};
        if (!artifacts.rows.empty()) {
            auto maybe_rows = artifacts.rows.concrete_ranges((int)assignment.max_size() - 1);
            if (!maybe_rows.has_value()) {
                error << "Table " << i << ": Rows: " << maybe_rows.error();
                return error.str();
            }
            rows = maybe_rows.value();
        }

        if (artifacts.to_stdout()) {
            BOOST_LOG_TRIVIAL(debug) << "writing table " << i << " to stdout";

            assignment.export_table(std::cout, witnesses, public_inputs, constants, selectors,
                                    rows);
        } else {
            std::string filename = artifacts.basename + "." + std::to_string(i);
            BOOST_LOG_TRIVIAL(debug) << "writing table " << i << " into file " << filename;

            std::ofstream fout(filename, std::ios_base::binary | std::ios_base::out);
            if (!fout.is_open()) {
                error << "Cannot open " << filename;
                return error.str();
            }
            assignment.export_table(fout, witnesses, public_inputs, constants, selectors, rows);
            fout.close();
        }
        BOOST_LOG_TRIVIAL(debug) << "\n";
    }

    return {};
}

#endif  // ZKEMV_FRAMEWORK_LIBS_ASSIGNER_RUNNER_INCLUDE_ZKEVM_FRAMEWORK_ASSIGNER_RUNNER_WRITE_ASSIGNMENTS_HPP_
