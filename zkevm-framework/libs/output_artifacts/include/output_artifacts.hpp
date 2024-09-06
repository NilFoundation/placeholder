/**
 * @file output_artifacts.hpp
 *
 * @brief This file defines functions and types for writing output artifacts.
 */

#ifndef ZKEMV_FRAMEWORK_LIBS_OUTPUT_ARTIFACTS_INCLUDE_OUTPUT_ARTIFACTS_HPP_
#define ZKEMV_FRAMEWORK_LIBS_OUTPUT_ARTIFACTS_INCLUDE_OUTPUT_ARTIFACTS_HPP_

#include <assigner.hpp>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

#include "boost/program_options.hpp"

/**
 * @brief Inclusive range of indexes: `[N-M]`. May be opened from both sides. If both bounds are not
 * set (lower is 0), it is "full" range of all possible values. Range is considered to be not empty.
 */
struct Range {
    /// @brief Lower bound.
    std::size_t lower;

    /// @brief Upper bound.
    std::optional<std::size_t> upper;

    /// @brief Default constructor creates full range.
    Range() : lower(0), upper(std::nullopt) {}

    /// @brief Constructor for single value range.
    Range(std::size_t single_value) : lower(single_value), upper(single_value) {}

    /// @brief Constructor for both sides bounded range.
    Range(std::size_t lower_, std::size_t upper_) : lower(lower_), upper(upper_) {}

    /// @brief Create new range with lower bound only.
    static Range new_lower(std::size_t lower_);

    /// @brief Create new range with upper bound only.
    static Range new_upper(std::size_t upper_);

    /**
     * @brief Parse range from string. Regular expression for string is: `N|N-|-N|N-N`, where N is
     * size_t. May return error as string if parse fails. Also fails if upper bound is less than
     * lower bound.
     */
    static std::expected<Range, std::string> parse(const std::string& s);

    /// @brief Get human-readable representation of range. Looks the same as parse() input.
    std::string to_string() const;

    /**
     * @brief Range with both bounds concretized to size_t: first is lower, second is upper.
     * These ranges are also inclusive.
     */
    using ConcreteRange = std::pair<std::size_t, std::size_t>;

    /**
     * @brief Concretize upper bound of the range using given max value.
     *
     * Unwraps upper bound from optional, if some, or sets it to max value.
     * Returns error as string if current upper bound is greater than max value.
     * Also returns error, if lower is greater than upper after concretization.
     */
    std::expected<ConcreteRange, std::string> concrete_range(int max) const;
};

/// @brief A number of ranges.
struct Ranges : std::vector<Range> {
    /**
     * @brief Parse a number of ranges from string. Regular expression for string is:
     * `Range(,Range)*`. May return error as string if parse fails.
     */
    static std::expected<Ranges, std::string> parse(const std::string& s);

    /// @brief Get human-readable representation of ranges. Looks the same as parse() input.
    std::string to_string() const;

    /// @brief A number of concrete ranges. See Range::ConcreteRange for details.
    using ConcreteRanges = std::vector<Range::ConcreteRange>;

    /**
     * @brief Conretize upper bounds of all ranges with a single max value.
     * See Range::concrete_range for details.
     */
    std::expected<ConcreteRanges, std::string> concrete_ranges(int max) const;
};

/**
 * @brief Description of output artifacts. Formed from CLI options. Basically some human-readable
 * representations of assignment tables.
 */
struct OutputArtifacts {
    /**
     * @brief Base part of the filename of assignment tables. For each generated table its index
     * will be appended at the end: `basename.N`. If equals to "-", then output to stdout.
     */
    std::string basename;

    /// @brief Indices of the table to write.
    std::vector<nil::evm_assigner::zkevm_circuit> tables;

    /// @brief Rows in every table to write.
    Ranges rows;

    /// @brief Witness columns in every table to write.
    Ranges witness_columns;

    /// @brief Public input columns in every table to write.
    Ranges public_input_columns;

    /// @brief Constant columns in every table to write.
    Ranges constant_columns;

    /// @brief Selector columns in every table to write.
    Ranges selector_columns;

    /// @brief Default constructor creates no artifacts and stdout output.
    OutputArtifacts()
        : basename("-"),
          tables({}),
          rows({}),
          witness_columns({}),
          public_input_columns({}),
          constant_columns({}),
          selector_columns({}) {}

    /// @brief Whether write output into stdout or into file.
    bool to_stdout() const { return basename == "-"; }

    std::string tables_to_string() const;

    /**
     * @brief Parse table names from string.
     */
    static std::expected<std::vector<nil::evm_assigner::zkevm_circuit>, std::string> parse_tables(
        const std::vector<std::string>& s);

    /**
     * @brief Parse program options and construct output artifacts description from it.
     * May return error as string. Assumes that option `output-text` is set.
     */
    static std::expected<OutputArtifacts, std::string> from_program_options(
        boost::program_options::variables_map vm);
};

#endif  // ZKEMV_FRAMEWORK_LIBS_OUTPUT_ARTIFACTS_INCLUDE_OUTPUT_ARTIFACTS_HPP_
