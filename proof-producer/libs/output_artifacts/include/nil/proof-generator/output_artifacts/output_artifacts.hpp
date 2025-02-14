/**
 * @file output_artifacts.hpp
 *
 * @brief This file defines functions and types for writing output artifacts.
 */

#ifndef PROOF_GENERATOR_OUTPUT_ARTIFACTS_HPP
#define PROOF_GENERATOR_OUTPUT_ARTIFACTS_HPP

#include <cstddef>
#include <expected>
#include <optional>
#include <string>
#include <vector>

#include <boost/program_options.hpp>

namespace nil {
    namespace proof_producer {

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
            std::expected<ConcreteRange, std::string> concrete_range(std::size_t max) const;
        };

        /// @brief A number of ranges.
        struct Ranges : std::vector<Range> {
            /// @brief Get human-readable representation of ranges. Looks the same as parse() input.
            std::string to_string() const;

            /// @brief A number of concrete ranges. See Range::ConcreteRange for details.
            using ConcreteRanges = std::vector<Range::ConcreteRange>;

            /**
            * @brief Conretize upper bounds of all ranges with a single max value.
            * See Range::concrete_range for details.
            */
            std::expected<ConcreteRanges, std::string> concrete_ranges(std::size_t max) const;
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
            std::string output_filename;

            /// @brief Whether to write full table without other range specifications.
            bool write_full{};

            /// @brief Rows to write.
            Ranges rows;

            /// @brief Witness columns to write.
            Ranges witness_columns;

            /// @brief Public input columns to write.
            Ranges public_input_columns;

            /// @brief Constant columns to write.
            Ranges constant_columns;

            /// @brief Selector columns to write.
            Ranges selector_columns;

            /// @brief Default constructor creates no artifacts and stdout output.
            OutputArtifacts()
                : output_filename(stdout_filename),
                rows({}),
                witness_columns({}),
                public_input_columns({}),
                constant_columns({}),
                selector_columns({}) {}

            /// @brief Whether write output into stdout or into file.
            bool to_stdout() const noexcept { return output_filename == "-"; }

            bool empty() const noexcept {
                return !write_full &&
                    (rows.empty() || (
                        witness_columns.empty() &&
                        public_input_columns.empty() &&
                        constant_columns.empty() &&
                        selector_columns.empty()
                   )
                );
            }

            private:
                static constexpr auto stdout_filename = "-";
        };

        void register_output_artifacts_cli_args(OutputArtifacts& to_fill, boost::program_options::options_description& cli_options);

    } // namespace proof_producer
} // namespace nil

#endif  // PROOF_GENERATOR_OUTPUT_ARTIFACTS_HPP
