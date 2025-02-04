#include <cstddef>
#include <expected>
#include <ostream>
#include <string>
#include <vector>

#include <boost/any.hpp>
#include <boost/regex.hpp>
#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>

#include <nil/proof-generator/output_artifacts/output_artifacts.hpp>


namespace {

    template<typename T>
    boost::program_options::typed_value<T>* make_defaulted_option(T& variable) {
        return boost::program_options::value(&variable)->default_value(variable);
    }

} // namespace

namespace po = boost::program_options;


namespace nil {
    namespace proof_producer {

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
            if (boost::regex_match(s, match_results, boost::regex("^full$"))) {
                return Range();
            }
            if (boost::regex_match(s, match_results, boost::regex("^\\d+$"))) {
                return Range(std::stoi(match_results.str()));
            }
            if (boost::regex_match(s, match_results, boost::regex("^(\\d+)-$"))) {
                return Range::new_lower(std::stoi(match_results[1].str()));
            }
            if (boost::regex_match(s, match_results, boost::regex("^-(\\d+)$"))) {
                return Range::new_upper(std::stoi(match_results[1].str()));
            }
            if (boost::regex_match(s, match_results, boost::regex("^(\\d+)-(\\d+)$"))) {
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

        std::expected<Range::ConcreteRange, std::string> Range::concrete_range(std::size_t max) const {
            int upper_ = upper.value_or(max);
            if (upper_ > max || upper_ < 0 || lower > upper_) {
                return std::unexpected("index out of bounds");
            }
            return std::make_pair(lower, upper_);
        }

        std::string Ranges::to_string() const {
            std::vector<std::string> ranges;
            for (const auto& range : *this) {
                ranges.push_back(range.to_string());
            }
            return boost::algorithm::join(ranges, " ");
        }

        std::ostream& operator<<(std::ostream& out, const Ranges& ranges) {
            out << ranges.to_string();
            return out;
        }

        std::expected<Ranges::ConcreteRanges, std::string> Ranges::concrete_ranges(std::size_t max) const {
            ConcreteRanges ranges;
            ranges.reserve(this->size());
            for (const auto& range : *this) {
                auto maybe_concrete_range = range.concrete_range(max);
                if (!maybe_concrete_range.has_value()) {
                    return std::unexpected(maybe_concrete_range.error());
                }
                ranges.push_back(maybe_concrete_range.value());
            }
            return ranges;
        }

        // boost program options fails to parse <typename T> when T is a derivative of vector of some type so it is a workaround
        void validate(boost::any& v, const std::vector<std::string>& values, Ranges*, int) {
            po::validators::check_first_occurrence(v);
            Ranges result;
            for (const auto& value : values) {
                auto maybe_ranges = Range::parse(value);
                if (!maybe_ranges.has_value()) {
                    throw po::invalid_option_value(maybe_ranges.error());
                }
                result.push_back(maybe_ranges.value());
                v = boost::any(result);
            }
        }

        void register_output_artifacts_cli_args(OutputArtifacts& to_fill, po::options_description& cli_options) {

                cli_options.add_options()
                ("assignment-table-debug-file", make_defaulted_option(to_fill.output_filename),
                 "Output filename for print assignment tables in human readable format. If omitted or set to '-', write to stdout")

                 ("assignment-table-debug-full", make_defaulted_option(to_fill.write_full),
                    "Print full assignment table in human readable format (all rows and columns of every type)")

                 ("assignment-table-debug-rows", make_defaulted_option(to_fill.rows)->multitoken(),
                    "Assignment table rows to print in human readable format. Format: `full` or `N`, `N-M`, `N-` or `-M` (each range space-separated from another)")

                 ("assignment-table-debug-witness-columns", make_defaulted_option(to_fill.witness_columns)->multitoken(),
                    "Assignment table witness columns to print in human readable format. Format: `full` or `N`, `N-M`, `N-` or `-M` (each range space-separated from another)")

                 ("assignment-table-debug-public-input-columns", make_defaulted_option(to_fill.public_input_columns)->multitoken(),
                    "Assignment table public input columns to print in human readable format. Format: `full` or `N`, `N-M`, `N-` or `-M` (each range space-separated from another)")

                 ("assignment-table-debug-constant-columns", make_defaulted_option(to_fill.constant_columns)->multitoken(),
        "Assignment table constant columns to print in human readable format. Format: `full` or `N`, `N-M`, `N-` or `-M` (each range space-separated from another)")

                 ("assignment-table-debug-selector-columns", make_defaulted_option(to_fill.selector_columns)->multitoken(),
        "Assignment table selector columns to print in human readable format. Format: `full` or `N`, `N-M`, `N-` or `-M` (each range space-separated from another)");
        }

    } // namespace proof_producer

} // namespace nil
