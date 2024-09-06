#ifndef ZKEMV_FRAMEWORK_LIBS_JSON_HELPERS_INCLUDE_ZKEVM_FRAMEWORK_JSON_HELPERS_JSON_HELPERS_HPP_
#define ZKEMV_FRAMEWORK_LIBS_JSON_HELPERS_INCLUDE_ZKEVM_FRAMEWORK_JSON_HELPERS_JSON_HELPERS_HPP_

#include <boost/json/value.hpp>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace json_helpers {

    /// @brief JSON Schema validator
    /// @returns the first found error if exists
    std::optional<std::string> validate_json(const boost::json::value &schema_json,
                                             const boost::json::value &target_json) noexcept;

    /// @brief Parse config file and transform it to Boost json representation
    std::expected<boost::json::value, std::string> parse_json(std::istream &stream) noexcept;

    /// @brief Extract unsigned number from value
    size_t get_number(const boost::json::value &json_value) noexcept;

    /// @brief Put string into the given vector bytes
    std::optional<std::string> to_bytes(std::string &hex_string,
                                        std::vector<uint8_t> &dst) noexcept;

    /// @brief Put value into the given vector bytes
    std::optional<std::string> to_bytes(const boost::json::value &json_value,
                                        std::vector<uint8_t> &dst) noexcept;

    /// @brief Put string into the given vector std::bytes
    std::optional<std::string> to_std_bytes(std::string &hex_string,
                                            std::vector<std::byte> &dst) noexcept;

    /// @brief Put value into the given vector std::bytes
    std::optional<std::string> to_std_bytes(const boost::json::value &json_value,
                                            std::vector<std::byte> &dst) noexcept;

}  // namespace json_helpers

#endif  // ZKEMV_FRAMEWORK_LIBS_JSON_HELPERS_INCLUDE_ZKEVM_FRAMEWORK_JSON_HELPERS_JSON_HELPERS_HPP_
