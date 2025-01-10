#pragma once

#include <optional>

#include <boost/filesystem.hpp>
#include <boost/log/trivial.hpp>

#include <nil/marshalling/endianness.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/status_type.hpp>

#include <nil/proof-generator/file_operations.hpp>


namespace nil {
    namespace proof_generator {
        namespace detail {

            template<typename MarshallingType>
            std::optional<MarshallingType> decode_marshalling_from_file(
                const boost::filesystem::path& path,
                bool hex = false
            ) {
                const auto v = hex ? read_hex_file_to_vector(path.c_str()) : read_file_to_vector(path.c_str());
                if (!v.has_value()) {
                    return std::nullopt;
                }

                MarshallingType marshalled_data;
                auto read_iter = v->begin();
                auto status = marshalled_data.read(read_iter, v->size());
                if (status != nil::crypto3::marshalling::status_type::success) {
                    BOOST_LOG_TRIVIAL(error) << "When reading a Marshalled structure from file "
                        << path << ", decoding step failed.";
                    return std::nullopt;
                }
                return marshalled_data;
            }

            template<typename MarshallingType>
            bool encode_marshalling_to_file(
                const boost::filesystem::path& path,
                const MarshallingType& data_for_marshalling,
                bool hex = false
            ) {
                std::vector<std::uint8_t> v;
                v.resize(data_for_marshalling.length(), 0x00);
                auto write_iter = v.begin();
                nil::crypto3::marshalling::status_type status = data_for_marshalling.write(write_iter, v.size());
                if (status != nil::crypto3::marshalling::status_type::success) {
                    BOOST_LOG_TRIVIAL(error) << "Marshalled structure encoding failed";
                    return false;
                }

                return hex ? write_vector_to_hex_file(v, path.c_str()) : write_vector_to_file(v, path.c_str());
            }

        } // namespace details
    } // namespace proof_generator
} // namespace nil
