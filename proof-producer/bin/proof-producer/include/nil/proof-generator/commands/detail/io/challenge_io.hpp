#pragma once

#include <optional>

#include <boost/filesystem.hpp>

#include <nil/proof-generator/types/type_system.hpp>
#include <nil/proof-generator/file_operations.hpp>
#include <nil/proof-generator/marshalling_utils.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>


namespace nil {
    namespace proof_producer {

        template <typename CurveType, typename HashType>
        struct ChallengeIO {
            using Types          = TypeSystem<CurveType, HashType>;
            using BlueprintField = typename Types::BlueprintField;
            using TTypeBase      = typename Types::TTypeBase;
            using Endianness     = typename Types::Endianness;
            using Challenge      = typename BlueprintField::value_type;

        private:
            using challenge_marshalling_type = nil::crypto3::marshalling::types::field_element<TTypeBase, Challenge>;
            using challenge_vector_marshalling_type = nil::crypto3::marshalling::types::field_element_vector<Challenge, TTypeBase>;

        public:
            static std::optional<Challenge> read_challenge(const boost::filesystem::path& input_file) {
                if (!can_read_from_file(input_file.string())) {
                    BOOST_LOG_TRIVIAL(error) << "Can't read file " << input_file;
                    return std::nullopt;
                }

                auto marshalled_challenge = detail::decode_marshalling_from_file<challenge_marshalling_type>(
                    input_file);

                if (!marshalled_challenge) {
                    return std::nullopt;
                }
                return marshalled_challenge->value();
            }

            static bool save_challenge(const boost::filesystem::path& challenge_file, const Challenge& challenge)
            {
                BOOST_LOG_TRIVIAL(info) << "Writing challenge to " << challenge_file << ".";

                challenge_marshalling_type marshalled_challenge(challenge);

                auto res = detail::encode_marshalling_to_file<challenge_marshalling_type>(
                            challenge_file, marshalled_challenge);
                if (res) {
                    BOOST_LOG_TRIVIAL(info) << "Challenge written.";
                } else {
                    BOOST_LOG_TRIVIAL(error) << "Failed to write challenge to file.";
                }
                return res;
            }

            static std::optional<std::vector<Challenge>> read_challenge_vector_from_file(const boost::filesystem::path& input_file) {
                if (!can_read_from_file(input_file.string())) {
                    BOOST_LOG_TRIVIAL(error) << "Can't read file " << input_file;
                    return std::nullopt;
                }

                auto marshalled_challenges = detail::decode_marshalling_from_file<challenge_vector_marshalling_type>(
                    input_file);

                if (!marshalled_challenges) {
                    return std::nullopt;
                }

                return nil::crypto3::marshalling::types::make_field_element_vector<
                    Challenge, Endianness>(marshalled_challenges.value());
            }

            static bool save_challenge_vector_to_file(const std::vector<Challenge>& challenges, const boost::filesystem::path& output_file)
            {
                BOOST_LOG_TRIVIAL(info) << "Writing challenges to " << output_file;

                challenge_vector_marshalling_type marshalled_challenges =
                    nil::crypto3::marshalling::types::fill_field_element_vector<Challenge, Endianness>(
                        challenges);

                return detail::encode_marshalling_to_file<challenge_vector_marshalling_type>(output_file, marshalled_challenges);
            }
        };
    } // namespace proof_producer
} // namespace nil
