#pragma once

#include <cstddef>
#include <memory>

#include <boost/filesystem.hpp>
#include <boost/assert.hpp>
#include <boost/log/trivial.hpp>

#include <nil/proof-generator/types/type_system.hpp>
#include <nil/proof-generator/resources.hpp>
#include <nil/proof-generator/command_step.hpp>
#include <nil/proof-generator/commands/detail/io/lpc_scheme_io.hpp>
#include <nil/proof-generator/commands/detail/io/challenge_io.hpp>
#include <nil/proof-generator/commands/detail/io/polynomial_io.hpp>


#include <nil/crypto3/marshalling/math/types/polynomial.hpp>


namespace nil {
    namespace proof_generator {

        template <typename CurveType, typename HashType>
        struct CombinedQGenerator: public command_step {

            using Types           = TypeSystem<CurveType, HashType>;
            using Endianness      = typename Types::Endianness;
            using BlueprintField  = typename Types::BlueprintField;
            using LpcScheme       = typename Types::LpcScheme;
            using polynomial_type = typename Types::polynomial_type;

            CombinedQGenerator(
                resources::resource_provider<LpcScheme>& lpc_scheme_provider,
                const boost::filesystem::path& aggregated_challenge_file,
                std::size_t combined_Q_starting_power,
                const boost::filesystem::path& combined_Q_polynomial_file
            ): aggregated_challenge_file_(aggregated_challenge_file),
               combined_Q_starting_power_(combined_Q_starting_power),
               combined_Q_polynomial_file_(combined_Q_polynomial_file)
            {
                resources::subscribe_value<LpcScheme>(lpc_scheme_provider, lpc_scheme_);
            }

            CommandResult execute() override {
                BOOST_ASSERT(lpc_scheme_);
                return generate_combined_Q_to_file(
                    *lpc_scheme_,
                    aggregated_challenge_file_,
                    combined_Q_starting_power_,
                    combined_Q_polynomial_file_
                );
            }

        private:
            static CommandResult generate_combined_Q_to_file(
                LpcScheme& lpc_scheme,
                const boost::filesystem::path &aggregated_challenge_file,
                std::size_t starting_power,
                const boost::filesystem::path &output_combined_Q_file)
            {
                using ChallengeIO     = ChallengeIO<CurveType, HashType>;
                using PolynomialIO    = PolynomialIO<CurveType, HashType>;

                BOOST_LOG_TRIVIAL(info) << "Generating combined Q from " << aggregated_challenge_file
                    << " to " << output_combined_Q_file << " with starting_power " << starting_power;

                std::optional<typename BlueprintField::value_type> challenge = ChallengeIO::read_challenge(
                    aggregated_challenge_file);
                if (!challenge) {
                    return CommandResult::UnknownError("Failed to read challenge from {}", aggregated_challenge_file.string());
                }
                polynomial_type combined_Q = lpc_scheme.prepare_combined_Q(
                    challenge.value(), starting_power);
                const auto res = PolynomialIO::save_poly_to_file(combined_Q, output_combined_Q_file);
                if (!res) {
                    return CommandResult::UnknownError("Failed to write combined Q to {}", output_combined_Q_file.string());
                }
                return CommandResult::Ok();
            }

        private:
            std::shared_ptr<LpcScheme> lpc_scheme_;
            boost::filesystem::path aggregated_challenge_file_;
            std::size_t combined_Q_starting_power_;
            boost::filesystem::path combined_Q_polynomial_file_;
        };


        template <typename CurveType, typename HashType>
        struct CombinedQGeneratorCommand: public command_chain {

            struct Args {
                boost::filesystem::path in_lpc_scheme_file;
                boost::filesystem::path in_aggregated_challenge_file;
                std::size_t             combined_Q_starting_power;
                boost::filesystem::path out_combined_Q_polynomial_file;
            };

            CombinedQGeneratorCommand(const Args& args) {
                using LpcSchemeReader = LpcSchemeIO<CurveType, HashType>::Reader;
                using CombinedQGenerator = CombinedQGenerator<CurveType, HashType>;

                auto& lpc_scheme_provider = add_step<LpcSchemeReader>(args.in_lpc_scheme_file);
                add_step<CombinedQGenerator>(lpc_scheme_provider, args.in_aggregated_challenge_file, args.combined_Q_starting_power, args.out_combined_Q_polynomial_file);
            }
        };

    } // namespace proof_generator
} // namespace nil
