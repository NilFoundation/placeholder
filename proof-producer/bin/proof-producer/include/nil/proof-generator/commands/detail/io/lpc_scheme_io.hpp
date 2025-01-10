#pragma once

#include <memory>

#include <boost/log/trivial.hpp>
#include <boost/filesystem.hpp>

#include <nil/proof-generator/types/type_system.hpp>
#include <nil/proof-generator/resources.hpp>
#include <nil/proof-generator/command_step.hpp>
#include <nil/proof-generator/marshalling_utils.hpp>


namespace nil {
    namespace proof_generator {

        template <typename CurveType, typename HashType>
        struct LpcSchemeIO {

            using Types      = TypeSystem<CurveType, HashType>;
            using Endianness = typename Types::Endianness;
            using TTypeBase  = typename Types::TTypeBase;
            using LpcScheme  = typename Types::LpcScheme;

            struct Writer: public command_step {

                Writer(resources::resource_provider<LpcScheme>& lpc_scheme_provider,
                    const boost::filesystem::path& commitment_scheme_state_file
                ): commitment_scheme_state_file_(commitment_scheme_state_file)
                {
                    resources::subscribe_value<LpcScheme>(lpc_scheme_provider, lpc_scheme_);
                }

                CommandResult execute() override {
                    using namespace nil::crypto3::marshalling::types;

                    BOOST_ASSERT(lpc_scheme_);

                    BOOST_LOG_TRIVIAL(info) << "Writing commitment_state to " <<
                        commitment_scheme_state_file_;

                    auto marshalled_lpc_state = fill_commitment_scheme<Endianness, LpcScheme>(
                        *lpc_scheme_);
                    bool res = detail::encode_marshalling_to_file(
                        commitment_scheme_state_file_,
                        marshalled_lpc_state
                    );
                    if (!res) {
                        return CommandResult::UnknownError("Failed to write commitment scheme");
                    }

                    BOOST_LOG_TRIVIAL(info) << "Commitment scheme written.";
                    return CommandResult::Ok();
                }

            private:
                std::shared_ptr<LpcScheme> lpc_scheme_;
                boost::filesystem::path commitment_scheme_state_file_;
            };

            struct Reader: 
                public command_step,
                public resources::resource_provider<LpcScheme>
            {
                Reader(const boost::filesystem::path& commitment_scheme_state_file):
                    commitment_scheme_state_file_(commitment_scheme_state_file)
                {}
                
                CommandResult execute() override {
                    BOOST_LOG_TRIVIAL(info) << "Read commitment scheme from " << commitment_scheme_state_file_;

                    using namespace nil::crypto3::marshalling::types;
                    using resources::notify;

                    using CommitmentStateMarshalling = typename commitment_scheme_state<TTypeBase, LpcScheme>::type;

                    auto marshalled_value = detail::decode_marshalling_from_file<CommitmentStateMarshalling>(
                        commitment_scheme_state_file_);

                    if (!marshalled_value) {
                        return CommandResult::UnknownError("Failed to read commitment scheme from {}", commitment_scheme_state_file_.string());
                    }

                    auto commitment_scheme = make_commitment_scheme<Endianness, LpcScheme>(*marshalled_value);
                    if (!commitment_scheme) {
                        return CommandResult::UnknownError("Error decoding commitment scheme");
                    }

                    auto lpc_scheme = std::make_shared<LpcScheme>(std::move(commitment_scheme.value())); 
                    notify<LpcScheme>(*this, lpc_scheme);

                    return CommandResult::Ok();
                }

            private:
                boost::filesystem::path commitment_scheme_state_file_;
            };
        };
    } // namespace proof_generator
} // namespace nil
