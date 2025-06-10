#pragma once

#include <nil/proof-generator/types/type_system.hpp>
#include <nil/proof-generator/command_step.hpp>
#include <nil/proof-generator/file_operations.hpp>
#include <nil/proof-generator/marshalling_utils.hpp>
#include <nil/proof-generator/resources.hpp>

namespace nil {
    namespace proof_producer {

        template<typename CurveType, typename HashType>
        struct ProveStep {
            using Types                   = TypeSystem<CurveType, HashType>;
            using BlueprintField          = typename Types::BlueprintField;
            using Endianness              = typename Types::Endianness;
            using TTypeBase               = typename Types::TTypeBase;
            using ConstraintSystem        = typename Types::ConstraintSystem;
            using AssignmentTable         = typename Types::AssignmentTable;
            using AssignmentPublicInput   = typename Types::AssignmentPublicInput;
            using TableDescription        = typename Types::TableDescription;
            using PublicPreprocessedData  = typename Types::PublicPreprocessedData;
            using CommonData              = typename Types::CommonData;
            using LpcScheme               = typename Types::LpcScheme;
            using FriParams               = typename Types::FriParams;
            using PlaceholderParams       = typename Types::PlaceholderParams;
            using PrivatePreprocessedData = typename Types::PrivatePreprocessedData;
            using Proof                   = typename Types::Proof;

        private:
            struct ProofGeneratorBase {
                ProofGeneratorBase(
                    resources::resource_provider<ConstraintSystem>& constraint_provider,
                    resources::resource_provider<AssignmentTable>& table_provider,
                    resources::resource_provider<TableDescription>& desc_provider,
                    resources::resource_provider<PublicPreprocessedData>& public_data_provider,
                    resources::resource_provider<LpcScheme>& lpc_scheme_provider,
                    resources::resource_provider<PrivatePreprocessedData>& private_data_provider
                )
                {
                    using resources::subscribe;
                    using resources::subscribe_value;

                    subscribe(table_provider, [&](std::shared_ptr<AssignmentTable> table) {
                        public_inputs_.emplace(table->public_inputs());
                    });
                    subscribe_value<ConstraintSystem>(constraint_provider, constraint_system_);
                    subscribe_value<TableDescription>(desc_provider, table_description_);
                    subscribe_value<PublicPreprocessedData>(public_data_provider, public_preprocessed_data_);
                    subscribe_value<LpcScheme>(lpc_scheme_provider, lpc_scheme_);
                    subscribe_value<PrivatePreprocessedData>(private_data_provider, private_preprocessed_data_);
                }


                std::optional<AssignmentPublicInput> public_inputs_;
                std::shared_ptr<ConstraintSystem> constraint_system_;
                std::shared_ptr<TableDescription> table_description_;
                std::shared_ptr<PublicPreprocessedData> public_preprocessed_data_;
                std::shared_ptr<PrivatePreprocessedData> private_preprocessed_data_;
                std::shared_ptr<LpcScheme> lpc_scheme_;
            };

        public:

            struct ProofReader:
                public command_step,
                public resources::resource_provider<Proof>
            {
                ProofReader(const boost::filesystem::path& proof_file): proof_file_(proof_file) {}

                CommandResult execute() override {
                    using resources::notify;

                    using ProofMarshalling = nil::crypto3::marshalling::types::
                        placeholder_proof<nil::crypto3::marshalling::field_type<Endianness>, Proof>;

                    BOOST_LOG_TRIVIAL(info) << "Reading proof from file " << proof_file_;
                    auto marshalled_proof = detail::decode_marshalling_from_file<ProofMarshalling>(proof_file_, true);
                    if (!marshalled_proof) {
                        return CommandResult::Error(ResultCode::IOError, "Failed to read proof from {}", proof_file_.string());
                    }

                    notify<Proof>(*this, std::make_shared<Proof>(
                        nil::crypto3::marshalling::types::make_placeholder_proof<Endianness, Proof>(
                            *marshalled_proof
                        )
                    ));

                    return CommandResult::Ok();
                }

            private:
                boost::filesystem::path proof_file_;
            };

            struct ProofGenerator:
                public ProofGeneratorBase,
                public command_step,
                public resources::resource_provider<Proof>
            {

                ProofGenerator(
                    resources::resource_provider<ConstraintSystem>& constraint_provider,
                    resources::resource_provider<AssignmentTable>& table_provider,
                    resources::resource_provider<TableDescription>& desc_provider,
                    resources::resource_provider<PublicPreprocessedData>& public_data_provider,
                    resources::resource_provider<LpcScheme>& lpc_scheme_provider,
                    resources::resource_provider<PrivatePreprocessedData>& private_data_provider,
                    const boost::filesystem::path& proof_file,
                    const boost::filesystem::path& json_file
                ): ProofGeneratorBase(constraint_provider, table_provider, desc_provider, public_data_provider, lpc_scheme_provider, private_data_provider),
                   proof_file_(proof_file),
                   json_file_(json_file)
                {}

                CommandResult execute() override {

                    using resources::notify;

                    BOOST_ASSERT(this->public_inputs_);
                    BOOST_ASSERT(this->public_preprocessed_data_);
                    BOOST_ASSERT(this->private_preprocessed_data_);
                    BOOST_ASSERT(this->table_description_);
                    BOOST_ASSERT(this->constraint_system_);
                    BOOST_ASSERT(this->lpc_scheme_);

                    if (!can_write_to_file(proof_file_.string())) {
                        return CommandResult::Error(ResultCode::IOError, "Can't write to file {}", proof_file_.string());
                    }

                    BOOST_LOG_TRIVIAL(info) << "Generating proof...";
                    PROFILE_SCOPE("Generating proof");

                    nil::crypto3::zk::snark::placeholder_prover<BlueprintField, PlaceholderParams> prover(
                        *this->public_preprocessed_data_,
                        *this->private_preprocessed_data_,
                        *this->table_description_,
                        *this->constraint_system_,
                        *this->lpc_scheme_
                    );
                    auto proof = prover.process();

                    BOOST_LOG_TRIVIAL(info) << "Proof generated";
                    PROFILE_SCOPE_END();

                    auto res = write_proof_to_file(proof, this->lpc_scheme_->get_fri_params(), proof_file_);
                    if (!res) {
                        return CommandResult::Error(ResultCode::IOError, "Failed to write proof to file {}", proof_file_.string());
                    }

                    BOOST_LOG_TRIVIAL(info) << "Writing json proof to " << json_file_;
                    auto output_file = open_file<std::ofstream>(json_file_.string(), std::ios_base::out);
                    if (!output_file)
                    {
                        return CommandResult::Error(ResultCode::IOError, "Failed to open file {}", json_file_.string());
                    }

                    using nil::blueprint::recursive_verifier_generator;
                    (*output_file) << recursive_verifier_generator<PlaceholderParams, Proof, CommonData>(*this->table_description_).
                        generate_input(
                            *this->public_inputs_,
                            proof,
                            this->constraint_system_->public_input_sizes()
                    );
                    output_file->close();
                    BOOST_LOG_TRIVIAL(info) << "JSON proof written.";

                    notify<Proof>(*this, std::make_shared<Proof>(std::move(proof)));

                    return CommandResult::Ok();
                }

            private:
                boost::filesystem::path proof_file_;
                boost::filesystem::path json_file_;
            };

            struct PartialProofGenerator:
                public ProofGeneratorBase,
                public command_step
            {
                PartialProofGenerator(
                    resources::resource_provider<ConstraintSystem>& constraint_provider,
                    resources::resource_provider<AssignmentTable>& table_provider,
                    resources::resource_provider<TableDescription>& desc_provider,
                    resources::resource_provider<PublicPreprocessedData>& public_data_provider,
                    resources::resource_provider<LpcScheme>& lpc_scheme_provider,
                    resources::resource_provider<PrivatePreprocessedData>& private_data_provider,
                    const boost::filesystem::path& proof_file,
                    const boost::filesystem::path& challenge_file_,
                    const boost::filesystem::path& theta_power_file
                ): ProofGeneratorBase(constraint_provider, table_provider, desc_provider, public_data_provider, lpc_scheme_provider, private_data_provider),
                   proof_file_(proof_file),
                   challenge_file_(challenge_file_),
                   theta_power_file_(theta_power_file)
                {}

                CommandResult execute() override
                {
                    BOOST_ASSERT(this->public_preprocessed_data_);
                    BOOST_ASSERT(this->private_preprocessed_data_);
                    BOOST_ASSERT(this->table_description_);
                    BOOST_ASSERT(this->constraint_system_);
                    BOOST_ASSERT(this->lpc_scheme_);

                    if (!can_write_to_file(proof_file_.string())) {
                        return CommandResult::Error(ResultCode::IOError, "Can't write to file {}", proof_file_.string());
                    }

                    BOOST_LOG_TRIVIAL(info) << "Generating partial proof...";

                    PROFILE_SCOPE("Generating partial proof");
                    auto prover = nil::crypto3::zk::snark::placeholder_prover<BlueprintField, PlaceholderParams>(
                            *this->public_preprocessed_data_,
                            *this->private_preprocessed_data_,
                            *this->table_description_,
                            *this->constraint_system_,
                            *this->lpc_scheme_,
                            true);
                    Proof proof = prover.process();
                    PROFILE_SCOPE_END();

                    BOOST_LOG_TRIVIAL(info) << "Proof generated";

                    auto res = write_proof_to_file(proof, this->lpc_scheme_->get_fri_params(), proof_file_);
                    if (!res) {
                        return CommandResult::Error(ResultCode::IOError, "Failed to write proof to file {}", proof_file_.string());
                    }

                    BOOST_LOG_TRIVIAL(info) << "Writing challenge to " << challenge_file_ << ".";
                    using challenge_marshalling_type =
                        nil::crypto3::marshalling::types::field_element<
                        TTypeBase, typename BlueprintField::value_type>;

                    challenge_marshalling_type marshalled_challenge(
                        prover.transcript.template challenge<BlueprintField>());

                    res = detail::encode_marshalling_to_file<challenge_marshalling_type>(
                                challenge_file_, marshalled_challenge);
                    if (res) {
                        BOOST_LOG_TRIVIAL(info) << "Challenge written.";
                    } else {
                        BOOST_LOG_TRIVIAL(error) << "Failed to write challenge to file.";
                    }

                    // Looks like we don't need the following lines.
                    //this->lpc_scheme_->state_commited(crypto3::zk::snark::FIXED_VALUES_BATCH);
                    //this->lpc_scheme_->state_commited(crypto3::zk::snark::VARIABLE_VALUES_BATCH);
                    //this->lpc_scheme_->state_commited(crypto3::zk::snark::PERMUTATION_BATCH);
                    //this->lpc_scheme_->state_commited(crypto3::zk::snark::QUOTIENT_BATCH);
                    //this->lpc_scheme_->state_commited(crypto3::zk::snark::LOOKUP_BATCH);
                    //this->lpc_scheme_->mark_batch_as_fixed(crypto3::zk::snark::FIXED_VALUES_BATCH);
                    this->lpc_scheme_->set_fixed_polys_values(this->public_preprocessed_data_->common_data->commitment_scheme_data);

                    std::size_t theta_power = this->lpc_scheme_->compute_theta_power_for_combined_Q();

                    BOOST_LOG_TRIVIAL(info) << "Writing theta power to " << theta_power_file_ << ".";
                    auto output_file = open_file<std::ofstream>(theta_power_file_.string(), std::ios_base::out);
                    (*output_file) << theta_power << std::endl;
                    output_file->close();

                    return CommandResult::Ok();
                }

            private:
                boost::filesystem::path proof_file_;
                boost::filesystem::path challenge_file_;
                boost::filesystem::path theta_power_file_;
            };

        private:
            static bool write_proof_to_file(const Proof& proof, const FriParams& fri_params, boost::filesystem::path proof_file) {
                BOOST_LOG_TRIVIAL(info) << "Writing proof to " << proof_file;
                auto filled_placeholder_proof =
                    nil::crypto3::marshalling::types::fill_placeholder_proof<Endianness, Proof>(proof, fri_params);
                bool res = detail::encode_marshalling_to_file(
                    proof_file,
                    filled_placeholder_proof,
                    true
                );
                if (res) {
                    BOOST_LOG_TRIVIAL(info) << "Proof written.";
                } else {
                    BOOST_LOG_TRIVIAL(error) << "Failed to write proof to file.";
                }
                return res;
            }
        };
    } // namespace proof_producer
} // namespace nil
