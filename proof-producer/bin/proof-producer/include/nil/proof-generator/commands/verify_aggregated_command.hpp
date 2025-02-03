#pragma once

#include <memory>

#include <boost/filesystem.hpp>
#include <boost/log/trivial.hpp>

#include <nil/proof-generator/types/type_system.hpp>
#include <nil/proof-generator/command_step.hpp>
#include <nil/proof-generator/file_operations.hpp>
#include <nil/proof-generator/marshalling_utils.hpp>
#include <nil/proof-generator/resources.hpp>

#include <nil/proof-generator/commands/detail/io/circuit_io.hpp>
#include <nil/proof-generator/commands/detail/io/assignment_table_io.hpp>
#include <nil/proof-generator/commands/detail/io/preprocessed_data_io.hpp>
#include <nil/proof-generator/commands/detail/io/lpc_scheme_io.hpp>
#include <nil/proof-generator/commands/detail/commitment_scheme_factory.hpp>

#include <nil/proof-generator/commands/preprocess_command.hpp>
#include <nil/proof-generator/commands/gen_proof_command.hpp>
#include <nil/proof-generator/output_artifacts/output_artifacts.hpp>



namespace nil {
    namespace proof_producer {

        template<typename CurveType, typename HashType>
        struct VerifyStep {
            using Types                   = TypeSystem<CurveType, HashType>;
            using BlueprintField          = typename Types::BlueprintField;
            using PlaceholderParams       = typename Types::PlaceholderParams;
            using ConstraintSystem        = typename Types::ConstraintSystem;
            using TableDescription        = typename Types::TableDescription;
            using PublicPreprocessedData  = typename Types::PublicPreprocessedData;
            using CommonData              = typename Types::CommonData;
            using LpcScheme               = typename Types::LpcScheme;
            using Proof                   = typename Types::Proof;
            using CommitmentSchemeFac = CommitmentSchemeFactory<CurveType, HashType>;

            struct Verifier: public command_step
            {
                AggregatedFRIVerifier(
                    PlaceholderConfig config,
                    resources::resource_provider<ConstraintSystem>& constraint_system_provider,
                    resources::resource_provider<TableDescription>& desc_provider,
                    resources::resource_provider<CommonData>& common_data_provider,
                    resources::resource_provider<Proof>& fri_proof_provider
                    resources::resource_provider<Proof>& partial_proofs_provider
                ): commitment_scheme_fac_(config)
                {
                    using resources::subscribe_value;
                    subscribe_value<ConstraintSystem>(constraint_system_provider, constraint_system_);
                    subscribe_value<TableDescription>(desc_provider, table_description_);
                    subscribe_value<CommonData>(common_data_provider, common_data_);
                    subscribe_value<Proof>(proof_provider, fri_proof_);
                    subscribe_value<std::vector<Proof>>(partial_proofs_provider, partial_proofs_);
                }

                CommandResult execute() override {
                    BOOST_ASSERT(fri_proof_);
                    BOOST_ASSERT(partial_proofs_);
                    BOOST_ASSERT(common_data_);
                    BOOST_ASSERT(constraint_system_);
                    BOOST_ASSERT(table_description_);

                    BOOST_LOG_TRIVIAL(info) << "Verifying aggregated proof...";
                    // A type casting is required to perform on the output of aggregated FRI proof (x)
                        // fri_proof.final_polynomial = x.fri_commitments_proof_part.final_polynomial
                        // fri_proof.fri_roots = x.fri_commitments_proof_part.fri_roots
                        // fri_proof.round_proofs = x.fri_round_proof
                        // TODO
                        // fri_proof.proof_of_work = (is it in the merged proof?)
                    size_t proof_size = partial_proofs_.size()
                    std::vector<FieldType> challenges();
                    std::vector<std::vector<initial_proof_type>> initial_proofs(proof_size);
                    std::vector<LpcScheme> lpc_schemes(proof_size);
                    // TODO check the size of all the vectors are the same
                    using transcript_hash_type = typename PlaceholderParams::transcript_hash_type;
                    using transcript_type = crypto3::zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;
                    transcript_type aggregated_challenge_transcript;
                    size_t total_points = 0;
                    std::vector<std::size_t> starting_indexes(proof_size);

                    for (size_t i = 0; i < partial_proofs_[i].size; i++) {
                        read_circuit(circuit_file_paths[i]);
                        read_preprocessed_common_data_from_file(preprocessed_common_data_paths[i]);
                        read_assignment_description(assignment_description_file_paths[i]);
                        lpc_schemes[i] = commitment_scheme_fac_.make_lpc_scheme(table_description_->rows_amount);

                        transcript_type transcript(std::vector<std::uint8_t>({}));
                        auto common_data = public_preprocessed_data_.has_value() ? public_preprocessed_data_->common_data : *common_data_,
                        bool verification_result = 
                        nil::crypto3::zk::snark::placeholder_verifier<BlueprintField, PlaceholderParams>::verify_partial_proof(
                            common_data,
                            partial_proofs_[i],
                            *table_description_,
                            *constraint_system_,
                            *lpc_schemes[i],
                            *transcript
                            // TODO take care of public inputs
                        );
                        if (!verification_result) {
                            BOOST_LOG_TRIVIAL(error) << "Partial proof verification failed.";
                            return verification_result;
                        }
                        nil::crypto3::zk::snark::placeholder_verifier<BlueprintField, PlaceholderParams>::prepare_polynomials(
                            partial_proofs_[i],
                            &common_data,
                            &constraint_system_,
                            &lpc_schemes[i]
                        )
                        starting_indexes[i] = total_points;
                        // read challenges from input files and add them to the transcript
                        aggregated_challenge_transcript(partial_proofs_[i].eval_proof.challenge);
                        total_points += commitments[i].get_total_points();
                    }
                    typename std::vector<typename field_type::value_type> U(total_points);
                    // V is product of (x - eval_point) polynomial for each eval_point
                    typename std::vector<math::polynomial<value_type>> V(total_points);
                    // List of involved polynomials for each eval point [batch_id, poly_id, point_id]
                    typename std::vector<std::vector<std::tuple<std::size_t, std::size_t>>> poly_map(total_points);

                    value_type theta = aggregated_challenge_transcript.template challenge<field_type>();
                    value_type theta_acc = value_type::one();
                    size_t starting_index = 0;
                    for (size_t i = 0; i < lpc_schemes.size(); i++) {
                        lpc_schemes[i].generate_U_V_polymap(U, V, poly_map, *partial_proofs_i[i].z, theta, *theta_acc, starting_indexes[i]);
                    }
                    
                    // TODO is below needed?
                    // produce the aggregated challenge
                    transcript_type transcript1;
                    transcript1(aggregated_challenge_transcript.value())
                    if (!nil::crypto3::zk::algorithms::verify_eval<fri_type>(
                        proof.fri_proof,
                        fri_params,
                        fri_proof.commitments, // TODO or fri_proof.fri_roots instead? which one's which?
                        theta,
                        poly_map,
                        U,
                        V,
                        transcript
                    )) {
                        BOOST_LOG_TRIVIAL(info) << "Proof is verified";
                        return CommandResult::Ok();
                    }
                    return CommandResult::UnknownError("Proof verification failed");
                }

            private:
                CommitmentSchemeFac commitment_scheme_fac_;

                std::shared_ptr<ConstraintSystem> constraint_system_;
                std::shared_ptr<TableDescription> table_description_;
                std::shared_ptr<CommonData> common_data_;
                std::shared_ptr<Proof> proof_;
                std::shared_ptr<Proof> partial_proofs_;
            };
        };

        template<typename CurveType, typename HashType>
        class VerifyCommand: public command_chain {
        public:
            struct Args {
                PlaceholderConfig config;
                boost::filesystem::path in_circuit_file_path;
                boost::filesystem::path in_assignment_description_file_path;
                boost::filesystem::path in_common_data_file_path;
                boost::filesystem::path in_proof_file_path;
            };

            AggregatedFRIVerifyCommand(const Args& args) {
                using CircuitReader                = CircuitIO<CurveType, HashType>::Reader;
                using AssignmentDescriptionReader  = AssignmentTableIO<CurveType, HashType>::DescriptionReader;
                using CommonDataReader             = PreprocessedPublicDataIO<CurveType, HashType>::CommonDataReader;
                using ProofReader                  = ProveStep<CurveType, HashType>::ProofReader;
                using Verifier                     = VerifyStep<CurveType, HashType>::Verifier;

                auto& circuit_reader           = add_step<CircuitReader>(args.in_circuit_file_path);
                auto& table_description_reader = add_step<AssignmentDescriptionReader>(args.in_assignment_description_file_path);
                auto& common_data_reader       = add_step<CommonDataReader>(args.in_common_data_file_path);
                auto& proof_reader             = add_step<ProofReader>(args.in_proof_file_path);
                add_step<Verifier>(
                    args.config,
                    circuit_reader,
                    table_description_reader,
                    common_data_reader,
                    proof_reader
                );
            }
        };
    } // namespace proof_producer
} // namespace nil
