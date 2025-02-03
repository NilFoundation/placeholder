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

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/dFRI_verifier.hpp>

namespace nil {
    namespace proof_producer {

        template<typename CurveType, typename HashType>
        struct VerifyAggregatedStep {
            using Types                     = TypeSystem<CurveType, HashType>;
            using BlueprintField            = typename Types::BlueprintField;
            using Endianness                = typename Types::Endianness;
            using PlaceholderParams         = typename Types::PlaceholderParams;
            using ConstraintSystem          = typename Types::ConstraintSystem;
            using ConstraintSystemNoCircuit = typename Types::ConstraintSystemNoCircuit;
            using TableDescription          = typename Types::TableDescription;
            using PublicPreprocessedData    = typename Types::PublicPreprocessedData;
            using CommonData                = typename Types::CommonData;
            using LpcScheme                 = typename Types::LpcScheme;
            using AggregatedProof           = typename Types::AggregatedProof;
            using Proof                     = typename Types::Proof;
            using CommitmentSchemeFac       = CommitmentSchemeFactory<CurveType, HashType>;

            struct AggregatedProofReader:
                public command_step,
                public resources::resource_provider<AggregatedProof>
            {
                AggregatedProofReader(const boost::filesystem::path& proof_file): proof_file_(proof_file) {}

                CommandResult execute() override {
                    using resources::notify;

                    using ProofMarshalling = nil::crypto3::marshalling::types::
                        placeholder_aggregated_proof_type<nil::crypto3::marshalling::field_type<Endianness>, AggregatedProof>;

                    BOOST_LOG_TRIVIAL(info) << "Reading dFRI proof from file " << proof_file_;
                    auto marshalled_proof = detail::decode_marshalling_from_file<ProofMarshalling>(proof_file_, true);
                    if (!marshalled_proof) {
                        return CommandResult::Error(ResultCode::IOError, "Failed to read dFRI proof from {}", proof_file_.string());
                    }

                    notify<AggregatedProof>(*this, std::make_shared<AggregatedProof>(
                        nil::crypto3::marshalling::types::make_placeholder_aggregated_proof<Endianness, AggregatedProof, Proof>(
                            *marshalled_proof
                        )
                    ));

                    return CommandResult::Ok();
                }

            private:
                boost::filesystem::path proof_file_;
            };

            struct AggregatedFRIVerifier: public command_step
            {
                AggregatedFRIVerifier(
                    PlaceholderConfig config,
                    std::vector<resources::resource_provider<ConstraintSystem>*>& constraint_system_providers,
                    std::vector<resources::resource_provider<TableDescription>*>& desc_providers,
                    std::vector<resources::resource_provider<CommonData>*>& common_data_providers,
                    resources::resource_provider<AggregatedProof>& aggregated_proof_provider
                ) : commitment_scheme_fac_(config)
                  , N(constraint_system_providers.size())
                {
                    using resources::subscribe_value;
                    for (size_t i = 0; i < N; ++i) {
                        subscribe_value<ConstraintSystem>(*constraint_system_providers[i], constraint_systems_[i]);
                        subscribe_value<TableDescription>(*desc_providers[i], table_descriptions_[i]);
                        subscribe_value<CommonData>(*common_data_providers[i], common_datas_[i]);
                    }
                    subscribe_value<AggregatedProof>(aggregated_proof_provider, agg_proof_);
                }

                CommandResult execute() override {
                    BOOST_ASSERT(agg_proof_);
                    for (size_t i = 0; i < N; ++i) { 
                        BOOST_ASSERT(common_datas_[i]);
                        BOOST_ASSERT(constraint_systems_[i]);
                        BOOST_ASSERT(table_descriptions_[i]);
                    }

                    BOOST_LOG_TRIVIAL(info) << "Verifying aggreated dFRI proof...";

                    std::vector<std::shared_ptr<LpcScheme>> lpc_schemes;
                    for (size_t i = 0; i < N; ++i) {
                        BOOST_ASSERT(table_descriptions_[i]->rows_amount == table_descriptions_[0]->rows_amount);

                        auto lpc_scheme = commitment_scheme_fac_.make_lpc_scheme(table_descriptions_[i]->rows_amount);
                        lpc_schemes.push_back(lpc_scheme);
                    }
                    // We need to convert circuit<constraint_system> to constraint_system, otherwise it does not convert automatically
                    // for shared pointers.
                    std::vector<std::shared_ptr<ConstraintSystemNoCircuit>> constraint_systems;
                    for (size_t i = 0; i < N; ++i) {
                        constraint_systems.push_back(std::make_shared<ConstraintSystemNoCircuit>(*constraint_systems_[i]));
                    }

                    bool verification_result = nil::crypto3::zk::snark::placeholder_DFRI_verifier<BlueprintField, PlaceholderParams>::process(
                            common_datas_,
                            *agg_proof_,
                            table_descriptions_,
                            constraint_systems,
                            lpc_schemes,
                            {} // public inputs
                        );

                    if (verification_result) {
                        BOOST_LOG_TRIVIAL(info) << "Proof is verified";
                        return CommandResult::Ok();
                    }
                    return CommandResult::Error(ResultCode::ProverError, "dFRI Proof verification failed");
                }

            private:
                CommitmentSchemeFac commitment_scheme_fac_;
                // number of provers.
                size_t N;

                std::vector<std::shared_ptr<ConstraintSystem>> constraint_systems_;
                std::vector<std::shared_ptr<TableDescription>> table_descriptions_;
                std::vector<std::shared_ptr<CommonData>> common_datas_;
                std::shared_ptr<AggregatedProof> agg_proof_;
            };
        };

        template<typename CurveType, typename HashType>
        class AggregatedFRIVerifyCommand: public command_chain {
        public:
            struct Args {
                PlaceholderConfig config;
                std::vector<boost::filesystem::path> in_circuit_file_paths;
                std::vector<boost::filesystem::path> in_assignment_description_file_paths;
                std::vector<boost::filesystem::path> in_common_data_file_paths;
                boost::filesystem::path in_proof_file_path;

                Args(boost::program_options::options_description& config) {
                    namespace po = boost::program_options;

                    config.add_options()
                        ("circuits",
                         po::value<std::vector<boost::filesystem::path>>(&in_circuit_file_paths)->multitoken()->required(),
                         "Circuit input files")
                        ("assignment-description-files",
                         po::value<std::vector<boost::filesystem::path>>(&in_assignment_description_file_paths)->multitoken()->required(),
                         "Assignment description input files")
                        ("common-datas",
                         po::value<std::vector<boost::filesystem::path>>(&in_common_data_file_paths)->multitoken()->required(),
                         "Common data input file")
                        ("agg-proof",
                         po::value(&in_proof_file_path)->required(),
                         "Aggregated dFRI Proof input file");
                } 
            };

            AggregatedFRIVerifyCommand(const Args& args) {
                size_t N = args.in_circuit_file_paths.size();

                using Types                   = TypeSystem<CurveType, HashType>;
                using ConstraintSystem        = typename Types::ConstraintSystem;
                using TableDescription        = typename Types::TableDescription;
                using PublicPreprocessedData  = typename Types::PublicPreprocessedData;
                using CommonData              = typename Types::CommonData;
                using LpcScheme               = typename Types::LpcScheme;
                using AggregatedProof         = typename Types::AggregatedProof;

                using CircuitReader                = CircuitIO<CurveType, HashType>::Reader;
                using AssignmentDescriptionReader  = AssignmentTableIO<CurveType, HashType>::DescriptionReader;
                using CommonDataReader             = PreprocessedPublicDataIO<CurveType, HashType>::CommonDataReader;
                using Verifier                     = VerifyAggregatedStep<CurveType, HashType>::AggregatedFRIVerifier;
                using AggregatedProofReader        = VerifyAggregatedStep<CurveType, HashType>::AggregatedProofReader;

                std::vector<resources::resource_provider<ConstraintSystem>*> circuit_readers;
                std::vector<resources::resource_provider<TableDescription>*> table_description_readers;
                std::vector<resources::resource_provider<CommonData>*> common_data_readers;

                for (size_t i = 0; i < N; ++i) {
                    circuit_readers.push_back(&add_step<CircuitReader>(args.in_circuit_file_paths[i]));
                    table_description_readers.push_back(&add_step<AssignmentDescriptionReader>(args.in_assignment_description_file_paths[i]));
                    common_data_readers.push_back(&add_step<CommonDataReader>(args.in_common_data_file_paths[i]));
                }
                auto& proof_reader = add_step<AggregatedProofReader>(args.in_proof_file_path);

                add_step<Verifier>(
                    args.config,
                    circuit_readers,
                    table_description_readers,
                    common_data_readers,
                    proof_reader
                );
            }
        };
    } // namespace proof_producer
} // namespace nil
