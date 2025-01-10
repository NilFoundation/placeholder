#ifndef PROOF_GENERATOR_ASSIGNER_GEN_PROOF_COMMAND_HPP
#define PROOF_GENERATOR_ASSIGNER_GEN_PROOF_COMMAND_HPP

#include <boost/filesystem.hpp>
#include <boost/log/trivial.hpp>

#include <nil/crypto3/bench/scoped_profiler.hpp>

#include <nil/proof-generator/types/type_system.hpp>
#include <nil/proof-generator/command_step.hpp>
#include <nil/proof-generator/file_operations.hpp>
#include <nil/proof-generator/marshalling_utils.hpp>
#include <nil/proof-generator/resources.hpp>

#include <nil/proof-generator/commands/detail/io/circuit_io.hpp>
#include <nil/proof-generator/commands/detail/io/assignment_table_io.hpp>
#include <nil/proof-generator/commands/detail/io/preprocessed_data_io.hpp>
#include <nil/proof-generator/commands/detail/io/lpc_scheme_io.hpp>
#include <nil/proof-generator/commands/preprocess_command.hpp>
#include <nil/proof-generator/commands/fill_assignment_command.hpp>
#include <nil/proof-generator/output_artifacts/output_artifacts.hpp>
#include "nil/crypto3/bench/scoped_profiler.hpp"


namespace nil {
    namespace proof_generator {

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
                        return CommandResult::UnknownError("Failed to read proof from {}", proof_file_.string());
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
                        return CommandResult::UnknownError("Can't write to file {}", proof_file_.string());
                    }

                    BOOST_LOG_TRIVIAL(info) << "Generating proof...";
                    TIME_LOG_START("Generating proof");

                    nil::crypto3::zk::snark::placeholder_prover<BlueprintField, PlaceholderParams> prover(
                        *this->public_preprocessed_data_,
                        *this->private_preprocessed_data_,
                        *this->table_description_,
                        *this->constraint_system_,
                        *this->lpc_scheme_
                    );
                    auto proof = prover.process();

                    BOOST_LOG_TRIVIAL(info) << "Proof generated";
                    TIME_LOG_END("Generating proof");

                    auto res = write_proof_to_file(proof, this->lpc_scheme_->get_fri_params(), proof_file_);
                    if (!res) {
                        return CommandResult::UnknownError("Failed to write proof to file {}", proof_file_.string());
                    }

                    BOOST_LOG_TRIVIAL(info) << "Writing json proof to " << json_file_;
                    auto output_file = open_file<std::ofstream>(json_file_.string(), std::ios_base::out);
                    if (!output_file)
                    {
                        return CommandResult::UnknownError("Failed to open file {}", json_file_.string());
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
                        return CommandResult::UnknownError("Can't write to file {}", proof_file_.string());
                    }

                    BOOST_LOG_TRIVIAL(info) << "Generating partial proof...";
                    
                    TIME_LOG_START("Generating partial proof");
                    auto prover = nil::crypto3::zk::snark::placeholder_prover<BlueprintField, PlaceholderParams>(
                            *this->public_preprocessed_data_,
                            *this->private_preprocessed_data_,
                            *this->table_description_,
                            *this->constraint_system_,               
                            *this->lpc_scheme_,
                            true);
                    Proof proof = prover.process();
                    TIME_LOG_END("Generating partial proof");
    
                    BOOST_LOG_TRIVIAL(info) << "Proof generated";

                    auto res = write_proof_to_file(proof, this->lpc_scheme_->get_fri_params(), proof_file_);
                    if (!res) {
                        return CommandResult::UnknownError("Failed to write proof to file {}", proof_file_.string());
                    }

                    BOOST_LOG_TRIVIAL(info) << "Writing challenge to " << challenge_file_ << ".";
                    using challenge_marshalling_type =
                        nil::crypto3::marshalling::types::field_element<
                        TTypeBase, typename BlueprintField::value_type>;

                    challenge_marshalling_type marshalled_challenge(proof.eval_proof.challenge);

                    res = detail::encode_marshalling_to_file<challenge_marshalling_type>(
                                challenge_file_, marshalled_challenge);
                    if (res) {
                        BOOST_LOG_TRIVIAL(info) << "Challenge written.";
                    } else {
                        BOOST_LOG_TRIVIAL(error) << "Failed to write challenge to file.";
                    }

                    this->lpc_scheme_->state_commited(crypto3::zk::snark::FIXED_VALUES_BATCH);
                    this->lpc_scheme_->state_commited(crypto3::zk::snark::VARIABLE_VALUES_BATCH);
                    this->lpc_scheme_->state_commited(crypto3::zk::snark::PERMUTATION_BATCH);
                    this->lpc_scheme_->state_commited(crypto3::zk::snark::QUOTIENT_BATCH);
                    this->lpc_scheme_->state_commited(crypto3::zk::snark::LOOKUP_BATCH);
                    this->lpc_scheme_->mark_batch_as_fixed(crypto3::zk::snark::FIXED_VALUES_BATCH);
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

        // TODO move to files
        template<typename CurveType, typename HashType>
        class ProveCommand: public command_chain {
        public:
            struct Args {
                boost::filesystem::path circuit_file_path;
                boost::filesystem::path assignment_table_file_path;
                boost::filesystem::path public_preprocessed_data_file_path;
                boost::filesystem::path lpc_scheme_file_path;
            
                OutputArtifacts out_assignment_debug_opts;
                boost::filesystem::path out_evm_verifier_dir_path;
                boost::filesystem::path out_assignment_desc_file_path;
                boost::filesystem::path out_proof_file_path;
                boost::filesystem::path out_proof_json_file_path;
            }; 

            ProveCommand(const Args& args) {
                using CircuitReader                = CircuitIO<CurveType, HashType>::Reader;
                using AssignmentTableReader        = AssignmentTableIO<CurveType, HashType>::TableReader;
                using AssignmentDescriptionWriter  = AssignmentTableIO<CurveType, HashType>::DescriptionWriter;
                using AssignmentDebugPrinter       = AssignmentTableIO<CurveType, HashType>::DebugPrinter;
                using PreprocessedPublicDataReader = PreprocessedPublicDataIO<CurveType, HashType>::Reader;
                using LpcSchemeReader              = LpcSchemeIO<CurveType, HashType>::Reader;
                using Prover                       = ProveStep<CurveType, HashType>::ProofGenerator;
                using EvmVerifierDebug             = EvmVerifierDebug<CurveType, HashType>;
                using PrivatePreprocessor          = PrivatePreprocessStep<CurveType, HashType>::Executor;

                auto& circuit_reader = add_step<CircuitReader>(args.circuit_file_path);
                auto& table_reader = add_step<AssignmentTableReader>(args.assignment_table_file_path);
                if (!args.out_assignment_desc_file_path.empty()) {
                    add_step<AssignmentDescriptionWriter>(table_reader, args.out_assignment_desc_file_path);
                }
                if (!args.out_assignment_debug_opts.empty()) {
                    add_step<AssignmentDebugPrinter>(table_reader, table_reader, args.out_assignment_debug_opts);
                }
                if (!args.out_evm_verifier_dir_path.empty()) {
                    add_step<typename EvmVerifierDebug::PublicInputPrinter>(args.out_evm_verifier_dir_path, table_reader, table_reader);
                }

                auto& public_data_reader   = add_step<PreprocessedPublicDataReader>(args.public_preprocessed_data_file_path);
                auto& lpc_scheme_reader    = add_step<LpcSchemeReader>(args.lpc_scheme_file_path);
                auto& private_preprocessor = add_step<PrivatePreprocessor>(circuit_reader, table_reader, table_reader);
                add_step<Prover>(
                    circuit_reader, 
                    table_reader, 
                    table_reader, 
                    public_data_reader, 
                    lpc_scheme_reader,
                    private_preprocessor, 
                    args.out_proof_file_path, 
                    args.out_proof_json_file_path
                );
                if (!args.out_evm_verifier_dir_path.empty()) {
                    add_step<typename EvmVerifierDebug::Printer>(circuit_reader, public_data_reader, args.out_evm_verifier_dir_path);
                }
            }
        };


        // TODO move to files
        template<typename CurveType, typename HashType>
        class PartialProofCommand: public command_chain {
        public:
            struct Args {
                boost::filesystem::path circuit_file_path;
                boost::filesystem::path assignment_table_file_path;
                boost::filesystem::path public_preprocessed_data_file_path;
                boost::filesystem::path lpc_scheme_file_path;
            
                OutputArtifacts out_assignment_debug_opts;
                boost::filesystem::path out_evm_verifier_dir_path;
                boost::filesystem::path out_assignment_desc_file_path;
                boost::filesystem::path out_proof_file_path;
                boost::filesystem::path out_challenge_file_path;
                boost::filesystem::path out_theta_power_file_path;
                boost::filesystem::path out_updated_lpc_scheme_file_path;
            }; 

            PartialProofCommand(const Args& args) {
                using CircuitReader                = CircuitIO<CurveType, HashType>::Reader;
                using AssignmentTableReader        = AssignmentTableIO<CurveType, HashType>::TableReader;
                using AssignmentDescriptionWriter  = AssignmentTableIO<CurveType, HashType>::DescriptionWriter;
                using AssignmentDebugPrinter       = AssignmentTableIO<CurveType, HashType>::DebugPrinter;
                using PreprocessedPublicDataReader = PreprocessedPublicDataIO<CurveType, HashType>::Reader;
                using PrivatePreprocessor          = PrivatePreprocessStep<CurveType, HashType>::Executor;
                using LpcSchemeReader              = LpcSchemeIO<CurveType, HashType>::Reader;
                using Prover                       = ProveStep<CurveType, HashType>::PartialProofGenerator;
                using LpcSchemeWriter              = LpcSchemeIO<CurveType, HashType>::Writer;


                auto& circuit_reader = add_step<CircuitReader>(args.circuit_file_path);
                auto& table_reader = add_step<AssignmentTableReader>(args.assignment_table_file_path);
                if (!args.out_assignment_desc_file_path.empty()) {
                    add_step<AssignmentDescriptionWriter>(table_reader, args.out_assignment_desc_file_path);
                }
                if (!args.out_assignment_debug_opts.empty()) {
                    add_step<AssignmentDebugPrinter>(table_reader, table_reader, args.out_assignment_debug_opts);
                }

                auto& public_data_reader   = add_step<PreprocessedPublicDataReader>(args.public_preprocessed_data_file_path);
                auto& lpc_scheme_reader    = add_step<LpcSchemeReader>(args.lpc_scheme_file_path);
                auto& private_preprocessor = add_step<PrivatePreprocessor>(circuit_reader, table_reader, table_reader);
                add_step<Prover>(
                    circuit_reader, 
                    table_reader, 
                    table_reader, 
                    public_data_reader, 
                    lpc_scheme_reader,
                    private_preprocessor, 

                    args.out_proof_file_path,
                    args.out_challenge_file_path,
                    args.out_theta_power_file_path
                );
                add_step<LpcSchemeWriter>(lpc_scheme_reader, args.out_updated_lpc_scheme_file_path);
            }
        }; 

        // TODO move to files
        template<typename CurveType, typename HashType>
        class FastPartialProofCommand: public command_chain {
        public:
            struct Args {
                PlaceholderConfig config;
                std::string circuit_name;
                boost::filesystem::path trace_file_path;

                boost::filesystem::path out_proof_file_path;
                boost::filesystem::path out_challenge_file_path;
                boost::filesystem::path out_theta_power_file_path;
                boost::filesystem::path out_updated_lpc_scheme_file_path;
            }; 

            FastPartialProofCommand(const Args& args) {
                using Preset                = PresetStep<CurveType, HashType>::Executor;
                using Assigner              = FillAssignmentStep<CurveType, HashType>::Executor;
                using PublicPreprocessor    = PublicPreprocessStep<CurveType, HashType>::Executor;
                using PrivatePreprocessor   = PrivatePreprocessStep<CurveType, HashType>::Executor;
                using Prover                = ProveStep<CurveType, HashType>::PartialProofGenerator;
                using LpcSchemeWriter       = LpcSchemeIO<CurveType, HashType>::Writer;

                auto& circuit_maker        = add_step<Preset>(args.circuit_name);                                              
                auto& assigner             = add_step<Assigner>(circuit_maker, circuit_maker, args.circuit_name, args.trace_file_path); 
                auto& public_preprocessor  = add_step<PublicPreprocessor>(args.config, assigner, assigner, circuit_maker);
                auto& private_preprocessor = add_step<PrivatePreprocessor>(circuit_maker, assigner, assigner);

                add_step<Prover>(
                    circuit_maker, 
                    assigner,            // for table
                    assigner,            // for table description
                    public_preprocessor, // for public data
                    public_preprocessor, // for LPC scheme
                    private_preprocessor, 

                    args.out_proof_file_path,
                    args.out_challenge_file_path,
                    args.out_theta_power_file_path
                );
                add_step<LpcSchemeWriter>(public_preprocessor, args.out_updated_lpc_scheme_file_path);
            }
        }; 


    } // namespace proof_generator
} // namespace nil


#endif // PROOF_GENERATOR_ASSIGNER_GEN_PROOF_COMMAND_HPP