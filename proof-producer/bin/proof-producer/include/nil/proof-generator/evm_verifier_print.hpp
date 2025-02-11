#pragma once

#include <memory>
#include <optional>
#include <fstream>

#include <boost/log/trivial.hpp>
#include <boost/filesystem.hpp>
#include <boost/assert.hpp>

#include <nil/proof-generator/command_step.hpp>
#include <nil/proof-generator/resources.hpp>
#include <nil/proof-generator/types/type_system.hpp>
#include <nil/blueprint/transpiler/lpc_evm_verifier_gen.hpp>

namespace nil {
    namespace proof_producer {

        template <typename CurveType, typename HashType>
        struct EvmVerifierDebug {

            using Types = TypeSystem<CurveType, HashType>;
            using PlaceholderParams = typename Types::PlaceholderParams;
            using ConstraintSystem = typename Types::ConstraintSystem;
            using PublicPreprocessedData = typename Types::PublicPreprocessedData;
            using CommonData = typename Types::CommonData;
            using TableDescription = typename Types::TableDescription;
            using AssignmentTable = typename Types::AssignmentTable;
            using AssignmentPublicInput = typename Types::AssignmentPublicInput;


            struct Printer: public command_step {

                Printer(
                    resources::resource_provider<ConstraintSystem>& constraint_system_provider,
                    resources::resource_provider<CommonData>& common_data_provider,
                    boost::filesystem::path output_folder
                ): output_folder_(output_folder)
                {
                    resources::subscribe_value<ConstraintSystem>(constraint_system_provider, constraint_system_);
                    resources::subscribe_value<CommonData>(common_data_provider, common_data_);
                }

                CommandResult execute() override {
                    BOOST_ASSERT(constraint_system_);
                    BOOST_ASSERT(common_data_);

                    BOOST_LOG_TRIVIAL(info) << "Print evm verifier";
                    nil::blueprint::lpc_evm_verifier_printer<PlaceholderParams> evm_verifier_printer(
                        *constraint_system_,
                        *common_data_,
                        output_folder_.string()
                    );
                    evm_verifier_printer.print();
                    return CommandResult::Ok();
                }

            private:
                boost::filesystem::path output_folder_;
                std::shared_ptr<ConstraintSystem> constraint_system_;
                std::shared_ptr<CommonData> common_data_;
            };

            struct PublicInputPrinter: public command_step {

                PublicInputPrinter(
                    boost::filesystem::path output_folder,
                    resources::resource_provider<TableDescription>& table_description_provider,
                    resources::resource_provider<AssignmentTable>& assignment_table_provider
                ): output_folder_(output_folder)
                {
                    resources::subscribe_value<TableDescription>(table_description_provider, table_description_);
                    resources::subscribe<AssignmentTable>(assignment_table_provider, [&](std::shared_ptr<AssignmentTable> assignment_table) {
                        public_inputs_.emplace(assignment_table->public_inputs()); // public inputs are small enough to be copied
                    });
                }

                CommandResult execute() override {
                    BOOST_ASSERT(public_inputs_);
                    BOOST_ASSERT(table_description_);

                    BOOST_LOG_TRIVIAL(info) << "Print public input for EVM";
                    std::ofstream pi_stream;
                    pi_stream.open(output_folder_.string() + "/public_input.inp");

                    if(!pi_stream.is_open()) {
                        return CommandResult::Error(ResultCode::IOError, "Can't open file {}/public_input.inp", output_folder_.string());
                    }

                    // Does not support public input columns.
                    if( table_description_->public_input_columns != 0 ) {
                        std::size_t max_non_zero = 0;
                        const auto& public_input = public_inputs_->at(0);
                        for (std::size_t i = 0; i < public_input.size(); i++) {
                            if (public_input[i] != 0u) {
                                max_non_zero = i + 1;
                            }
                        }
                        for (std::size_t i = 0; i < std::min(public_input.size(), max_non_zero); i++) {
                            pi_stream << public_input[i] << "\n";
                        }
                    } // else empty file is generated
                    pi_stream.close();
                    return CommandResult::Ok();
                }
            private:
                boost::filesystem::path output_folder_;
                std::shared_ptr<TableDescription> table_description_;
                std::optional<AssignmentPublicInput> public_inputs_;
            };
        };

    } // namespace proof_producer
} // namespace nil
