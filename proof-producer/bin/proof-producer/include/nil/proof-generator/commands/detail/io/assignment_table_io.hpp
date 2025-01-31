#pragma once

#include <memory>

#include <boost/log/trivial.hpp>
#include <boost/filesystem.hpp>

#include <nil/proof-generator/resources.hpp>
#include <nil/proof-generator/types/type_system.hpp>
#include <nil/proof-generator/command_step.hpp>
#include <nil/proof-generator/marshalling_utils.hpp>
#include <nil/proof-generator/output_artifacts/output_artifacts.hpp>
#include <nil/proof-generator/output_artifacts/assignment_table_writer.hpp>


namespace nil {
    namespace proof_generator {
 
        template <typename CurveType, typename HashType>
        struct AssignmentTableIO {

            using Types = TypeSystem<CurveType, HashType>;
            using BlueprintField = typename Types::BlueprintField;
            using Endianness = typename Types::Endianness;
            using TTypeBase = typename Types::TTypeBase;
            using AssignmentTable = typename Types::AssignmentTable;
            using TableDescription = typename Types::TableDescription;
            using TableMarshalling = typename Types::TableMarshalling;

            struct BinaryWriter: public command_step {

                BinaryWriter(
                    resources::resource_provider<AssignmentTable>& table_provider,
                    resources::resource_provider<TableDescription>& description_provider,
                    const boost::filesystem::path& output_filename): 
                output_filename_ (output_filename) 
                {
                    resources::subscribe_value<AssignmentTable>(table_provider, assignment_table_);
                    resources::subscribe_value<TableDescription>(description_provider, table_description_);
                }

                CommandResult execute() override {
                    using writer = assignment_table_writer<Endianness, BlueprintField>;

                    BOOST_LOG_TRIVIAL(info) << "Writing binary assignment table to " << output_filename_;

                    if (!assignment_table_ || !table_description_) {
                        return CommandResult::UnknownError("No assignment table is currently loaded");
                    }

                    std::ofstream out(output_filename_.string(), std::ios::binary | std::ios::out);
                    if (!out.is_open()) {
                        return CommandResult::UnknownError("Failed to open file {}", output_filename_.string());
                    }

                    writer::write_binary_assignment(
                        out, *assignment_table_, *table_description_
                    );

                    return CommandResult::Ok();
                }

            private:
                const boost::filesystem::path output_filename_;
                std::shared_ptr<AssignmentTable> assignment_table_;
                std::shared_ptr<TableDescription> table_description_;
            };

            struct DescriptionWriter: public command_step {

                DescriptionWriter(
                    resources::resource_provider<TableDescription>& description_provider,
                    const boost::filesystem::path& assignment_description_file_path
                ): assignment_description_file_path_(assignment_description_file_path) 
                {
                    resources::subscribe_value<TableDescription>(description_provider, table_description_);
                }

                CommandResult execute() override {
                    BOOST_ASSERT(table_description_);
                    BOOST_LOG_TRIVIAL(info) << "Writing assignment description to " << assignment_description_file_path_;

                    auto marshalled_assignment_description =
                        nil::crypto3::marshalling::types::fill_assignment_table_description<Endianness, BlueprintField>(
                            *table_description_
                    );
                    bool res = detail::encode_marshalling_to_file(
                        assignment_description_file_path_,
                        marshalled_assignment_description
                    );
                    if (!res) {
                        return CommandResult::UnknownError("Failed to write assignment description");
                    } 

                    BOOST_LOG_TRIVIAL(info) << "Assignment description written.";
                    return CommandResult::Ok();
                }

            private:
                const boost::filesystem::path assignment_description_file_path_;
                std::shared_ptr<TableDescription> table_description_;
            };


            struct DebugPrinter: public command_step {
                DebugPrinter(
                    resources::resource_provider<AssignmentTable>& table_provider,
                    resources::resource_provider<TableDescription>& description_provider,
                    const OutputArtifacts& opts):
                    opts_(opts)
                {
                    resources::subscribe_value<AssignmentTable>(table_provider, assignment_table_);
                    resources::subscribe_value<TableDescription>(description_provider, table_description_);
                }

                CommandResult execute() override 
                {
                    BOOST_ASSERT(!opts_.empty());

                    if (!assignment_table_ || !table_description_) {
                        return CommandResult::UnknownError("No assignment table is currently loaded");
                    }

                    BOOST_LOG_TRIVIAL(debug) << "Rows to print: " << opts_.rows.to_string();
                    BOOST_LOG_TRIVIAL(debug) << "Witness columns to print: "
                                            << opts_.witness_columns.to_string();
                    BOOST_LOG_TRIVIAL(debug) << "Public input columns to print: "
                                            << opts_.public_input_columns.to_string();
                    BOOST_LOG_TRIVIAL(debug) << "Constant columns to print: "
                                            << opts_.constant_columns.to_string();
                    BOOST_LOG_TRIVIAL(debug) << "Selector columns to print: "
                                            << opts_.selector_columns.to_string();

                    const auto write = [&](std::ostream& out) -> CommandResult {
                        auto const res = assignment_table_writer<Endianness, BlueprintField>::write_text_assignment(
                            out,
                            *assignment_table_,
                            *table_description_,
                            opts_
                        );
                        if (!res) {
                            return CommandResult::UnknownError("Failed to write text assignment table");
                        }
                        return CommandResult::Ok();
                    };

                    if (opts_.to_stdout()) {
                        BOOST_LOG_TRIVIAL(info) << "Writing text assignment table to stdout";
                        return write(std::cout);
                    }

                    BOOST_LOG_TRIVIAL(info) << "Writing text assignment table to " << opts_.output_filename;
                    std::ofstream out(opts_.output_filename, std::ios::binary | std::ios::out);
                    if (!out.is_open()) {
                        return CommandResult::UnknownError("Failed to open file {}",  opts_.output_filename);
                    }

                    return write(out);
                }

            private:
                const OutputArtifacts opts_;
                std::shared_ptr<AssignmentTable> assignment_table_;
                std::shared_ptr<TableDescription> table_description_;
            };


            struct TableReader:
                public command_step,
                public resources::resources_provider<AssignmentTable, TableDescription>
            {

                TableReader(const boost::filesystem::path& assignment_table_file_path):
                    assignment_table_file_path_(assignment_table_file_path)
                {}

                CommandResult execute() override {
                    using resources::notify;

                    BOOST_LOG_TRIVIAL(info) << "Read assignment table from " << assignment_table_file_path_;

                    auto marshalled_table =
                        detail::decode_marshalling_from_file<TableMarshalling>(assignment_table_file_path_);
                    if (!marshalled_table) {
                        return CommandResult::UnknownError("Failed to read assignment table from {}", assignment_table_file_path_.string());
                    }

                    auto [table_description, assignment_table] =
                        nil::crypto3::marshalling::types::make_assignment_table<Endianness, AssignmentTable>(
                            *marshalled_table
                        );

                    notify<AssignmentTable>(*this, std::make_shared<AssignmentTable>(std::move(assignment_table)));
                    notify<TableDescription>(*this, std::make_shared<TableDescription>(std::move(table_description)));

                    return CommandResult::Ok();
                }
            private:
                const boost::filesystem::path assignment_table_file_path_;
            };

            struct DescriptionReader:
                public command_step,
                public resources::resource_provider<TableDescription>
            {

                DescriptionReader(const boost::filesystem::path& assignment_description_file):
                    assignment_description_file_(assignment_description_file)
                {}

                CommandResult execute() override {
                    BOOST_LOG_TRIVIAL(info) << "Read assignment description from " << assignment_description_file_;
                    using resources::notify;

                    using TableDescriptionMarshalling =
                        nil::crypto3::marshalling::types::plonk_assignment_table_description<TTypeBase>;
                    auto marshalled_description =
                        detail::decode_marshalling_from_file<TableDescriptionMarshalling>(assignment_description_file_);
                    if (!marshalled_description) {
                        return CommandResult::UnknownError("Failed to read assignment description from {}", assignment_description_file_.string());
                    }
                    auto table_description =
                        nil::crypto3::marshalling::types::make_assignment_table_description<Endianness, BlueprintField>(
                            *marshalled_description
                        );

                    notify<TableDescription>(*this, std::make_shared<TableDescription>(std::move(table_description)));

                    return CommandResult::Ok();
                }

            private:
                const boost::filesystem::path assignment_description_file_;
            };
        };

    } // namespace proof_generator
} // namespace nil
