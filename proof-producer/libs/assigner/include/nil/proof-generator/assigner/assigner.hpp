#ifndef PROOF_GENERATOR_LIBS_ASSIGNER_ASSIGNER_HPP_
#define PROOF_GENERATOR_LIBS_ASSIGNER_ASSIGNER_HPP_

#include <nil/proof-generator/preset/preset.hpp>

#include <nil/proof-generator/assigner/options.hpp>
#include <nil/proof-generator/assigner/bytecode.hpp>
#include <nil/proof-generator/assigner/rw.hpp>
#include <nil/proof-generator/assigner/copy.hpp>
#include <nil/proof-generator/assigner/zkevm.hpp>
#include <nil/proof-generator/assigner/trace_parser.hpp>


namespace nil {
    namespace proof_generator {

        using AssignmentTableFiller = std::function<std::optional<std::string>(
            crypto3::zk::snark::plonk_assignment_table<nil::crypto3::algebra::fields::pallas_fq>& assignment_table,
            const boost::filesystem::path& trace_base_path,
            const AssignerOptions& options)
        >;

        template<typename BlueprintFieldType>
        std::map<const std::string, AssignmentTableFiller> circuit_selector = {
                {circuits::BYTECODE, fill_bytecode_assignment_table<BlueprintFieldType>},
                {circuits::RW, fill_rw_assignment_table<BlueprintFieldType>},
                {circuits::ZKEVM, fill_zkevm_assignment_table<BlueprintFieldType>},
                {circuits::COPY, fill_copy_events_assignment_table<BlueprintFieldType>}
        };

        template<typename BlueprintFieldType>
        void set_padding(nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>& assignment_table) {
            std::uint32_t used_rows_amount = assignment_table.rows_amount();

            std::uint32_t padded_rows_amount = std::pow(2, std::ceil(std::log2(used_rows_amount)));
            if (padded_rows_amount == used_rows_amount) {
                padded_rows_amount *= 2;
            }
            if (padded_rows_amount < 8) {
                padded_rows_amount = 8;
            }

            for (std::uint32_t i = 0; i < assignment_table.witnesses_amount(); i++) {
                for (std::uint32_t j = assignment_table.witness_column_size(i); j < padded_rows_amount; j++) {
                    assignment_table.witness(i, j) = 0;
                }
            }

            for (std::uint32_t i = 0; i < assignment_table.public_inputs_amount(); i++) {
                for (std::uint32_t j = assignment_table.public_input_column_size(i); j < padded_rows_amount; j++) {
                    assignment_table.public_input(i, j) = 0;
                }
            }

            for (std::uint32_t i = 0; i < assignment_table.constants_amount(); i++) {
                for (std::uint32_t j = assignment_table.constant_column_size(i); j < padded_rows_amount; j++) {
                    assignment_table.constant(i, j) = 0;
                }
            }

            for (std::uint32_t i = 0; i < assignment_table.selectors_amount(); i++) {
                for (std::uint32_t j = assignment_table.selector_column_size(i); j < padded_rows_amount; j++) {
                    assignment_table.selector(i, j) = 0;
                }
            }
        }

        template<typename BlueprintFieldType>
        std::optional<std::string> fill_assignment_table_single_thread(crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>& assignment_table,
                                                                       crypto3::zk::snark::plonk_table_description<BlueprintFieldType>& desc,
                                                                       const std::string& circuit_name,
                                                                       const boost::filesystem::path& trace_base_path,
                                                                       const AssignerOptions& options = {}) {
            auto find_it = circuit_selector<BlueprintFieldType>.find(circuit_name);
            if (find_it == circuit_selector<BlueprintFieldType>.end()) {
                return "Unknown circuit name " + circuit_name;
            }
            const auto err = find_it->second(assignment_table, trace_base_path, options);
            if (err) {
                return err;
            }
            desc.usable_rows_amount = assignment_table.rows_amount();
            set_padding(assignment_table);
            desc.rows_amount = assignment_table.rows_amount();
            BOOST_LOG_TRIVIAL(debug) << "total rows amount = " << desc.rows_amount << " for " << circuit_name << "\n";
            return {};
        }
    } // proof_generator
} // nil

#endif  // PROOF_GENERATOR_LIBS_ASSIGNER__ASSIGNER_HPP_
