#ifndef PROOF_GENERATOR_LIBS_ASSIGNER_ASSIGNER_HPP_
#define PROOF_GENERATOR_LIBS_ASSIGNER_ASSIGNER_HPP_

#include <nil/proof-generator/assigner/bytecode.hpp>
#include <nil/proof-generator/assigner/rw.hpp>
#include <nil/proof-generator/assigner/zkevm.hpp>

namespace nil {
    namespace proof_generator {

        template<typename BlueprintFieldType>
        std::map<const std::string, std::function<std::optional<std::string>(
                    nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>& assignment_table,
                    const boost::filesystem::path& trace_file_path)>> circuit_selector = {
                {"bytecode", fill_bytecode_assignment_table<BlueprintFieldType>},
                {"rw", fill_rw_assignment_table<BlueprintFieldType>},
                {"zkevm", fill_zkevm_assignment_table<BlueprintFieldType>}
        };

        template<typename BlueprintFieldType>
        void set_paddnig(nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>& assignment_table) {
            std::uint32_t used_rows_amount = assignment_table.rows_amount();

            std::uint32_t padded_rows_amount = std::pow(2, std::ceil(std::log2(used_rows_amount)));
            if (padded_rows_amount == used_rows_amount) {
                padded_rows_amount *= 2;
            }
            if (padded_rows_amount < 8) {
                padded_rows_amount = 8;
            }

            assignment_table.resize_witnesses(padded_rows_amount);
            for (std::uint32_t i = 0; i < assignment_table.witnesses_amount(); i++) {
                for (std::uint32_t j = assignment_table.witness_column_size(i); j < padded_rows_amount; j++) {
                    assignment_table.witness(i, j) = 0;
                }
            }

            assignment_table.resize_public_inputs(padded_rows_amount);
            for (std::uint32_t i = 0; i < assignment_table.public_inputs_amount(); i++) {
                for (std::uint32_t j = assignment_table.public_input_column_size(i); j < padded_rows_amount; j++) {
                    assignment_table.public_input(i, j) = 0;
                }
            }

            assignment_table.resize_constants(padded_rows_amount);
            for (std::uint32_t i = 0; i < assignment_table.constants_amount(); i++) {
                for (std::uint32_t j = assignment_table.constant_column_size(i); j < padded_rows_amount; j++) {
                    assignment_table.constant(i, j) = 0;
                }
            }

            assignment_table.resize_selectors(padded_rows_amount);
            for (std::uint32_t i = 0; i < assignment_table.selectors_amount(); i++) {
                for (std::uint32_t j = assignment_table.selector_column_size(i); j < padded_rows_amount; j++) {
                    assignment_table.selector(i, j) = 0;
                }
            }
        }

        template<typename BlueprintFieldType>
        std::optional<std::string> fill_assignment_table_single_thread(nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>& assignment_table,
                                                                       nil::crypto3::zk::snark::plonk_table_description<BlueprintFieldType>& desc,
                                                                       const std::string& circuit_name,
                                                                       const boost::filesystem::path& trace_file_path) {
            auto find_it = circuit_selector<BlueprintFieldType>.find(circuit_name);
            if (find_it == circuit_selector<BlueprintFieldType>.end()) {
                return "Unknown circuit name " + circuit_name;
            }
            const auto err = find_it->second(assignment_table, trace_file_path);
            if (err) {
                return err;
            }
            desc.usable_rows_amount = assignment_table.rows_amount();
            set_paddnig(assignment_table);
            desc.rows_amount = assignment_table.rows_amount();
            return {};
        }
    } // proof_generator
} // nil

#endif  // PROOF_GENERATOR_LIBS_ASSIGNER__ASSIGNER_HPP_
