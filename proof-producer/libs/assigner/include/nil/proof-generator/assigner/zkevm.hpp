#ifndef PROOF_GENERATOR_LIBS_ASSIGNER_ZKEVM_HPP_
#define PROOF_GENERATOR_LIBS_ASSIGNER_ZKEVM_HPP_

#include <optional>
#include <boost/log/trivial.hpp>
#include <boost/filesystem.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/blueprint/zkevm_bbf/zkevm.hpp>
#include <nil/proof-generator/assigner/options.hpp>
#include <nil/proof-generator/assigner/trace_parser.hpp>

namespace nil {
    namespace proof_generator {

        /// @brief Fill assignment table
        template<typename BlueprintFieldType>
        std::optional<std::string> fill_zkevm_assignment_table(nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>& assignment_table,
                                                             const boost::filesystem::path& trace_base_path,
                                                             const AssignerOptions& options) {
            BOOST_LOG_TRIVIAL(debug) << "fill zkevm table from " << trace_base_path << "\n";

            using ComponentType = nil::blueprint::bbf::zkevm<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;

            typename nil::blueprint::bbf::context<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT> context_object(assignment_table, options.circuits_limits.max_rows);

            typename ComponentType::input_type input;

            // bytecode
            const auto bytecode_trace_path = get_bytecode_trace_path(trace_base_path);
            const auto contract_bytecodes = deserialize_bytecodes_from_file(bytecode_trace_path, options);
            if (!contract_bytecodes) {
                return "can't read bytecode from file: " + bytecode_trace_path.string();
            }
            for (const auto& bytecode_it : contract_bytecodes->value) {
                const auto raw_bytecode = string_to_bytes(bytecode_it.second);
                input.bytecodes.new_buffer(raw_bytecode);
                input.keccak_buffers.new_buffer(raw_bytecode);
            }

            // rw
            const auto rw_trace_path = get_rw_trace_path(trace_base_path);
            auto rw_operations = deserialize_rw_traces_from_file(rw_trace_path, options, contract_bytecodes->index);
            if (!rw_operations) {
                return "can't read rw from file: " + rw_trace_path.string();
            }
            input.rw_operations = std::move(rw_operations->value);

            // states
            const auto zkevm_trace_path = get_zkevm_trace_path(trace_base_path);
            const auto zkevm_states = deserialize_zkevm_state_traces_from_file(zkevm_trace_path, options, contract_bytecodes->index);
            if (!zkevm_states) {
                return "can't read zkevm states from file: " + zkevm_trace_path.string();
            }
            input.zkevm_states = std::move(zkevm_states->value);

            const auto copy_trace_path = get_copy_trace_path(trace_base_path);
            const auto copy_events = deserialize_copy_events_from_file(copy_trace_path, options, contract_bytecodes->index);
            if (!copy_events) {
                return "can't read copy events from file: " + copy_trace_path.string();
            }
            input.copy_events = std::move(copy_events->value);

            const auto exp_trace_path = get_exp_trace_path(trace_base_path);
            const auto exp_operations = deserialize_exp_traces_from_file(exp_trace_path, options, contract_bytecodes->index);
            if (!exp_operations) {
                return "can't read exp operations from file: " + exp_trace_path.string();
            }
            input.exponentiations = std::move(exp_operations->value);

            ComponentType instance(
                context_object,
                input,
                options.circuits_limits.max_zkevm_rows,
                options.circuits_limits.max_copy,
                options.circuits_limits.max_rw_size,
                options.circuits_limits.max_keccak_blocks,
                options.circuits_limits.max_bytecode_size
            );

            return {};
        }
    } // proof_generator
} // nil

#endif  // PROOF_GENERATOR_LIBS_ASSIGNER_ZKEVM_HPP_
