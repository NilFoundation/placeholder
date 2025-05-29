#ifndef PROOF_GENERATOR_LIBS_ASSIGNER_COPY_HPP_
#define PROOF_GENERATOR_LIBS_ASSIGNER_COPY_HPP_

#include <optional>

#include <boost/log/trivial.hpp>
#include <boost/filesystem.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/circuits/copy.hpp>
#include <nil/proof-generator/assigner/options.hpp>
#include <nil/proof-generator/assigner/trace_parser.hpp>

namespace nil {
    namespace proof_producer {

        /// @brief Fill assignment table
        template<typename BlueprintFieldType>
        std::optional<std::string> fill_copy_events_assignment_table(nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>& assignment_table,
                                                             const boost::filesystem::path& trace_base_path,
                                                             const AssignerOptions& options) {
            BOOST_LOG_TRIVIAL(debug) << "fill copy table from " << trace_base_path << "\n";

            using ComponentType = nil::blueprint::bbf::zkevm_big_field::copy<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;

            typename nil::blueprint::bbf::context<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT> context_object(assignment_table, options.circuits_limits.max_total_rows);

            typename ComponentType::input_type input;
            input.rlc_challenge = options.circuits_limits.RLC_CHALLENGE;

            const auto copy_trace_path = get_copy_trace_path(trace_base_path);
            auto copy_events = deserialize_copy_events_from_file(copy_trace_path, options);
            if (!copy_events) {
                return "can't read copy events from file: " + copy_trace_path.string();
            }
            input.copy_events = std::move(copy_events->value);

            const auto bytecode_trace_path = get_bytecode_trace_path(trace_base_path);
            const auto contract_bytecodes = deserialize_bytecodes_from_file(bytecode_trace_path, options, copy_events->index);
            if (!contract_bytecodes) {
                return "can't read bytecode trace from file: " + bytecode_trace_path.string();
            }
            size_t total_bytecode_size = 0;
            for (const auto& bytecode_it : contract_bytecodes->value) {
                const auto raw_bytecode = string_to_bytes(bytecode_it.second);
                total_bytecode_size += raw_bytecode.size();
                input.bytecodes.new_buffer(raw_bytecode);
                input.keccak_buffers.new_buffer(raw_bytecode);
            }

            const auto keccak_trace_path = get_keccak_trace_path(trace_base_path);
            auto keccak_buffers = deserialize_keccak_traces_from_file(keccak_trace_path, options, copy_events->index);
            if (!keccak_buffers) {
                return "can't read keccak buffers trace from file: " + keccak_trace_path.string();
            }
            for (const auto& keccak_buffer : keccak_buffers->value) {
                input.keccak_buffers.new_buffer(keccak_buffer.buffer);
            }

            const auto rw_trace_path = get_rw_trace_path(trace_base_path);
            auto rw_operations = deserialize_rw_traces_from_file(rw_trace_path, options, copy_events->index);
            if (!rw_operations) {
                return "can't read rw operations trace from file: " + rw_trace_path.string();
            }
            input.rw_operations = std::move(rw_operations->value);

            // TODO: there is no defined relation between input size and row size:
            // replace these checks with handling of an error returned by component instantiation
            if (total_bytecode_size > options.circuits_limits.max_bytecode_rows) {
                return std::format("bytecode size {} exceeds circuit limit {}", total_bytecode_size, options.circuits_limits.max_bytecode_rows);
            }
            if (input.rw_operations.size() > options.circuits_limits.max_rw_rows) {
                return std::format("rw operations size {} exceeds circuit limit {}", input.rw_operations.size(), options.circuits_limits.max_rw_rows);
            }
            size_t total_copy_bytes = 0;
            for (const auto &copy_event : input.copy_events) {
                total_copy_bytes += copy_event.get_bytes().size();
            }
            size_t expected_copy_table_size = total_copy_bytes * 2;
            if (expected_copy_table_size > options.circuits_limits.max_copy_rows) {
                return std::format("estimated size of copy table {} exceeds circuit limit {}", expected_copy_table_size, input.copy_events.size());
            }

            ComponentType instance(
                context_object,
                input,
                options.circuits_limits.max_copy_rows,
                options.circuits_limits.max_rw_rows,
                options.circuits_limits.max_keccak_blocks,
                options.circuits_limits.max_bytecode_rows
            );

            return {};
        }
    } // proof_producer
} // nil

#endif  // PROOF_GENERATOR_LIBS_ASSIGNER_COPY_HPP_
