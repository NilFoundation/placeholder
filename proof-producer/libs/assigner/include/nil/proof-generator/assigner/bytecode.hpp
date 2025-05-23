#ifndef PROOF_GENERATOR_LIBS_ASSIGNER_BYTECODE_HPP_
#define PROOF_GENERATOR_LIBS_ASSIGNER_BYTECODE_HPP_

#include <format>
#include <optional>
#include <boost/log/trivial.hpp>
#include <boost/filesystem.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/circuits/bytecode.hpp>
#include <nil/proof-generator/assigner/trace_parser.hpp>
#include <nil/proof-generator/assigner/options.hpp>

namespace nil {
    namespace proof_producer {

        /// @brief Fill assignment table
        template<typename BlueprintFieldType>
        std::optional<std::string> fill_bytecode_assignment_table(nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>& assignment_table,
                                                             const boost::filesystem::path& trace_base_path,
                                                             const AssignerOptions& options) {

            using ComponentType = nil::blueprint::bbf::zkevm_big_field::bytecode<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;

            typename nil::blueprint::bbf::context<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT> context_object(assignment_table, options.circuits_limits.max_total_rows);

            typename ComponentType::input_type input;
            input.rlc_challenge = options.circuits_limits.RLC_CHALLENGE;

            const auto bytecode_trace_path = get_bytecode_trace_path(trace_base_path);
            BOOST_LOG_TRIVIAL(debug) << "fill bytecode table from " << bytecode_trace_path << "\n";
            const auto contract_bytecodes = deserialize_bytecodes_from_file(bytecode_trace_path, options);
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
            const auto keccak_operations = deserialize_keccak_traces_from_file(keccak_trace_path, options, contract_bytecodes->index);
            if (!keccak_operations) {
                return "can't read keccak operations from file: " + keccak_trace_path.string();
            }
            for (const auto& keccak_it : keccak_operations->value) {
                input.keccak_buffers.new_buffer(keccak_it.buffer);
            }

            if (total_bytecode_size > options.circuits_limits.max_bytecode_rows) {
                return {std::format("bytecode size {} exceeds circuit limit {}", total_bytecode_size, options.circuits_limits.max_bytecode_rows)};
            }

            ComponentType instance(context_object, input, options.circuits_limits.max_bytecode_rows, options.circuits_limits.max_keccak_blocks);
            return {};
        }
    } // proof_producer
} // nil

#endif  // PROOF_GENERATOR_LIBS_ASSIGNER_BYTECODE_HPP_
