#ifndef PROOF_GENERATOR_LIBS_ASSIGNER_ZKEVM_HPP_
#define PROOF_GENERATOR_LIBS_ASSIGNER_ZKEVM_HPP_

#include <optional>
#include <chrono>
#include <boost/log/trivial.hpp>
#include <boost/filesystem.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/blueprint/zkevm_bbf/zkevm.hpp>
#include <nil/proof-generator/assigner/trace_parser.hpp>
#include <nil/proof-generator/preset/limits.hpp>


namespace nil {
    namespace proof_generator {

        /// @brief Fill assignment table
        template<typename BlueprintFieldType>
        std::optional<std::string> fill_zkevm_assignment_table(nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>& assignment_table,
                                                             const boost::filesystem::path& trace_file_path) {
            BOOST_LOG_TRIVIAL(debug) << "fill zkevm table from " << trace_file_path << "\n";

            using ComponentType = nil::blueprint::bbf::zkevm<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;

            typename nil::blueprint::bbf::context<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT> context_object(assignment_table, limits::max_rows);

            typename ComponentType::input_type input;

            // bytecode
            const auto contract_bytecodes = deserialize_bytecodes_from_file(trace_file_path);
            if (!contract_bytecodes) {
                return "can't read bytecode from file";
            }
            for (const auto& bytecode_it : contract_bytecodes.value()) {
                const auto raw_bytecode = string_to_bytes(bytecode_it.second);
                input.bytecodes.new_buffer(raw_bytecode);
                input.keccak_buffers.new_buffer(raw_bytecode);
            }

            // rw
            const auto rw_operations = deserialize_rw_traces_from_file(trace_file_path);
            if (!rw_operations) {
                return "can't read rw from file";
            }
            for (const auto& stack_op : rw_operations->stack_ops) {
                input.rw_operations.push_back(stack_op);
            }
            for (const auto& memory_op : rw_operations->memory_ops) {
                input.rw_operations.push_back(memory_op);
            }
            for (const auto& storage_op : rw_operations->storage_ops) {
                input.rw_operations.push_back(storage_op);
            }

            
            // states
            const auto zkevm_states = deserialize_zkevm_state_traces_from_file(trace_file_path);
            if (!zkevm_states) {
                return "can't read zkevm states from file";
            }
            input.zkevm_states = zkevm_states.value();

            const auto copy_events = deserialize_copy_events_from_file(trace_file_path);
            if (!copy_events) {
                return "can't read copy events from file";
            }
            input.copy_events = copy_events.value();

            auto start = std::chrono::high_resolution_clock::now();
            ComponentType instance(
                context_object, 
                input, 
                limits::max_zkevm_rows, 
                limits::max_copy, 
                limits::max_rw_size, 
                limits::max_keccak_blocks, 
                limits::max_bytecode_size
            );
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
            std::cout << "FILL ASSIGNMENT TABLE: " << duration.count() << "\n";
            return {};
        }
    } // proof_generator
} // nil

#endif  // PROOF_GENERATOR_LIBS_ASSIGNER_ZKEVM_HPP_
