#ifndef PROOF_GENERATOR_LIBS_ASSIGNER_ZKEVM_HPP_
#define PROOF_GENERATOR_LIBS_ASSIGNER_BYTECODE_HPP_

#include <optional>
#include <chrono>
#include <boost/log/trivial.hpp>
#include <boost/filesystem.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/blueprint/zkevm_bbf/zkevm.hpp>
#include <nil/proof-generator/assigner/trace_parser.hpp>

namespace nil {
    namespace proof_generator {

        /// @brief Fill assignment table
        template<typename BlueprintFieldType>
        std::optional<std::string> fill_zkevm_assignment_table(nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>& assignment_table,
                                                             const boost::filesystem::path& trace_file_path) {
            BOOST_LOG_TRIVIAL(debug) << "fill zkevm table from " << trace_file_path << "\n";

            using ComponentType = nil::blueprint::bbf::zkevm<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;

            std::size_t max_zkevm_rows = 10000;
            std::size_t max_copy = 500;
            std::size_t max_rw = 15000;
            std::size_t max_keccak_blocks = 100;
            std::size_t max_bytecode = 10000;
            std::size_t max_rows = 500000;

            typename nil::blueprint::bbf::context<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT> context_object(assignment_table, max_rows);

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

            // no copy events
            // states
            std::vector<nil::blueprint::zkevm_word_type> stack;
            std::map<std::size_t, std::uint8_t> memory;
            std::map<nil::blueprint::zkevm_word_type, nil::blueprint::zkevm_word_type> storage;
            input.zkevm_states.push_back(nil::blueprint::bbf::zkevm_state(stack, memory, storage));

            auto start = std::chrono::high_resolution_clock::now();
            ComponentType instance(context_object, input, max_zkevm_rows, max_copy, max_rw, max_keccak_blocks, max_bytecode);
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
            std::cout << "FILL ASSIGNMENT TABLE: " << duration.count() << "\n";
            return {};
        }
    } // proof_generator
} // nil

#endif  // PROOF_GENERATOR_LIBS_ASSIGNER_ZKEVM_HPP_
