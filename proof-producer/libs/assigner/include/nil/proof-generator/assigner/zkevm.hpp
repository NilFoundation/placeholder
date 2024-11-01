#ifndef PROOF_GENERATOR_LIBS_ASSIGNER_ZKEVM_HPP_
#define PROOF_GENERATOR_LIBS_ASSIGNER_BYTECODE_HPP_

#include <boost/log/trivial.hpp>

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

            std::size_t max_zkevm_rows = 500;
            std::size_t max_copy = 500;
            std::size_t max_rw = 500;
            std::size_t max_keccak_blocks = 30;
            std::size_t max_bytecode = 1000;
            std::size_t max_rows = 500000;

            typename nil::blueprint::bbf::context<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT> context_object(assignment_table, max_rows);

            //TODO read from trace
            std::vector<std::uint8_t> raw_bytecode = {0x60, 0x04, 0x60, 0x08, 0x02}; // 4*8
            typename ComponentType::input_type input;
            // bytecode
            input.bytecodes.new_buffer(raw_bytecode);
            input.keccak_buffers.new_buffer(raw_bytecode);
            // rw
            size_t call_id = 0;
            size_t rw_id = 0;
            std::vector<uint8_t> bytes_0 = {0x04};
            std::vector<uint8_t> bytes_1 = {0x08};
            std::vector<std::size_t> stack_size = {0, 1, 2, 1, 0};
            nil::blueprint::zkevm_word_type value_0 = nil::blueprint::zkevm_word_from_bytes(bytes_0);
            nil::blueprint::zkevm_word_type value_1 = nil::blueprint::zkevm_word_from_bytes(bytes_1);
            input.rw_operations.push_back(nil::blueprint::bbf::stack_rw_operation(call_id, stack_size[rw_id], rw_id++, true, value_0));
            input.rw_operations.push_back(nil::blueprint::bbf::stack_rw_operation(call_id, stack_size[rw_id], rw_id++, true, value_1));
            input.rw_operations.push_back(nil::blueprint::bbf::stack_rw_operation(call_id, stack_size[rw_id], rw_id++, false, value_1));
            input.rw_operations.push_back(nil::blueprint::bbf::stack_rw_operation(call_id, stack_size[rw_id], rw_id++, false, value_0));
            input.rw_operations.push_back(nil::blueprint::bbf::stack_rw_operation(call_id, stack_size[rw_id], rw_id++, true, value_0 * value_1));
            // no copy events
            // states
            std::vector<nil::blueprint::zkevm_word_type> stack;
            std::map<std::size_t, std::uint8_t> memory;
            std::map<nil::blueprint::zkevm_word_type, nil::blueprint::zkevm_word_type> storage;
            input.zkevm_states.push_back(nil::blueprint::bbf::zkevm_state(stack, memory, storage));
            stack.insert(stack.begin(), value_0);
            input.zkevm_states.push_back(nil::blueprint::bbf::zkevm_state(stack, memory, storage));
            stack.insert(stack.begin(), value_1);
            input.zkevm_states.push_back(nil::blueprint::bbf::zkevm_state(stack, memory, storage));

            ComponentType instance(context_object, input, max_zkevm_rows, max_copy, max_rw, max_keccak_blocks, max_bytecode);
            return {};
        }
    } // proof_generator
} // nil

#endif  // PROOF_GENERATOR_LIBS_ASSIGNER_ZKEVM_HPP_
