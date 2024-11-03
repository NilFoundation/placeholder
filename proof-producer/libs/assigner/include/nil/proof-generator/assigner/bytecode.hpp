#ifndef PROOF_GENERATOR_LIBS_ASSIGNER_BYTECODE_HPP_
#define PROOF_GENERATOR_LIBS_ASSIGNER_BYTECODE_HPP_

#include <optional>
#include <boost/log/trivial.hpp>
#include <boost/filesystem.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/blueprint/zkevm_bbf/bytecode.hpp>
#include <nil/proof-generator/assigner/trace_parser.hpp>

namespace nil {
    namespace proof_generator {

        /// @brief Fill assignment table
        template<typename BlueprintFieldType>
        std::optional<std::string> fill_bytecode_assignment_table(nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>& assignment_table,
                                                             const boost::filesystem::path& trace_file_path) {
            BOOST_LOG_TRIVIAL(debug) << "fill bytecode table from " << trace_file_path << "\n";

            using ComponentType = nil::blueprint::bbf::bytecode<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;

            std::size_t max_bytecode_size = 1000;
            std::size_t max_keccak_blocks = 30;
            std::size_t max_rows = 500000;

            typename nil::blueprint::bbf::context<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT> context_object(assignment_table, max_rows);

            typename ComponentType::input_type input;
            const auto contract_bytecodes = deserialize_bytecodes_from_file(trace_file_path);
            if (!contract_bytecodes) {
                return "can't read bytecode trace from file";
            }
            for (const auto& bytecode_it : contract_bytecodes.value()) {
                const auto raw_bytecode = string_to_bytes(bytecode_it.second);
                input.bytecodes.new_buffer(raw_bytecode);
                input.keccak_buffers.new_buffer(raw_bytecode);
            }

            ComponentType instance(context_object, input, max_bytecode_size, max_keccak_blocks);
            return {};
        }
    } // proof_generator
} // nil

#endif  // PROOF_GENERATOR_LIBS_ASSIGNER_BYTECODE_HPP_
