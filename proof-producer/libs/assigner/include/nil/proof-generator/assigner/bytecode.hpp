#ifndef PROOF_GENERATOR_LIBS_ASSIGNER_BYTECODE_HPP_
#define PROOF_GENERATOR_LIBS_ASSIGNER_BYTECODE_HPP_

#include <optional>
#include <chrono>
#include <boost/log/trivial.hpp>
#include <boost/filesystem.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/blueprint/zkevm_bbf/bytecode.hpp>
#include <nil/proof-generator/assigner/trace_parser.hpp>
#include <nil/proof-generator/preset/limits.hpp>

namespace nil {
    namespace proof_generator {

        /// @brief Fill assignment table
        template<typename BlueprintFieldType>
        std::optional<std::string> fill_bytecode_assignment_table(nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>& assignment_table,
                                                             const boost::filesystem::path& trace_base_path) {
            BOOST_LOG_TRIVIAL(debug) << "fill bytecode table from " << trace_base_path << "\n";

            using ComponentType = nil::blueprint::bbf::bytecode<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;

            typename nil::blueprint::bbf::context<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT> context_object(assignment_table, limits::max_rows);

            typename ComponentType::input_type input;
            input.rlc_challenge = limits::RLC_CHALLENGE;

            const auto bytecode_trace_path = get_bytecode_trace_path(trace_base_path);
            const auto contract_bytecodes = deserialize_bytecodes_from_file(bytecode_trace_path);
            if (!contract_bytecodes) {
                return "can't read bytecode trace from file: " + bytecode_trace_path.string();
            }

            for (const auto& bytecode_it : contract_bytecodes.value()) {
                const auto raw_bytecode = string_to_bytes(bytecode_it.second);
                input.bytecodes.new_buffer(raw_bytecode);
                input.keccak_buffers.new_buffer(raw_bytecode);
            }

            auto start = std::chrono::high_resolution_clock::now();
            ComponentType instance(context_object, input, limits::max_bytecode_size, limits::max_keccak_blocks);
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
            std::cout << "FILL ASSIGNMENT TABLE: " << duration.count() << "\n";
            return {};
        }
    } // proof_generator
} // nil

#endif  // PROOF_GENERATOR_LIBS_ASSIGNER_BYTECODE_HPP_
