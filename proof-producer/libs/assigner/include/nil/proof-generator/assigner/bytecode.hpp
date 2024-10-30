#ifndef PROOF_GENERATOR_LIBS_ASSIGNER_BYTECODE_HPP_
#define PROOF_GENERATOR_LIBS_ASSIGNER_BYTECODE_HPP_

#include <boost/log/trivial.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/blueprint/zkevm_bbf/bytecode.hpp>
#include <nil/proof-generator/assigner/trace_parser.hpp>

namespace nil {
    namespace proof_generator {

        /// @brief Fill assignment table
        template<typename BlueprintFieldType>
        std::optional<std::string> fill_bytecode_assignment_table(nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>& assignment_table,
                                                             const boost::filesystem::path& trace_file_path) {
            BOOST_LOG_TRIVIAL(debug) << "fill add table from " << trace_file_path << "\n";

            using ComponentType = nil::blueprint::bbf::bytecode<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;

            std::size_t max_bytecode_size = 1000;
            std::size_t max_keccak_blocks = 30;
            std::size_t max_rows = 500000;

            typename nil::blueprint::bbf::context<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT> context_object(assignment_table, max_rows);

            //TODO read from trace
            std::vector<std::uint8_t> raw_bytecode = {0x60, 0x04, 0x60, 0x08, 0x02}; // 4*8
            typename ComponentType::input_type input;
            input.bytecodes.new_buffer(raw_bytecode);
            input.keccak_buffers.new_buffer(raw_bytecode);

            ComponentType instance(context_object, input, max_bytecode_size, max_keccak_blocks);
            return {};
        }
    } // proof_generator
} // nil

#endif  // PROOF_GENERATOR_LIBS_ASSIGNER_BYTECODE_HPP_
