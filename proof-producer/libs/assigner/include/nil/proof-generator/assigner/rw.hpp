#ifndef PROOF_GENERATOR_LIBS_ASSIGNER_RW_HPP_
#define PROOF_GENERATOR_LIBS_ASSIGNER_RW_HPP_

#include <optional>
#include <chrono>
#include <boost/log/trivial.hpp>
#include <boost/filesystem.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/blueprint/zkevm_bbf/rw.hpp>
#include <nil/proof-generator/assigner/trace_parser.hpp>

namespace nil {
    namespace proof_generator {

        /// @brief Fill assignment table
        template<typename BlueprintFieldType>
        std::optional<std::string> fill_rw_assignment_table(nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>& assignment_table,
                                                             const boost::filesystem::path& trace_file_path) {
            BOOST_LOG_TRIVIAL(debug) << "fill rw table from " << trace_file_path << "\n";

            using ComponentType = nil::blueprint::bbf::rw<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;

            std::size_t max_rw_size = 1000;
            std::size_t max_mpt_size = 30;
            std::size_t max_rows = 500000;

            typename nil::blueprint::bbf::context<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT> context_object(assignment_table, max_rows);

            std::vector<nil::blueprint::bbf::rw_operation> input;
            const auto rw_operations = deserialize_rw_traces_from_file(trace_file_path);
            if (!rw_operations) {
                return "can't read rw from file";
            }
            for (const auto& stack_op : rw_operations->stack_ops) {
                input.push_back(stack_op);
            }
            for (const auto& memory_op : rw_operations->memory_ops) {
                input.push_back(memory_op);
            }
            for (const auto& storage_op : rw_operations->storage_ops) {
                input.push_back(storage_op);
            }

            auto start = std::chrono::high_resolution_clock::now();
            ComponentType instance(context_object, input, max_rw_size, max_mpt_size);
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
            std::cout << "FILL ASSIGNMENT TABLE: " << duration.count() << "\n";
            return {};
        }
    } // proof_generator
} // nil

#endif  // PROOF_GENERATOR_LIBS_ASSIGNER_RW_HPP_
