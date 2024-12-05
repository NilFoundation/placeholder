#ifndef PROOF_GENERATOR_LIBS_ASSIGNER_RW_HPP_
#define PROOF_GENERATOR_LIBS_ASSIGNER_RW_HPP_

#include <optional>
#include <chrono>
#include <boost/log/trivial.hpp>
#include <boost/filesystem.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/blueprint/zkevm_bbf/rw.hpp>
#include <nil/proof-generator/assigner/trace_parser.hpp>
#include <nil/proof-generator/preset/limits.hpp>


namespace nil {
    namespace proof_generator {

        /// @brief Fill assignment table
        template<typename BlueprintFieldType>
        std::optional<std::string> fill_rw_assignment_table(nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>& assignment_table,
                                                            const boost::filesystem::path& trace_base_path) {
            BOOST_LOG_TRIVIAL(debug) << "fill rw table from " << trace_base_path << "\n";

            using ComponentType = nil::blueprint::bbf::rw<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;

            typename nil::blueprint::bbf::context<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT> context_object(assignment_table, limits::max_rows);

            nil::blueprint::bbf::rw_operations_vector input;
            const auto rw_trace_path = get_rw_trace_path(trace_base_path);
            const auto rw_operations = deserialize_rw_traces_from_file(rw_trace_path);
            if (!rw_operations) {
                return "can't read rw from file: " + rw_trace_path.string();
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
            BOOST_LOG_TRIVIAL(debug) << "number RW operations " << input.size() << ":\n"
             << "stack   " << rw_operations->stack_ops.size() << "\n"
             << "memory  " << rw_operations->memory_ops.size() << "\n"
             << "storage " << rw_operations->storage_ops.size() << "\n";

            auto start = std::chrono::high_resolution_clock::now();
            ComponentType instance(context_object, std::move(input), limits::max_rw_size, limits::max_mpt_size);
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
            std::cout << "FILL ASSIGNMENT TABLE: " << duration.count() << "\n";
            return {};
        }
    } // proof_generator
} // nil

#endif  // PROOF_GENERATOR_LIBS_ASSIGNER_RW_HPP_
