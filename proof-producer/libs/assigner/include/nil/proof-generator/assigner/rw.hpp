#pragma once

#include <boost/log/trivial.hpp>

#include <boost/filesystem.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/blueprint/zkevm_bbf/rw.hpp>
#include <nil/blueprint/zkevm/memory.hpp>
#include <optional>
#include "nil/blueprint/zkevm/zkevm_word.hpp"

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

            // TODO read from trace
            // auto traces = deserialize_traces_from_file(trace_file_path);
            // if (!traces) {
            //     return std::nullopt;
            // }
            // for (const StackOp& op : traces->stack_ops) {
            uint16_t sample_int_address = 1;
            size_t sample_id = 0;
            nil::blueprint::zkevm_word_type sample_value(42);
            nil::blueprint::zkevm_word_type sample_word_address(0xdeadbeef);
            std::vector<nil::blueprint::bbf::rw_operation> input;
            input.push_back(nil::blueprint::bbf::stack_rw_operation(sample_id, sample_int_address, sample_id++, true, sample_value));
            input.push_back(nil::blueprint::bbf::memory_rw_operation(sample_id, sample_word_address, sample_id++, false, sample_value));
            input.push_back(nil::blueprint::bbf::storage_rw_operation(sample_id, sample_word_address, sample_id++, true, sample_value, sample_value));

            ComponentType instance(context_object, input, max_rw_size, max_mpt_size);
            return {};
        }
    } // proof_generator
} // nil
