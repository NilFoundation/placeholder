#ifndef PROOF_GENERATOR_LIBS_ASSIGNER_RW_HPP_
#define PROOF_GENERATOR_LIBS_ASSIGNER_RW_HPP_

#include <optional>
#include <boost/log/trivial.hpp>
#include <boost/filesystem.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/circuits/rw.hpp>
#include <nil/proof-generator/assigner/options.hpp>
#include <nil/proof-generator/assigner/trace_parser.hpp>

namespace nil {
    namespace proof_producer {

        /// @brief Fill assignment table
        template<typename BlueprintFieldType>
        std::optional<std::string> fill_rw_assignment_table(nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>& assignment_table,
                                                            const boost::filesystem::path& trace_base_path,
                                                            const AssignerOptions& options) {
            BOOST_LOG_TRIVIAL(debug) << "fill rw table from " << trace_base_path << "\n";

            using ComponentType = nil::blueprint::bbf::zkevm_big_field::rw<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;

            typename nil::blueprint::bbf::context<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT> context_object(assignment_table, options.circuits_limits.max_total_rows);

            const auto rw_trace_path = get_rw_trace_path(trace_base_path);
            auto input = deserialize_rw_traces_from_file(rw_trace_path, options);
            if (!input) {
                return "can't read rw from file: " + rw_trace_path.string();
            }

            // TODO: there is no defined relation between input size and row size:
            // replace this check with handling of an error returned by component instantiation
            if (input->value.size() > options.circuits_limits.max_rw_rows) {
                return std::format("rw operations size {} exceeds circuit limit {}", input->value.size(), options.circuits_limits.max_rw_rows);
            }

            // TODO: state operations, timeline
            ComponentType instance(
                context_object, {input->value, {}, {}},
                options.circuits_limits.max_rw_rows,
                options.circuits_limits.max_state_rows
            );

            return {};
        }
    } // proof_producer
} // nil

#endif  // PROOF_GENERATOR_LIBS_ASSIGNER_RW_HPP_
