#ifndef PROOF_GENERATOR_LIBS_ASSIGNER_EXP_HPP_
#define PROOF_GENERATOR_LIBS_ASSIGNER_EXP_HPP_

#include <optional>
#include <boost/log/trivial.hpp>
#include <boost/filesystem.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/circuits/exp.hpp>
#include <nil/proof-generator/assigner/options.hpp>
#include <nil/proof-generator/assigner/trace_parser.hpp>

namespace nil {
    namespace proof_producer {

        /// @brief Fill assignment table
        template<typename BlueprintFieldType>
        std::optional<std::string> fill_exp_assignment_table(nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>& assignment_table,
                                                             const boost::filesystem::path& trace_base_path,
                                                             const AssignerOptions& options) {
            BOOST_LOG_TRIVIAL(debug) << "fill exp table from " << trace_base_path << "\n";

            using ComponentType = nil::blueprint::bbf::zkevm_big_field::exponentiation<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;

            typename nil::blueprint::bbf::context<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT> context_object(assignment_table, options.circuits_limits.max_total_rows);

            typename ComponentType::input_type input;


            const auto exp_trace_path = get_exp_trace_path(trace_base_path);
            const auto exp_operations = deserialize_exp_traces_from_file(exp_trace_path, options);
            if (!exp_operations) {
                return "can't read exp operations from file: " + exp_trace_path.string();
            }
            input = std::move(exp_operations->value);

            if (input.size() > options.circuits_limits.max_exp_ops) {
                return std::format("exp operations size {} exceeds circuit limit {}", input.size(), options.circuits_limits.max_exp_ops);
            }

            ComponentType instance(
                context_object,
                input,
                options.circuits_limits.max_exp_rows,
                options.circuits_limits.max_exp_ops
            );

            return {};
        }
    } // proof_producer
} // nil

#endif  // PROOF_GENERATOR_LIBS_ASSIGNER_EXP_HPP_
