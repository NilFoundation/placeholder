/**
 * @file checks.hpp
 *
 * @brief This file defines functions and types for check assignment tables.
 */

#ifndef ZKEMV_FRAMEWORK_LIBS_CHECKS_INCLUDE_CHECKS_HPP_
#define ZKEMV_FRAMEWORK_LIBS_CHECKS_INCLUDE_CHECKS_HPP_

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/utils/connectedness_check.hpp>
#include <nil/blueprint/utils/satisfiability_check.hpp>

template<typename BlueprintFieldType>
using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;

template<typename BlueprintFieldType>
bool check_connectedness(
    const nil::blueprint::circuit<ArithmetizationType<BlueprintFieldType>>& bp,
    const nil::blueprint::assignment<ArithmetizationType<BlueprintFieldType>>& assignment,
    const std::vector<
        nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>&
        instance_input,
    const std::vector<
        nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>&
        component_result,
    size_t start_row, size_t component_rows_amount,
    nil::blueprint::connectedness_check_type connectedness_check) {
    if (assignment.rows_amount() - start_row != component_rows_amount) {
        std::cerr << "ERROR: wrong rows ampunt: expected " << component_rows_amount << ", real "
                  << assignment.rows_amount() - start_row << "\n";
        return false;
    }
    const std::size_t rows_after_component_batching =
        assignment.finalize_component_batches(bp, start_row + component_rows_amount);
    const std::size_t rows_after_const_batching =
        assignment.finalize_constant_batches(bp, 0, std::max<std::size_t>(start_row, 1));
    const std::size_t rows_after_batching =
        std::max(rows_after_component_batching, rows_after_const_batching);
    for (auto variable : component_result) {
        if (assignment.get_batch_variable_map().count(variable)) {
            variable.get() = assignment.get_batch_variable_map().at(variable);
        }
    }
    bool is_connected = nil::blueprint::check_connectedness(
        assignment, bp, instance_input, component_result, start_row,
        rows_after_batching - start_row, connectedness_check);
    if (!is_connected) {
        std::cerr << "ERROR: connectness violation\n";
        return false;
    }
    if (connectedness_check.t == nil::blueprint::connectedness_check_type::type::NONE) {
        std::cerr << "WARNING: Connectedness check is disabled.\n";
    }
    return true;
}

template<typename BlueprintFieldType>
bool is_satisfied(
    const nil::blueprint::circuit<ArithmetizationType<BlueprintFieldType>>& bp,
    const nil::blueprint::assignment<ArithmetizationType<BlueprintFieldType>>& assignment) {
    if (!nil::blueprint::is_satisfied(bp, assignment)) {
        std::cerr << "ERROR: is not satisfied\n";
        return false;
    }
    return true;
}

#endif  // ZKEMV_FRAMEWORK_LIBS_CHECKS_INCLUDE_CHECKS_HPP_
