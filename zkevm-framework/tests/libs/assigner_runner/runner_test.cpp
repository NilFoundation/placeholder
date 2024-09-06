#include "zkevm_framework/assigner_runner/runner.hpp"

#include <gtest/gtest.h>

#include <boost/log/trivial.hpp>
#include <fstream>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <unordered_map>

#include "zkevm_framework/preset/preset.hpp"

TEST(runner_test, check_block) {
    using BlueprintFieldType = typename nil::crypto3::algebra::curves::pallas::base_field_type;
    using ArithmetizationType =
        nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;

    zkevm_circuits<ArithmetizationType> circuits;

    std::unordered_map<nil::evm_assigner::zkevm_circuit,
                       nil::blueprint::assignment<ArithmetizationType>>
        assignments;

    auto err = initialize_circuits<BlueprintFieldType>(circuits, assignments);
    ASSERT_FALSE(err.has_value());
    single_thread_runner<BlueprintFieldType> runner(assignments, 0 /*shad id*/,
                                                    circuits.get_circuit_names());
    err = runner.extract_block_with_messages("", BLOCK_CONFIG);
    ASSERT_FALSE(err.has_value());
    err = runner.extract_accounts_with_storage(STATE_CONFIG);
    ASSERT_FALSE(err.has_value());
    err = runner.run("", std::nullopt);
    ASSERT_FALSE(err.has_value());

    // Checks below are disabled due to frequent changes in filling assignment tables
    /*
    auto assignments = runner.get_assignments();
    ASSERT_EQ(assignments.size(), 2);
    ASSERT_EQ(assignments[1].witness(0, 0), 8);
    ASSERT_EQ(assignments[1].witness(0, 1), 4);
    */
}
