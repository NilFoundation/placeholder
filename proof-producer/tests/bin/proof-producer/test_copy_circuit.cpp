#include <gtest/gtest.h>

#include <nil/marshalling/options.hpp>
#include <nil/marshalling/field_type.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/utils/satisfiability_check.hpp>

#include <nil/proof-generator/prover.hpp>
#include "nil/blueprint/blueprint/plonk/circuit.hpp"
#include "nil/proof-generator/preset/preset.hpp"

namespace npg = nil::proof_generator;

using Curve = nil::crypto3::algebra::curves::pallas;
using Hash = nil::crypto3::hashes::keccak_1600<256>;


class CopyCircuitTest: public ::testing::Test {

protected:

    static constexpr auto copy_traces_file_path = "./resources/traces/copy.trace.pb";

    static constexpr std::size_t lambda = 9;
    static constexpr std::size_t grind = 0;
    static constexpr std::size_t expand_factor = 2;
    static constexpr std::size_t max_quotient_chunks = 0;
};

TEST_F(CopyCircuitTest, CopyCircuit)
{
    const auto circuit_name = nil::proof_generator::circuits::COPY;

    using Prover = npg::Prover<Curve, Hash>;
    Prover prover(
        lambda,
        expand_factor,
        max_quotient_chunks,
        grind,
        circuit_name
    );

    using ConstraintSystem = Prover::ConstraintSystem;
    using BlueprintFieldType = Prover::BlueprintField;

    ASSERT_TRUE(prover.setup_prover());
    ASSERT_TRUE(prover.fill_assignment_table(copy_traces_file_path));

    const auto& circuit = prover.get_constraint_system();
    const auto& assignment_table = prover.get_assignment_table();
    const auto& table_description = prover.get_table_description();

    auto bp_circuit = nil::blueprint::circuit<ConstraintSystem>(circuit);
    auto bp_assignment_table = nil::blueprint::assignment<ConstraintSystem>(assignment_table, table_description);

    ASSERT_TRUE(nil::blueprint::is_satisfied<BlueprintFieldType>(bp_circuit, bp_assignment_table));
}