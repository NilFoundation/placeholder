#include <gtest/gtest.h>

#include <string>

#include <nil/blueprint/utils/satisfiability_check.hpp>
#include <nil/proof-generator/prover.hpp>
#include <nil/proof-generator/preset/preset.hpp>


namespace {

    struct Input {
        std::string trace_base_name; // base name of trace set collected from the cluster
        std::string circuit_name;    // circuit name
        bool skip_check{false};      // skip satisfiability check while running the test
    };

} // namespace


class ProverTests: public ::testing::TestWithParam<Input> {

    protected:
        using CurveType = nil::crypto3::algebra::curves::pallas;
        using HashType = nil::crypto3::hashes::keccak_1600<256>;
        using ConstraintSystem = nil::proof_generator::Prover<CurveType, HashType>::ConstraintSystem;
        using BlueprintFieldType = nil::proof_generator::Prover<CurveType, HashType>::BlueprintField;

        static constexpr std::size_t lambda = 9;
        static constexpr std::size_t grind = 0;
        static constexpr std::size_t expand_factor = 2;
        static constexpr std::size_t max_quotient_chunks = 0;
};


TEST_P(ProverTests, FillAssignmentAndCheck) {
    const auto input = GetParam();
    const std::string trace_base_path = std::string(TEST_DATA_DIR) + input.trace_base_name;
    nil::proof_generator::Prover<CurveType, HashType> prover(
                        lambda,
                        expand_factor,
                        max_quotient_chunks,
                        grind,
                        input.circuit_name
    );

    ASSERT_TRUE(prover.setup_prover());

    ASSERT_TRUE(prover.fill_assignment_table(trace_base_path));

    const auto& circuit = prover.get_constraint_system();
    const auto& assignment_table = prover.get_assignment_table();

    if (input.skip_check) {
        GTEST_SKIP() << "Skipping satisfiability_check for " << input.circuit_name <<   " circuit for trace " << input.trace_base_name;
    }

    ASSERT_TRUE(nil::blueprint::is_satisfied<BlueprintFieldType>(circuit, assignment_table));
}


using namespace nil::proof_generator::circuits;

// Single call of Counter contract increment function
const std::string SimpleIncrement = "increment_simple.pb";    
INSTANTIATE_TEST_SUITE_P(SimpleRw, ProverTests, ::testing::Values(Input{SimpleIncrement,  RW}));
INSTANTIATE_TEST_SUITE_P(SimpleBytecode, ProverTests, ::testing::Values(Input{SimpleIncrement,  BYTECODE}));
INSTANTIATE_TEST_SUITE_P(SimpleCopy, ProverTests, ::testing::Values(Input{SimpleIncrement,  COPY}));
INSTANTIATE_TEST_SUITE_P(SimpleZkevm, ProverTests, ::testing::Values(Input{SimpleIncrement,  ZKEVM}));

// Multiple calls of Counter contract increment function (several transactions)
// !! note that due to https://github.com/NilFoundation/placeholder/issues/196
// contracts for these traces were compiled with --no-cbor-metadata flag
const std::string MultiTxIncrement = "increment_multi_tx.pb"; 
INSTANTIATE_TEST_SUITE_P(MultiTxRw, ProverTests, ::testing::Values(Input{MultiTxIncrement,  RW})); 
INSTANTIATE_TEST_SUITE_P(MultiTxBytecode, ProverTests, :: testing::Values(Input{MultiTxIncrement,  BYTECODE}));
INSTANTIATE_TEST_SUITE_P(MultiTxCopy, ProverTests, ::testing::Values(Input{MultiTxIncrement,  COPY}));
INSTANTIATE_TEST_SUITE_P(MultiTxZkevm, ProverTests, ::testing::Values(Input{MultiTxIncrement,  ZKEVM}));
