#include <gtest/gtest.h>

#include <memory>
#include <string>

#include <nil/blueprint/utils/satisfiability_check.hpp>
#include <nil/proof-generator/commands/preset_command.hpp>
#include <nil/proof-generator/commands/fill_assignment_command.hpp>


namespace {

    struct Input {
        std::string trace_base_name; // base name of trace set collected from the cluster
        std::string circuit_name;    // circuit name
        bool skip_check{false};      // skip satisfiability check while running the test
    };

} // namespace


class ProverTests: public ::testing::TestWithParam<Input> {

    public:
        using CurveType = nil::crypto3::algebra::curves::pallas;
        using HashType = nil::crypto3::hashes::keccak_1600<256>;

        using ConstraintSystem = nil::proof_generator::TypeSystem<CurveType, HashType>::ConstraintSystem;
        using BlueprintFieldType = nil::proof_generator::TypeSystem<CurveType, HashType>::BlueprintField;
        using AssignmentTable = nil::proof_generator::TypeSystem<CurveType, HashType>::AssignmentTable;


        class AssignmentTableChecker: public nil::proof_generator::command_chain {

        public:
            AssignmentTableChecker(const std::string& circuit_name, const std::string& trace_base_path) {
                using PresetStep                       = typename nil::proof_generator::PresetStep<CurveType, HashType>::Executor;
                using Assigner                         = typename nil::proof_generator::FillAssignmentStep<CurveType, HashType>::Executor;

                nil::proof_generator::CircuitsLimits circuit_limits;
                auto& circuit_maker = add_step<PresetStep>(circuit_name, circuit_limits);
                auto& assigner = add_step<Assigner>(circuit_maker, circuit_maker, circuit_name, trace_base_path,
                    nil::proof_generator::AssignerOptions(false, circuit_limits));

                resources::subscribe_value<ConstraintSystem>(circuit_maker, circuit_);    // capture circuit to do the check
                resources::subscribe_value<AssignmentTable>(assigner, assignment_table_); // capture assignment table to do the check
            }

            std::shared_ptr<ConstraintSystem> circuit_;
            std::shared_ptr<AssignmentTable> assignment_table_;
        };
};


TEST_P(ProverTests, FillAssignmentAndCheck) {
    const auto input = GetParam();
    const std::string trace_base_path = std::string(TEST_DATA_DIR) + input.trace_base_name;

    AssignmentTableChecker checker(input.circuit_name, trace_base_path);
    auto const res = checker.execute();
    ASSERT_TRUE(res.succeeded());

    if (input.skip_check) {
        GTEST_SKIP() << "Skipping satisfiability_check for " << input.circuit_name <<   " circuit for trace " << input.trace_base_name;
    }

    ASSERT_NE(checker.circuit_, nullptr);
    ASSERT_NE(checker.assignment_table_, nullptr);

    ASSERT_TRUE(nil::blueprint::is_satisfied<BlueprintFieldType>(
        *checker.circuit_,
        *checker.assignment_table_
    ));
}


using namespace nil::proof_generator::circuits;

// !! note that due to https://github.com/NilFoundation/placeholder/issues/196
// contracts for these traces were compiled with --no-cbor-metadata flag

// Single call of Counter contract increment function
const std::string SimpleIncrement = "simple/increment_simple";
INSTANTIATE_TEST_SUITE_P(SimpleRw, ProverTests, ::testing::Values(Input{SimpleIncrement,  RW}));
INSTANTIATE_TEST_SUITE_P(SimpleBytecode, ProverTests, ::testing::Values(Input{SimpleIncrement,  BYTECODE}));
INSTANTIATE_TEST_SUITE_P(SimpleCopy, ProverTests, ::testing::Values(Input{SimpleIncrement,  COPY}));
INSTANTIATE_TEST_SUITE_P(SimpleZkevm, ProverTests, ::testing::Values(Input{SimpleIncrement,  ZKEVM}));
INSTANTIATE_TEST_SUITE_P(SimpleExp, ProverTests, ::testing::Values(Input{SimpleIncrement, EXP}));

// // Multiple calls of Counter contract increment function (several transactions)
const std::string MultiTxIncrement = "multi_tx/increment_multi_tx";
INSTANTIATE_TEST_SUITE_P(MultiTxRw, ProverTests, ::testing::Values(Input{MultiTxIncrement,  RW}));
INSTANTIATE_TEST_SUITE_P(MultiTxBytecode, ProverTests, :: testing::Values(Input{MultiTxIncrement,  BYTECODE}));
INSTANTIATE_TEST_SUITE_P(MultiTxCopy, ProverTests, ::testing::Values(Input{MultiTxIncrement,  COPY}));
INSTANTIATE_TEST_SUITE_P(MultiTxZkevm, ProverTests, ::testing::Values(Input{MultiTxIncrement,  ZKEVM}));
INSTANTIATE_TEST_SUITE_P(MultiTxExp, ProverTests, ::testing::Values(Input{MultiTxIncrement, EXP}));

// // Single call of exp operation
const std::string SimpleExp = "exp/exp";
INSTANTIATE_TEST_SUITE_P(SimpleExpRw, ProverTests, ::testing::Values(Input{SimpleExp, RW}));
INSTANTIATE_TEST_SUITE_P(SimpleExpBytecode, ProverTests, :: testing::Values(Input{SimpleExp, BYTECODE}));
INSTANTIATE_TEST_SUITE_P(SimpleExpCopy, ProverTests, ::testing::Values(Input{SimpleExp, COPY}));
INSTANTIATE_TEST_SUITE_P(SimpleExpZkevm, ProverTests, ::testing::Values(Input{SimpleExp, ZKEVM}));
INSTANTIATE_TEST_SUITE_P(SimpleExpExp, ProverTests, ::testing::Values(Input{SimpleExp, EXP}));

// RW trace is picked from another trace set and has different trace_idx
TEST(ProverTest, TraceIndexMismatch) {
    const std::string trace_base_path = std::string(TEST_DATA_DIR) + "/broken_index/increment_simple.pb";

    ProverTests::AssignmentTableChecker checker(ZKEVM, trace_base_path);
    auto const res = checker.execute();
    ASSERT_FALSE(res.succeeded());
    ASSERT_NE(checker.circuit_, nullptr);        // circuit is filled
    ASSERT_EQ(checker.assignment_table_, nullptr); // assignment table is not filled
}

// Trace files contain different proto hash
TEST(ProverTest, DifferentProtoHash) {
    const std::string trace_base_path = std::string(TEST_DATA_DIR) + "/different_proto/increment_simple.pb";

    ProverTests::AssignmentTableChecker checker(ZKEVM, trace_base_path);
    auto const res = checker.execute();
    ASSERT_FALSE(res.succeeded());
    ASSERT_NE(checker.circuit_, nullptr);        // circuit is filled
    ASSERT_EQ(checker.assignment_table_, nullptr); // assignment table is not filled
}
