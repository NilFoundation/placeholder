#include <gtest/gtest.h>

#include <filesystem>
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


class ProverTestBase: public ::testing::TestWithParam<Input> {
    public:
        using CurveType = nil::crypto3::algebra::curves::pallas;
        using HashType = nil::crypto3::hashes::keccak_1600<256>;
        using ConstraintSystem = nil::proof_generator::Prover<CurveType, HashType>::ConstraintSystem;
        using BlueprintFieldType = nil::proof_generator::Prover<CurveType, HashType>::BlueprintField;

        static constexpr std::size_t lambda = 9;
        static constexpr std::size_t grind = 0;
        static constexpr std::size_t expand_factor = 2;
        static constexpr std::size_t max_quotient_chunks = 0;
};

class ProverTestsAssignment : public ProverTestBase {
};

TEST_P(ProverTestsAssignment, FillAssignmentAndCheck) {
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

// !! note that due to https://github.com/NilFoundation/placeholder/issues/196
// contracts for these traces were compiled with --no-cbor-metadata flag

// Single call of Counter contract increment function
const std::string SimpleIncrement = "increment_simple";
INSTANTIATE_TEST_SUITE_P(SimpleRw, ProverTestsAssignment, ::testing::Values(Input{SimpleIncrement,  RW}));
INSTANTIATE_TEST_SUITE_P(SimpleBytecode, ProverTestsAssignment, ::testing::Values(Input{SimpleIncrement,  BYTECODE}));
INSTANTIATE_TEST_SUITE_P(SimpleCopy, ProverTestsAssignment, ::testing::Values(Input{SimpleIncrement,  COPY}));
INSTANTIATE_TEST_SUITE_P(SimpleZkevm, ProverTestsAssignment, ::testing::Values(Input{SimpleIncrement,  ZKEVM}));
INSTANTIATE_TEST_SUITE_P(SimpleExp, ProverTestsAssignment, ::testing::Values(Input{SimpleIncrement, EXP}));

// // Multiple calls of Counter contract increment function (several transactions)
const std::string MultiTxIncrement = "increment_multi_tx";
INSTANTIATE_TEST_SUITE_P(MultiTxRw, ProverTestsAssignment, ::testing::Values(Input{MultiTxIncrement,  RW}));
INSTANTIATE_TEST_SUITE_P(MultiTxBytecode, ProverTestsAssignment, :: testing::Values(Input{MultiTxIncrement,  BYTECODE}));
INSTANTIATE_TEST_SUITE_P(MultiTxCopy, ProverTestsAssignment, ::testing::Values(Input{MultiTxIncrement,  COPY}));
INSTANTIATE_TEST_SUITE_P(MultiTxZkevm, ProverTestsAssignment, ::testing::Values(Input{MultiTxIncrement,  ZKEVM}));
INSTANTIATE_TEST_SUITE_P(MultiTxExp, ProverTestsAssignment, ::testing::Values(Input{MultiTxIncrement, EXP}));

// // Single call of exp operation
const std::string SimpleExp = "exp/exp";
INSTANTIATE_TEST_SUITE_P(SimpleExpRw, ProverTestsAssignment, ::testing::Values(Input{SimpleExp, RW}));
INSTANTIATE_TEST_SUITE_P(SimpleExpBytecode, ProverTestsAssignment, :: testing::Values(Input{SimpleExp, BYTECODE}));
INSTANTIATE_TEST_SUITE_P(SimpleExpCopy, ProverTestsAssignment, ::testing::Values(Input{SimpleExp, COPY}));
INSTANTIATE_TEST_SUITE_P(SimpleExpZkevm, ProverTestsAssignment, ::testing::Values(Input{SimpleExp, ZKEVM}));
INSTANTIATE_TEST_SUITE_P(SimpleExpExp, ProverTestsAssignment, ::testing::Values(Input{SimpleExp, EXP}));

// RW trace is picked from another trace set and has different trace_idx
TEST(ProverTest, TraceIndexMismatch) {
    const std::string trace_base_path = std::string(TEST_DATA_DIR) + "/broken_index/increment_simple.pb";
    nil::proof_generator::Prover<ProverTestBase::CurveType, ProverTestBase::HashType> prover(
                        ProverTestBase::lambda,
                        ProverTestBase::expand_factor,
                        ProverTestBase::max_quotient_chunks,
                        ProverTestBase::grind,
                        ZKEVM
    );

    ASSERT_TRUE(prover.setup_prover());
    ASSERT_FALSE(prover.fill_assignment_table(trace_base_path));
}

// Trace files contain different proto hash
TEST(ProverTest, DifferentProtoHash) {
    const std::string trace_base_path = std::string(TEST_DATA_DIR) + "/different_proto/increment_simple.pb";
    nil::proof_generator::Prover<ProverTestBase::CurveType, ProverTestBase::HashType> prover(
                        ProverTestBase::lambda,
                        ProverTestBase::expand_factor,
                        ProverTestBase::max_quotient_chunks,
                        ProverTestBase::grind,
                        ZKEVM
    );

    ASSERT_TRUE(prover.setup_prover());
    ASSERT_FALSE(prover.fill_assignment_table(trace_base_path));
}

namespace fs = std::filesystem;

class ProverTestsVerification : public ProverTestBase {
protected:
    fs::path proof_file_path;
    fs::path json_file_path;

    void SetUp() override {
        proof_file_path = fs::temp_directory_path() / "proof.dat";
        json_file_path = fs::temp_directory_path() / "proof.json";
    }

    void TearDown() override {
        if (fs::exists(proof_file_path))
            fs::remove(proof_file_path);
        if (fs::exists(json_file_path))
            fs::remove(json_file_path);
    }
};

TEST_P(ProverTestsVerification, GenerateProof) {
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
    ASSERT_TRUE(prover.preprocess_public_data());
    ASSERT_TRUE(prover.preprocess_private_data());
    ASSERT_TRUE(prover.generate_to_file(
        proof_file_path,
        json_file_path,
        false /*don't skip verification*/
    ));
}

INSTANTIATE_TEST_SUITE_P(SimpleRw, ProverTestsVerification, ::testing::Values(Input{SimpleIncrement, RW}));
INSTANTIATE_TEST_SUITE_P(SimpleBytecode, ProverTestsVerification, ::testing::Values(Input{SimpleIncrement, BYTECODE}));
INSTANTIATE_TEST_SUITE_P(SimpleCopy, ProverTestsVerification, ::testing::Values(Input{SimpleIncrement, COPY}));
INSTANTIATE_TEST_SUITE_P(SimpleExp, ProverTestsVerification, ::testing::Values(Input{SimpleIncrement, EXP}));
