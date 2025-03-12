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

        using ConstraintSystem = nil::proof_producer::TypeSystem<CurveType, HashType>::ConstraintSystem;
        using BlueprintFieldType = nil::proof_producer::TypeSystem<CurveType, HashType>::BlueprintField;
        using AssignmentTable = nil::proof_producer::TypeSystem<CurveType, HashType>::AssignmentTable;

        class AssignmentTableChecker: public nil::proof_producer::command_chain {

        public:
            AssignmentTableChecker(const std::string& circuit_name, const std::string& trace_base_path) {
                using PresetStep                       = typename nil::proof_producer::PresetStep<CurveType, HashType>::Executor;
                using Assigner                         = typename nil::proof_producer::FillAssignmentStep<CurveType, HashType>::Executor;

                nil::proof_producer::CircuitsLimits circuit_limits;
                auto& circuit_maker = add_step<PresetStep>(circuit_name, circuit_limits);
                auto& assigner = add_step<Assigner>(circuit_maker, circuit_maker, circuit_name, trace_base_path,
                    nil::proof_producer::AssignerOptions(false, circuit_limits));

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

    auto const check_res = nil::blueprint::satisfiability_checker<BlueprintFieldType>::is_satisfied(
        *checker.circuit_,
        *checker.assignment_table_,
        nil::blueprint::satisfiability_check_options{.verbose = true}
    );

    ASSERT_TRUE(check_res);
}

using namespace nil::proof_producer::circuits;

// Single call of SimpleStorage contract increment + keccakHash functions
const std::string SimpleIncAndKeccak = "simple/simple_inc_and_keccak";
INSTANTIATE_TEST_SUITE_P(SimpleRw, ProverTests, ::testing::Values(Input{SimpleIncAndKeccak,  RW}));
INSTANTIATE_TEST_SUITE_P(SimpleBytecode, ProverTests, ::testing::Values(Input{SimpleIncAndKeccak,  BYTECODE}));
INSTANTIATE_TEST_SUITE_P(SimpleCopy, ProverTests, ::testing::Values(Input{SimpleIncAndKeccak,  COPY}));
INSTANTIATE_TEST_SUITE_P(SimpleZkevm, ProverTests, ::testing::Values(Input{SimpleIncAndKeccak,  ZKEVM}));
INSTANTIATE_TEST_SUITE_P(SimpleExp, ProverTests, ::testing::Values(Input{SimpleIncAndKeccak, EXP}));
INSTANTIATE_TEST_SUITE_P(SimpleKeccak, ProverTests, ::testing::Values(Input{SimpleIncAndKeccak, KECCAK}));

// Multiple calls of SimpleStorage contract increment function (several transactions)
const std::string MultiTxIncrement = "multi_tx/increment_multi_tx";
INSTANTIATE_TEST_SUITE_P(MultiTxRw, ProverTests, ::testing::Values(Input{MultiTxIncrement,  RW}));
INSTANTIATE_TEST_SUITE_P(MultiTxBytecode, ProverTests, :: testing::Values(Input{MultiTxIncrement,  BYTECODE}));
INSTANTIATE_TEST_SUITE_P(MultiTxCopy, ProverTests, ::testing::Values(Input{MultiTxIncrement,  COPY}));
INSTANTIATE_TEST_SUITE_P(MultiTxZkevm, ProverTests, ::testing::Values(Input{MultiTxIncrement,  ZKEVM}));
INSTANTIATE_TEST_SUITE_P(MultiTxExp, ProverTests, ::testing::Values(Input{MultiTxIncrement, EXP}));
INSTANTIATE_TEST_SUITE_P(MultiTxKeccak, ProverTests, ::testing::Values(Input{MultiTxIncrement, KECCAK}));

// Single call of exp operation
const std::string SimpleExp = "exp/exp";
INSTANTIATE_TEST_SUITE_P(SimpleExpRw, ProverTests, ::testing::Values(Input{SimpleExp, RW}));
INSTANTIATE_TEST_SUITE_P(SimpleExpBytecode, ProverTests, :: testing::Values(Input{SimpleExp, BYTECODE}));
INSTANTIATE_TEST_SUITE_P(SimpleExpCopy, ProverTests, ::testing::Values(Input{SimpleExp, COPY}));
INSTANTIATE_TEST_SUITE_P(SimpleExpZkevm, ProverTests, ::testing::Values(Input{SimpleExp, ZKEVM}));
INSTANTIATE_TEST_SUITE_P(SimpleExpExp, ProverTests, ::testing::Values(Input{SimpleExp, EXP}));
INSTANTIATE_TEST_SUITE_P(SimpleExpKeccak, ProverTests, ::testing::Values(Input{SimpleExp, KECCAK}));

// ARITHMETIC CORNER CASES (OVERFLOW, UNDERFLOW, DIVISION BY ZERO)

const std::string AdditionOverflow = "corner_cases/addition_overflow/addition_overflow";
INSTANTIATE_TEST_SUITE_P(AdditionOverflowRw, ProverTests, ::testing::Values(Input{AdditionOverflow, RW}));
INSTANTIATE_TEST_SUITE_P(AdditionOverflowBytecode, ProverTests, :: testing::Values(Input{AdditionOverflow, BYTECODE}));
INSTANTIATE_TEST_SUITE_P(AdditionOverflowCopy, ProverTests, ::testing::Values(Input{AdditionOverflow, COPY}));
INSTANTIATE_TEST_SUITE_P(AdditionOverflowZkevm, ProverTests, ::testing::Values(Input{AdditionOverflow, ZKEVM}));
INSTANTIATE_TEST_SUITE_P(AdditionOverflowExp, ProverTests, ::testing::Values(Input{AdditionOverflow, EXP}));
INSTANTIATE_TEST_SUITE_P(AdditionOverflowKeccak, ProverTests, ::testing::Values(Input{AdditionOverflow, KECCAK}));

const std::string SubstractionUnderflow = "corner_cases/substraction_underflow/substraction_underflow";
INSTANTIATE_TEST_SUITE_P(SubstractionUnderflowRw, ProverTests, ::testing::Values(Input{SubstractionUnderflow, RW}));
INSTANTIATE_TEST_SUITE_P(SubstractionUnderflowBytecode, ProverTests, :: testing::Values(Input{SubstractionUnderflow, BYTECODE}));
INSTANTIATE_TEST_SUITE_P(SubstractionUnderflowCopy, ProverTests, ::testing::Values(Input{SubstractionUnderflow, COPY}));
INSTANTIATE_TEST_SUITE_P(SubstractionUnderflowZkevm, ProverTests, ::testing::Values(Input{SubstractionUnderflow, ZKEVM}));
INSTANTIATE_TEST_SUITE_P(SubstractionUnderflowExp, ProverTests, ::testing::Values(Input{SubstractionUnderflow, EXP}));
INSTANTIATE_TEST_SUITE_P(SubstractionUnderflowKeccak, ProverTests, ::testing::Values(Input{SubstractionUnderflow, KECCAK}));

const std::string DivByZero = "corner_cases/division_by_zero/div_by_zero";
INSTANTIATE_TEST_SUITE_P(DivByZeroRw, ProverTests, ::testing::Values(Input{DivByZero, RW}));
INSTANTIATE_TEST_SUITE_P(DivByZeroBytecode, ProverTests, :: testing::Values(Input{DivByZero, BYTECODE}));
INSTANTIATE_TEST_SUITE_P(DivByZeroCopy, ProverTests, ::testing::Values(Input{DivByZero, COPY}));
INSTANTIATE_TEST_SUITE_P(DivByZeroZkevm, ProverTests, ::testing::Values(Input{DivByZero, ZKEVM}));
INSTANTIATE_TEST_SUITE_P(DivByZeroExp, ProverTests, ::testing::Values(Input{DivByZero, EXP}));
INSTANTIATE_TEST_SUITE_P(DivByZeroKeccak, ProverTests, ::testing::Values(Input{DivByZero, KECCAK}));

const std::string MultiplicationOverflow = "corner_cases/multiplication_overflow/mul_overflow";
INSTANTIATE_TEST_SUITE_P(MultiplicationOverflowRw, ProverTests, ::testing::Values(Input{MultiplicationOverflow, RW}));
INSTANTIATE_TEST_SUITE_P(MultiplicationOverflowBytecode, ProverTests, :: testing::Values(Input{MultiplicationOverflow, BYTECODE}));
INSTANTIATE_TEST_SUITE_P(MultiplicationOverflowCopy, ProverTests, ::testing::Values(Input{MultiplicationOverflow, COPY}));
INSTANTIATE_TEST_SUITE_P(MultiplicationOverflowZkevm, ProverTests, ::testing::Values(Input{MultiplicationOverflow, ZKEVM}));
INSTANTIATE_TEST_SUITE_P(MultiplicationOverflowExp, ProverTests, ::testing::Values(Input{MultiplicationOverflow, EXP}));
INSTANTIATE_TEST_SUITE_P(MultiplicationOverflowKeccak, ProverTests, ::testing::Values(Input{MultiplicationOverflow, KECCAK}));

const std::string ExponentiationOverflow = "corner_cases/exponentiation_overflow/exp_overflow";
INSTANTIATE_TEST_SUITE_P(ExponentiationOverflowRw, ProverTests, ::testing::Values(Input{ExponentiationOverflow, RW}));
INSTANTIATE_TEST_SUITE_P(ExponentiationOverflowBytecode, ProverTests, :: testing::Values(Input{ExponentiationOverflow, BYTECODE}));
INSTANTIATE_TEST_SUITE_P(ExponentiationOverflowCopy, ProverTests, ::testing::Values(Input{ExponentiationOverflow, COPY}));
INSTANTIATE_TEST_SUITE_P(ExponentiationOverflowZkevm, ProverTests, ::testing::Values(Input{ExponentiationOverflow, ZKEVM}));
INSTANTIATE_TEST_SUITE_P(ExponentiationOverflowExp, ProverTests, ::testing::Values(Input{ExponentiationOverflow, EXP}));
INSTANTIATE_TEST_SUITE_P(ExponentiationOverflowKeccak, ProverTests, ::testing::Values(Input{ExponentiationOverflow, KECCAK}));


// MEMORY EXPANSTION TESTS

const std::string MemExpandCalldataCopy = "memory_expansion/calldatacopy/mem_expand_calldatacopy";
INSTANTIATE_TEST_SUITE_P(MemExpandCalldataCopyRw, ProverTests, ::testing::Values(Input{MemExpandCalldataCopy, RW}));
INSTANTIATE_TEST_SUITE_P(MemExpandCalldataCopyBytecode, ProverTests, :: testing::Values(Input{MemExpandCalldataCopy, BYTECODE}));
INSTANTIATE_TEST_SUITE_P(MemExpandCalldataCopyCopy, ProverTests, ::testing::Values(Input{MemExpandCalldataCopy, COPY}));
INSTANTIATE_TEST_SUITE_P(MemExpandCalldataCopyZkevm, ProverTests, ::testing::Values(Input{MemExpandCalldataCopy, ZKEVM}));
INSTANTIATE_TEST_SUITE_P(MemExpandCalldataCopyExp, ProverTests, ::testing::Values(Input{MemExpandCalldataCopy, EXP}));
INSTANTIATE_TEST_SUITE_P(MemExpandCalldataCopyKeccak, ProverTests, ::testing::Values(Input{MemExpandCalldataCopy, KECCAK}));


const std::string MemExpandCodeCopy = "memory_expansion/codecopy/mem_expand_codecopy";
INSTANTIATE_TEST_SUITE_P(MemExpandCodeCopyRw, ProverTests, ::testing::Values(Input{MemExpandCodeCopy, RW}));
INSTANTIATE_TEST_SUITE_P(MemExpandCodeCopyBytecode, ProverTests, :: testing::Values(Input{MemExpandCodeCopy, BYTECODE}));
INSTANTIATE_TEST_SUITE_P(MemExpandCodeCopyCopy, ProverTests, ::testing::Values(Input{MemExpandCodeCopy, COPY}));
INSTANTIATE_TEST_SUITE_P(MemExpandCodeCopyZkevm, ProverTests, ::testing::Values(Input{MemExpandCodeCopy, ZKEVM}));
INSTANTIATE_TEST_SUITE_P(MemExpandCodeCopyExp, ProverTests, ::testing::Values(Input{MemExpandCodeCopy, EXP}));
INSTANTIATE_TEST_SUITE_P(MemExpandCodeCopyKeccak, ProverTests, ::testing::Values(Input{MemExpandCodeCopy, KECCAK}));

const std::string MemExpandMload = "memory_expansion/mload/mem_expand_mload";
INSTANTIATE_TEST_SUITE_P(MemExpandMloadRw, ProverTests, ::testing::Values(Input{MemExpandMload, RW}));
INSTANTIATE_TEST_SUITE_P(MemExpandMloadBytecode, ProverTests, :: testing::Values(Input{MemExpandMload, BYTECODE}));
INSTANTIATE_TEST_SUITE_P(MemExpandMloadCopy, ProverTests, ::testing::Values(Input{MemExpandMload, COPY}));
INSTANTIATE_TEST_SUITE_P(MemExpandMloadZkevm, ProverTests, ::testing::Values(Input{MemExpandMload, ZKEVM}));
INSTANTIATE_TEST_SUITE_P(MemExpandMloadExp, ProverTests, ::testing::Values(Input{MemExpandMload, EXP}));
INSTANTIATE_TEST_SUITE_P(MemExpandMloadKeccak, ProverTests, ::testing::Values(Input{MemExpandMload, KECCAK}));

const std::string MemExpandMstore = "memory_expansion/mstore/mem_expand_mstore";
INSTANTIATE_TEST_SUITE_P(MemExpandMstoreRw, ProverTests, ::testing::Values(Input{MemExpandMstore, RW}));
INSTANTIATE_TEST_SUITE_P(MemExpandMstoreBytecode, ProverTests, :: testing::Values(Input{MemExpandMstore, BYTECODE}));
INSTANTIATE_TEST_SUITE_P(MemExpandMstoreCopy, ProverTests, ::testing::Values(Input{MemExpandMstore, COPY}));
INSTANTIATE_TEST_SUITE_P(MemExpandMstoreZkevm, ProverTests, ::testing::Values(Input{MemExpandMstore, ZKEVM}));
INSTANTIATE_TEST_SUITE_P(MemExpandMstoreExp, ProverTests, ::testing::Values(Input{MemExpandMstore, EXP}));
INSTANTIATE_TEST_SUITE_P(MemExpandMstoreKeccak, ProverTests, ::testing::Values(Input{MemExpandMstore, KECCAK}));

const std::string MemExpandMstore8 = "memory_expansion/mstore/mem_expand_mstore8";
INSTANTIATE_TEST_SUITE_P(MemExpandMstore8Rw, ProverTests, ::testing::Values(Input{MemExpandMstore8, RW}));
INSTANTIATE_TEST_SUITE_P(MemExpandMstore8Bytecode, ProverTests, :: testing::Values(Input{MemExpandMstore8, BYTECODE}));
INSTANTIATE_TEST_SUITE_P(MemExpandMstore8Copy, ProverTests, ::testing::Values(Input{MemExpandMstore8, COPY}));
INSTANTIATE_TEST_SUITE_P(MemExpandMstore8Zkevm, ProverTests, ::testing::Values(Input{MemExpandMstore8, ZKEVM}));
INSTANTIATE_TEST_SUITE_P(MemExpandMstore8Exp, ProverTests, ::testing::Values(Input{MemExpandMstore8, EXP}));
INSTANTIATE_TEST_SUITE_P(MemExpandMstore8Keccak, ProverTests, ::testing::Values(Input{MemExpandMstore8, KECCAK}));

const std::string MemMcopy = "memory_expansion/mcopy/mem_expand_mcopy";
INSTANTIATE_TEST_SUITE_P(MemMcopyRw, ProverTests, ::testing::Values(Input{MemMcopy, RW}));
INSTANTIATE_TEST_SUITE_P(MemMcopyBytecode, ProverTests, :: testing::Values(Input{MemMcopy, BYTECODE}));
INSTANTIATE_TEST_SUITE_P(MemMcopyCopy, ProverTests, ::testing::Values(Input{MemMcopy, COPY}));
INSTANTIATE_TEST_SUITE_P(MemMcopyZkevm, ProverTests, ::testing::Values(Input{MemMcopy, ZKEVM}));
INSTANTIATE_TEST_SUITE_P(MemMcopyExp, ProverTests, ::testing::Values(Input{MemMcopy, EXP}));
INSTANTIATE_TEST_SUITE_P(MemMcopyKeccak, ProverTests, ::testing::Values(Input{MemMcopy, KECCAK}));

const std::string MemExpandReturndatacopy = "memory_expansion/returndatacopy/mem_expand_returndatacopy";

// TODO(oclaw): RW circuit now fails to validate memory operations done inside CALL subcontext
INSTANTIATE_TEST_SUITE_P(MemExpandReturndatacopyRw, ProverTests, ::testing::Values(Input{MemExpandReturndatacopy, RW, true}));

INSTANTIATE_TEST_SUITE_P(MemExpandReturndatacopyBytecode, ProverTests, :: testing::Values(Input{MemExpandReturndatacopy, BYTECODE}));
INSTANTIATE_TEST_SUITE_P(MemExpandReturndatacopyCopy, ProverTests, ::testing::Values(Input{MemExpandReturndatacopy, COPY}));
INSTANTIATE_TEST_SUITE_P(MemExpandReturndatacopyZkevm, ProverTests, ::testing::Values(Input{MemExpandReturndatacopy, ZKEVM}));
INSTANTIATE_TEST_SUITE_P(MemExpandReturndatacopyExp, ProverTests, ::testing::Values(Input{MemExpandReturndatacopy, EXP}));
INSTANTIATE_TEST_SUITE_P(MemExpandReturndatacopyKeccak, ProverTests, ::testing::Values(Input{MemExpandReturndatacopy, KECCAK}));

// RW trace is picked from another trace set and has different trace_idx
TEST(ProverTest, TraceIndexMismatch) {
    const std::string trace_base_path = std::string(TEST_DATA_DIR) + "/broken_index/increment_simple";

    ProverTests::AssignmentTableChecker checker(ZKEVM, trace_base_path);
    auto const res = checker.execute();
    ASSERT_EQ(res.result_code(), nil::proof_producer::ResultCode::InvalidInput);
    ASSERT_NE(checker.circuit_, nullptr);        // circuit is filled
    ASSERT_EQ(checker.assignment_table_, nullptr); // assignment table is not filled
}

// Trace files contain different proto hash
TEST(ProverTest, DifferentProtoHash) {
    const std::string trace_base_path = std::string(TEST_DATA_DIR) + "/different_proto/increment_simple.pb";

    ProverTests::AssignmentTableChecker checker(ZKEVM, trace_base_path);
    auto const res = checker.execute();
    ASSERT_EQ(res.result_code(), nil::proof_producer::ResultCode::InvalidInput);
    ASSERT_NE(checker.circuit_, nullptr);        // circuit is filled
    ASSERT_EQ(checker.assignment_table_, nullptr); // assignment table is not filled
}
