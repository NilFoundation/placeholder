#include <gtest/gtest.h>
#include <memory>

#include <nil/blueprint/utils/satisfiability_check.hpp>

#include <nil/proof-generator/prover.hpp>

class ProverTests: public ::testing::Test {

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

TEST_F(ProverTests, Bytecode) {
    std::string trace_file_path = std::string(TEST_DATA_DIR) + "increment_multi_tx.pb";
    nil::proof_generator::Prover<CurveType, HashType> prover(
                        lambda,
                        expand_factor,
                        max_quotient_chunks,
                        grind,
                        nil::proof_generator::circuits::BYTECODE
    );

    ASSERT_TRUE(prover.setup_prover());

    ASSERT_TRUE(prover.fill_assignment_table(trace_file_path));

    const auto& circuit = prover.get_constraint_system();
    const auto& assignment_table = prover.get_assignment_table();

    ASSERT_TRUE(nil::blueprint::is_satisfied<BlueprintFieldType>(circuit, assignment_table));
}

TEST_F(ProverTests, RW) {
    std::string trace_file_path = std::string(TEST_DATA_DIR) + "increment_multi_tx.pb";
    nil::proof_generator::Prover<CurveType, HashType> prover(
                        lambda,
                        expand_factor,
                        max_quotient_chunks,
                        grind,
                        nil::proof_generator::circuits::RW
    );

    ASSERT_TRUE(prover.setup_prover());

    ASSERT_TRUE(prover.fill_assignment_table(trace_file_path));

    const auto& circuit = prover.get_constraint_system();
    const auto& assignment_table = prover.get_assignment_table();

    ASSERT_TRUE(nil::blueprint::is_satisfied<BlueprintFieldType>(circuit, assignment_table));
}

TEST_F(ProverTests, Copy) {
    std::string trace_file_path = std::string(TEST_DATA_DIR) + "increment_multi_tx.pb";
    nil::proof_generator::Prover<CurveType, HashType> prover(
                        lambda,
                        expand_factor,
                        max_quotient_chunks,
                        grind,
                        nil::proof_generator::circuits::COPY
    );

    ASSERT_TRUE(prover.setup_prover());

    ASSERT_TRUE(prover.fill_assignment_table(trace_file_path));

    const auto& circuit = prover.get_constraint_system();
    const auto& assignment_table = prover.get_assignment_table();

    ASSERT_TRUE(nil::blueprint::is_satisfied<BlueprintFieldType>(circuit, assignment_table));
}

TEST_F(ProverTests, Zkevm) {
    std::string trace_file_path = std::string(TEST_DATA_DIR) + "increment_multi_tx.pb";
    nil::proof_generator::Prover<CurveType, HashType> prover(
                        lambda,
                        expand_factor,
                        max_quotient_chunks,
                        grind,
                        nil::proof_generator::circuits::ZKEVM
    );

    ASSERT_TRUE(prover.setup_prover());

    ASSERT_TRUE(prover.fill_assignment_table(trace_file_path));

    const auto& circuit = prover.get_constraint_system();
    const auto& assignment_table = prover.get_assignment_table();

    ASSERT_TRUE(nil::blueprint::is_satisfied<BlueprintFieldType>(circuit, assignment_table));
}
