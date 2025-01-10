//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022-2023 Elena Tatuzova <e.tatuzova@nil.foundation>
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE crypto3_marshalling_placeholder_proof_test

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <filesystem>
#include <algorithm>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>

#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/pairing/mnt6.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt6.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/pairing/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/poseidon.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/zk/commitments/type_traits.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/profiling.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>

#include <nil/crypto3/marshalling/zk/types/commitments/eval_storage.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/kzg.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/lpc.hpp>
#include <nil/crypto3/marshalling/zk/types/placeholder/proof.hpp>

#include <nil/crypto3/marshalling/algebra/processing/bls12.hpp>
#include <nil/crypto3/marshalling/algebra/processing/alt_bn128.hpp>
#include <nil/crypto3/marshalling/algebra/processing/mnt4.hpp>
#include <nil/crypto3/marshalling/algebra/processing/mnt6.hpp>

#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/test_tools/random_test_initializer.hpp>
#include <nil/crypto3/marshalling/zk/detail/random_test_data_generation.hpp>

#include "./detail/circuits.hpp"

using namespace nil;
using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::zk::snark;

template<typename FieldType,
        typename merkle_hash_type,
        typename transcript_hash_type>
struct placeholder_lpc_proof_test_runner {

    using Endianness = nil::crypto3::marshalling::option::big_endian;
    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;
    using field_type = FieldType;

    typedef placeholder_circuit_params<field_type> circuit_params;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

    constexpr static std::size_t m = 2;
    constexpr static std::size_t lambda = 10;

    using lpc_params_type = commitments::list_polynomial_commitment_params<
        merkle_hash_type,
        transcript_hash_type,
        m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, lpc_placeholder_params_type>;

    using constraint_system = typename policy_type::constraint_system_type;
    using circuit_type = circuit_description<field_type, placeholder_circuit_params<field_type>>;

    using public_preprocessor = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>;
    using private_preprocessor = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>;

    using common_data_type = typename public_preprocessor::preprocessed_data_type::common_data_type;

    placeholder_lpc_proof_test_runner(circuit_type const& circuit) :
        circuit(circuit)
    {
    }

    bool run_test()
    {
        std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

        typename policy_type::constraint_system_type constraint_system(
                circuit.gates, circuit.copy_constraints, circuit.lookup_gates, circuit.lookup_tables);
        typename policy_type::variable_assignment_type assignments = circuit.table;

        typename lpc_type::fri_type::params_type fri_params(
                1, table_rows_log, lambda, 4, false
                );
        lpc_scheme_type lpc_scheme(fri_params);

        std::size_t max_quotient_chunks = 10;

        plonk_table_description<field_type> desc = circuit.table.get_description();
        desc.usable_rows_amount = circuit.usable_rows;

        typename public_preprocessor::preprocessed_data_type
            lpc_preprocessed_public_data = public_preprocessor::process(
                    constraint_system, assignments.public_table(), desc, lpc_scheme, max_quotient_chunks
                    );

        typename private_preprocessor::preprocessed_data_type
            lpc_preprocessed_private_data = private_preprocessor::process(
                    constraint_system, assignments.private_table(), desc
                    );

        auto lpc_proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
                lpc_preprocessed_public_data, lpc_preprocessed_private_data, desc, constraint_system, lpc_scheme
                );

        test_placeholder_proof(lpc_proof, fri_params);
        test_placeholder_partial_proof(lpc_proof, fri_params);

        auto verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
                *lpc_preprocessed_public_data.common_data, lpc_proof, desc, constraint_system, lpc_scheme
                );

        /*
        for(auto &it:lpc_proof.commitments ) {
            std::cout << "Commitment " << it.first << " = " << it.second << std::endl;
        }
        */

        BOOST_CHECK(verifier_res);

        return true;
    }

    using PlaceholderParams = lpc_placeholder_params_type;

    using ProofType = placeholder_proof<typename PlaceholderParams::field_type, PlaceholderParams>;
    using CommitmentParamsType = typename lpc_type::fri_type::params_type;

    void test_placeholder_proof(const ProofType &proof, const CommitmentParamsType& params)
    {
        using namespace nil::crypto3::marshalling;

        using proof_marshalling_type = nil::crypto3::marshalling::types::placeholder_proof<TTypeBase, ProofType>;

        auto filled_placeholder_proof = types::fill_placeholder_proof<Endianness, ProofType>(proof, params);
        ProofType _proof = types::make_placeholder_proof<Endianness, ProofType>(filled_placeholder_proof);
        BOOST_CHECK(_proof == proof);

        std::vector<std::uint8_t> cv;
        cv.resize(filled_placeholder_proof.length(), 0x00);
        auto write_iter = cv.begin();
        auto status = filled_placeholder_proof.write(write_iter, cv.size());
        BOOST_CHECK(status == nil::crypto3::marshalling::status_type::success);

        proof_marshalling_type test_val_read;
        auto read_iter = cv.begin();
        status = test_val_read.read(read_iter, cv.size());
        BOOST_CHECK(status == nil::crypto3::marshalling::status_type::success);
        auto constructed_val_read = types::make_placeholder_proof<Endianness, ProofType>(test_val_read);
        BOOST_CHECK(proof == constructed_val_read);
    }

    void test_placeholder_partial_proof(const typename ProofType::partial_proof_type &proof, const CommitmentParamsType& params)
    {

        using namespace nil::crypto3::marshalling;

        using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;
        using proof_marshalling_type = nil::crypto3::marshalling::types::placeholder_partial_evaluation_proof<TTypeBase, ProofType>;

        auto filled_placeholder_proof = types::fill_placeholder_partial_evaluation_proof<Endianness, ProofType>(proof);
        ProofType _proof = types::make_placeholder_partial_evaluation_proof<Endianness, ProofType>(filled_placeholder_proof);
        BOOST_CHECK(_proof == proof);

        std::vector<std::uint8_t> cv;
        cv.resize(filled_placeholder_proof.length(), 0x00);
        auto write_iter = cv.begin();
        auto status = filled_placeholder_proof.write(write_iter, cv.size());
        BOOST_CHECK(status == nil::crypto3::marshalling::status_type::success);

        proof_marshalling_type test_val_read;
        auto read_iter = cv.begin();
        status = test_val_read.read(read_iter, cv.size());
        BOOST_CHECK(status == nil::crypto3::marshalling::status_type::success);
        auto constructed_val_read = types::make_placeholder_partial_evaluation_proof<Endianness, ProofType>(test_val_read);
        BOOST_CHECK(proof == constructed_val_read);
    }

    using batch_lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using batch_lpc_scheme_type = typename commitments::lpc_commitment_scheme<batch_lpc_type>;
    using batch_lpc_placeholder_params_type =
        nil::crypto3::zk::snark::placeholder_params<circuit_params, batch_lpc_scheme_type>;
    using AggregatedProofType = placeholder_aggregated_proof<field_type, batch_lpc_placeholder_params_type>;

    void test_placeholder_aggregated_proof(
            const AggregatedProofType &proof,
            const CommitmentParamsType& params)
    {
        using namespace nil::crypto3::marshalling;

        using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;
        using proof_marshalling_type = nil::crypto3::marshalling::types::placeholder_aggregated_proof_type<TTypeBase, ProofType>;

        auto filled_placeholder_proof = types::fill_placeholder_aggregated_proof<Endianness, AggregatedProofType,  ProofType>(proof);
        AggregatedProofType _proof = types::make_placeholder_aggregated_proof<
            Endianness, AggregatedProofType, ProofType>(filled_placeholder_proof);
        BOOST_CHECK(_proof == proof);

        std::vector<std::uint8_t> cv;
        cv.resize(filled_placeholder_proof.length(), 0x00);
        auto write_iter = cv.begin();
        auto status = filled_placeholder_proof.write(write_iter, cv.size());
        BOOST_CHECK(status == nil::crypto3::marshalling::status_type::success);

        proof_marshalling_type test_val_read;
        auto read_iter = cv.begin();
        status = test_val_read.read(read_iter, cv.size());
        BOOST_CHECK(status == nil::crypto3::marshalling::status_type::success);
        auto constructed_val_read = types::make_placeholder_aggregated_proof<Endianness, AggregatedProofType, ProofType>(test_val_read);
        BOOST_CHECK(proof == constructed_val_read);
    }

    bool run_aggregated_proof_test()
    {
        std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

        typename policy_type::constraint_system_type constraint_system(
                circuit.gates, circuit.copy_constraints, circuit.lookup_gates, circuit.lookup_tables);
        typename policy_type::variable_assignment_type assignments = circuit.table;

        typename lpc_type::fri_type::params_type fri_params(
                1, table_rows_log, lambda, 4, false
                );
        lpc_scheme_type lpc_scheme(fri_params);

        std::size_t max_quotient_chunks = 10;

        plonk_table_description<field_type> desc = circuit.table.get_description();
        desc.usable_rows_amount = circuit.usable_rows;

        typename public_preprocessor::preprocessed_data_type
            lpc_preprocessed_public_data = public_preprocessor::process(
                    constraint_system, assignments.public_table(), desc, lpc_scheme, max_quotient_chunks
                    );

        typename private_preprocessor::preprocessed_data_type
            lpc_preprocessed_private_data = private_preprocessor::process(
                    constraint_system, assignments.private_table(), desc
                    );

        auto proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
                lpc_preprocessed_public_data, lpc_preprocessed_private_data, desc, constraint_system, lpc_scheme
                );

        // now we get a vector of partial proofs
        std::vector<placeholder_partial_proof<field_type, batch_lpc_placeholder_params_type>> partial_proofs;
        for (std::size_t i = 0; i < 5; i++) {
            partial_proofs.push_back(proof);
        }
        test_tools::random_test_initializer<field_type> random_test_initializer;
        // and lpc aggregated proof
        auto lpc_proof = generate_random_lpc_aggregated_proof<lpc_type>(
                7, 5,
                fri_params.step_list,
                10,
                false,
                random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
                random_test_initializer.generic_random_engine
                );
        AggregatedProofType aggregated_proof;
        aggregated_proof.partial_proofs = partial_proofs;
        aggregated_proof.aggregated_proof = lpc_proof;
        test_placeholder_aggregated_proof(aggregated_proof, fri_params);
        return true;
    }

    circuit_type circuit;
};

BOOST_AUTO_TEST_SUITE(placeholder_lpc_proof)
using pallas_base_field = typename curves::pallas::base_field_type;
using keccak_256 = hashes::keccak_1600<256>;
using keccak_512 = hashes::keccak_1600<512>;
using sha2_256 = hashes::sha2<256>;
using poseidon_over_pallas = hashes::poseidon<nil::crypto3::hashes::detail::pasta_poseidon_policy<pallas_base_field>>;

using TestRunners = boost::mpl::list<
    /* Test pallas with different hashes */
    placeholder_lpc_proof_test_runner<pallas_base_field, poseidon_over_pallas, poseidon_over_pallas>,
    placeholder_lpc_proof_test_runner<pallas_base_field, keccak_256, keccak_256>,
    placeholder_lpc_proof_test_runner<pallas_base_field, keccak_512, keccak_512>,

    /* Test case for different hashes of transcript and merkle tree */
    placeholder_lpc_proof_test_runner<pallas_base_field, keccak_256, sha2_256>,

    /* Test other curves with keccak_256 */
    placeholder_lpc_proof_test_runner<typename curves::bls12_381::scalar_field_type, keccak_256, keccak_256>,
    placeholder_lpc_proof_test_runner<typename curves::alt_bn128_254::scalar_field_type, keccak_256, keccak_256>,
    placeholder_lpc_proof_test_runner<typename curves::mnt4_298::scalar_field_type, keccak_256, keccak_256>,
    placeholder_lpc_proof_test_runner<typename curves::mnt6_298::scalar_field_type, keccak_256, keccak_256>
>;

BOOST_AUTO_TEST_CASE_TEMPLATE(circuit_1, TestRunner, TestRunners)
{
    using field_type = typename TestRunner::field_type;
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_1<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
            );

    TestRunner test_runner(circuit);

    BOOST_CHECK(test_runner.run_test());
    BOOST_CHECK(test_runner.run_aggregated_proof_test());
}

BOOST_AUTO_TEST_CASE_TEMPLATE(circuit_2, TestRunner, TestRunners)
{
    using field_type = typename TestRunner::field_type;
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto pi0 = random_test_initializer.alg_random_engines.template get_alg_engine<field_type>()();
    auto circuit = circuit_test_t<field_type>(
            pi0,
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
            );

    TestRunner test_runner(circuit);

    BOOST_CHECK(test_runner.run_test());
    BOOST_CHECK(test_runner.run_aggregated_proof_test());
}

BOOST_AUTO_TEST_CASE_TEMPLATE(circuit_3, TestRunner, TestRunners)
{
    using field_type = typename TestRunner::field_type;
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_3<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
            );

    TestRunner test_runner(circuit);

    BOOST_CHECK(test_runner.run_test());
    BOOST_CHECK(test_runner.run_aggregated_proof_test());
}

BOOST_AUTO_TEST_CASE_TEMPLATE(circuit_4, TestRunner, TestRunners)
{
    using field_type = typename TestRunner::field_type;
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_4<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
            );

    TestRunner test_runner(circuit);

    BOOST_CHECK(test_runner.run_test());
    BOOST_CHECK(test_runner.run_aggregated_proof_test());
}

BOOST_AUTO_TEST_CASE_TEMPLATE(circuit_5, TestRunner, TestRunners)
{
    using field_type = typename TestRunner::field_type;
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_5<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
            );

    TestRunner test_runner(circuit);

    BOOST_CHECK(test_runner.run_test());
    BOOST_CHECK(test_runner.run_aggregated_proof_test());
}

BOOST_AUTO_TEST_CASE_TEMPLATE(circuit_6, TestRunner, TestRunners)
{
    using field_type = typename TestRunner::field_type;
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_6<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
            );

    TestRunner test_runner(circuit);

    BOOST_CHECK(test_runner.run_test());
    BOOST_CHECK(test_runner.run_aggregated_proof_test());
}

BOOST_AUTO_TEST_CASE_TEMPLATE(circuit_7, TestRunner, TestRunners)
{
    using field_type = typename TestRunner::field_type;
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_7<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
            );

    TestRunner test_runner(circuit);

    BOOST_CHECK(test_runner.run_test());
    BOOST_CHECK(test_runner.run_aggregated_proof_test());
}

BOOST_AUTO_TEST_CASE_TEMPLATE(circuit_8, TestRunner, TestRunners)
{
    using field_type = typename TestRunner::field_type;
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_8<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
            );

    TestRunner test_runner(circuit);

    BOOST_CHECK(test_runner.run_test());
    BOOST_CHECK(test_runner.run_aggregated_proof_test());
}

BOOST_AUTO_TEST_CASE_TEMPLATE(circuit_fib, TestRunner, TestRunners)
{
    using field_type = typename TestRunner::field_type;
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_fib<field_type, 100>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>()
            );

    TestRunner test_runner(circuit);

    BOOST_CHECK(test_runner.run_test());
    BOOST_CHECK(test_runner.run_aggregated_proof_test());
}

BOOST_AUTO_TEST_SUITE_END()


template<
    typename curve_type,
    typename merkle_hash_type,
    typename transcript_hash_type >
struct placeholder_kzg_v2_proof_test_runner : public test_tools::random_test_initializer<typename curve_type::scalar_field_type> {
    using field_type = typename curve_type::scalar_field_type;

    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

    using circuit_params = placeholder_circuit_params<field_type>;

    using kzg_type = commitments::batched_kzg<curve_type, transcript_hash_type>;
    using kzg_scheme_type = typename commitments::kzg_commitment_scheme_v2<kzg_type>;
    using kzg_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, kzg_scheme_type>;

    using policy_type = zk::snark::detail::placeholder_policy<field_type, kzg_placeholder_params_type>;

    using circuit_type =
        circuit_description<field_type,
        placeholder_circuit_params<field_type>>;

    placeholder_kzg_v2_proof_test_runner(circuit_type const& circuit)
        : circuit(circuit)
    {
    }

    using PlaceholderParams = kzg_placeholder_params_type;
    using ProofType = placeholder_proof<typename PlaceholderParams::field_type, PlaceholderParams>;
    using CommitmentParamsType = typename kzg_type::params_type;

    void test_placeholder_proof(const ProofType &proof, const CommitmentParamsType& params, std::string output_file = "")
    {
        using namespace nil::crypto3::marshalling;
        using Endianness = nil::crypto3::marshalling::option::big_endian;
        using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;

        using proof_marshalling_type = nil::crypto3::marshalling::types::placeholder_proof<TTypeBase, ProofType>;

        auto filled_placeholder_proof = types::fill_placeholder_proof<Endianness, ProofType>(proof, params);
        ProofType _proof = types::make_placeholder_proof<Endianness, ProofType>(filled_placeholder_proof);
        BOOST_CHECK(_proof == proof);

        std::vector<std::uint8_t> cv;
        cv.resize(filled_placeholder_proof.length(), 0x00);
        auto write_iter = cv.begin();
        auto status = filled_placeholder_proof.write(write_iter, cv.size());
        BOOST_CHECK(status == nil::crypto3::marshalling::status_type::success);

        proof_marshalling_type test_val_read;
        auto read_iter = cv.begin();
        status = test_val_read.read(read_iter, cv.size());
        BOOST_CHECK(status == nil::crypto3::marshalling::status_type::success);
        auto constructed_val_read = types::make_placeholder_proof<Endianness, ProofType>(test_val_read);
        BOOST_CHECK(proof == constructed_val_read);
    }


    bool run_test() {

        std::size_t table_rows_log = std::log2(circuit.table_rows);

        typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints, circuit.lookup_gates);
        typename policy_type::variable_assignment_type assignments = circuit.table;

        // KZG commitment scheme
        typename kzg_type::field_type::value_type alpha(7u);
        auto kzg_params = kzg_scheme_type::create_params(1 << table_rows_log, alpha);
        kzg_scheme_type kzg_scheme(kzg_params);

        plonk_table_description<field_type> desc = circuit.table.get_description();
        desc.usable_rows_amount = circuit.usable_rows;

        typename placeholder_public_preprocessor<field_type, kzg_placeholder_params_type>::preprocessed_data_type
            kzg_preprocessed_public_data =
            placeholder_public_preprocessor<field_type, kzg_placeholder_params_type>::process(
                constraint_system, assignments.public_table(), desc, kzg_scheme
            );

        typename placeholder_private_preprocessor<field_type, kzg_placeholder_params_type>::preprocessed_data_type
            kzg_preprocessed_private_data = placeholder_private_preprocessor<field_type, kzg_placeholder_params_type>::process(
                    constraint_system, assignments.private_table(), desc
                    );

        auto kzg_proof = placeholder_prover<field_type, kzg_placeholder_params_type>::process(
                kzg_preprocessed_public_data, std::move(kzg_preprocessed_private_data), desc, constraint_system, kzg_scheme
                );

        using common_data_type = typename placeholder_public_preprocessor<field_type, kzg_placeholder_params_type>::preprocessed_data_type::common_data_type;
        using Endianness = nil::crypto3::marshalling::option::big_endian;

        test_placeholder_proof(kzg_proof, kzg_params);

        kzg_scheme = kzg_scheme_type(kzg_params);
        bool verifier_res = placeholder_verifier<field_type, kzg_placeholder_params_type>::process(
                *kzg_preprocessed_public_data.common_data, kzg_proof, desc, constraint_system, kzg_scheme);
        BOOST_CHECK(verifier_res);
        return true;
    }

    circuit_type circuit;
};

BOOST_AUTO_TEST_SUITE(placeholder_kzg_v2_proof)

using keccak_256 = hashes::keccak_1600<256>;

/* KZG v2 only for pairing-friendly curves */
using TestRunners = boost::mpl::list<
    placeholder_kzg_v2_proof_test_runner<curves::bls12_381, keccak_256, keccak_256>,
    placeholder_kzg_v2_proof_test_runner<curves::alt_bn128_254, keccak_256, keccak_256>,
    placeholder_kzg_v2_proof_test_runner<curves::mnt4_298, keccak_256, keccak_256>,
    placeholder_kzg_v2_proof_test_runner<curves::mnt6_298, keccak_256, keccak_256>
>;

BOOST_AUTO_TEST_CASE_TEMPLATE(circuit_1, TestRunner, TestRunners)
{
    using field_type = typename TestRunner::field_type;
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_1<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
            );

    TestRunner test_runner(circuit);

    BOOST_CHECK(test_runner.run_test());
}

BOOST_AUTO_TEST_CASE_TEMPLATE(circuit_2, TestRunner, TestRunners)
{
    using field_type = typename TestRunner::field_type;
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto pi0 = random_test_initializer.alg_random_engines.template get_alg_engine<field_type>()();
    auto circuit = circuit_test_t<field_type>(
            pi0,
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
            );

    TestRunner test_runner(circuit);

    BOOST_CHECK(test_runner.run_test());
}

// TODO: Fix placeholder with KZG with lookup argument
/*
BOOST_AUTO_TEST_CASE_TEMPLATE(circuit_3, TestRunner, TestRunners)
{
    using field_type = typename TestRunner::field_type;
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_3<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
            );

    TestRunner test_runner(circuit);

    BOOST_CHECK(test_runner.run_test());
}

BOOST_AUTO_TEST_CASE_TEMPLATE(circuit_4, TestRunner, TestRunners)
{
    using field_type = typename TestRunner::field_type;
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_4<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
            );

    TestRunner test_runner(circuit);

    BOOST_CHECK(test_runner.run_test());
}
*/

BOOST_AUTO_TEST_CASE_TEMPLATE(circuit_5, TestRunner, TestRunners)
{
    using field_type = typename TestRunner::field_type;
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_5<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
            );

    TestRunner test_runner(circuit);

    BOOST_CHECK(test_runner.run_test());
}

// TODO: Fix placeholder with KZG with lookup argument
/*
BOOST_AUTO_TEST_CASE_TEMPLATE(circuit_6, TestRunner, TestRunners)
{
    using field_type = typename TestRunner::field_type;
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_6<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
            );

    TestRunner test_runner(circuit);

    BOOST_CHECK(test_runner.run_test());
}

BOOST_AUTO_TEST_CASE_TEMPLATE(circuit_7, TestRunner, TestRunners)
{
    using field_type = typename TestRunner::field_type;
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_7<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
            );

    TestRunner test_runner(circuit);

    BOOST_CHECK(test_runner.run_test());
}

BOOST_AUTO_TEST_CASE_TEMPLATE(circuit_8, TestRunner, TestRunners)
{
    using field_type = typename TestRunner::field_type;
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_8<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
            );

    TestRunner test_runner(circuit);

    BOOST_CHECK(test_runner.run_test());
}
*/

BOOST_AUTO_TEST_CASE_TEMPLATE(circuit_fib, TestRunner, TestRunners)
{
    using field_type = typename TestRunner::field_type;
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_fib<field_type, 100>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>()
            );

    TestRunner test_runner(circuit);

    BOOST_CHECK(test_runner.run_test());
}

BOOST_AUTO_TEST_SUITE_END()

