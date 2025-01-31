#define BOOST_TEST_MODULE crypto3_marshalling_placeholder_common_data_test

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <iostream>
#include <filesystem>
#include <iomanip>
#include <fstream>
#include <algorithm>
#include <regex>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>


#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/pairing/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>

#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/pairing/mnt6.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt6.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>


#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/poseidon.hpp>

#include <nil/crypto3/zk/commitments/type_traits.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/profiling.hpp>
#include <nil/crypto3/test_tools/random_test_initializer.hpp>

#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/marshalling/zk/types/commitments/eval_storage.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/kzg.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/lpc.hpp>
#include <nil/crypto3/marshalling/zk/types/placeholder/common_data.hpp>
#include "./detail/circuits.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::zk::snark;

template<typename FieldType,
        typename merkle_hash_type,
        typename transcript_hash_type>
struct placeholder_common_data_test_runner {
    using field_type = FieldType;

    typedef placeholder_circuit_params<field_type> circuit_params;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

    constexpr static std::size_t m = 2;
    constexpr static std::size_t lambda = 40;

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
    using common_data_type = typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type::common_data_type;

    placeholder_common_data_test_runner(circuit_type const& circuit)
        : circuit(circuit)
    {
    }

    void test_placeholder_common_data(common_data_type const& common_data)
    {
        using Endianness = nil::crypto3::marshalling::option::big_endian;
        using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;

        auto filled_common_data = nil::crypto3::marshalling::types::fill_placeholder_common_data<Endianness, common_data_type>(common_data);
        auto _common_data = nil::crypto3::marshalling::types::make_placeholder_common_data<Endianness, common_data_type>(filled_common_data);
        BOOST_CHECK(common_data == *_common_data);

        std::vector<std::uint8_t> cv;
        cv.resize(filled_common_data.length(), 0x00);
        auto write_iter = cv.begin();
        auto status = filled_common_data.write(write_iter, cv.size());
        BOOST_CHECK(status == nil::crypto3::marshalling::status_type::success);

        nil::crypto3::marshalling::types::placeholder_common_data<TTypeBase, common_data_type> test_val_read;
        auto read_iter = cv.begin();
        test_val_read.read(read_iter, cv.size());
        BOOST_CHECK(status == nil::crypto3::marshalling::status_type::success);
        auto constructed_val_read = nil::crypto3::marshalling::types::make_placeholder_common_data<Endianness, common_data_type>(
                test_val_read
                );
        BOOST_CHECK(common_data == *constructed_val_read);
    }

    bool run_test()
    {
        using preprocessor = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>;

        std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

        typename policy_type::constraint_system_type constraint_system(
                circuit.gates, circuit.copy_constraints, circuit.lookup_gates);
        typename policy_type::variable_assignment_type assignments = circuit.table;

        typename lpc_type::fri_type::params_type fri_params(
                1, table_rows_log, lambda, 4, true
                );
        lpc_scheme_type lpc_scheme(fri_params);

        std::size_t max_quotient_chunks = 10;

        plonk_table_description<field_type> desc = circuit.table.get_description();
        desc.usable_rows_amount = circuit.usable_rows;

        typename preprocessor::preprocessed_data_type
            preprocessed_public_data = preprocessor::process(
                constraint_system,
                assignments.public_table(),
                desc,
                lpc_scheme,
                max_quotient_chunks);

        test_placeholder_common_data(*preprocessed_public_data.common_data);

        return true;
    }

    circuit_type circuit;
};

BOOST_AUTO_TEST_SUITE(placeholder_common_data)
using pallas_base_field = typename curves::pallas::base_field_type;
using keccak_256 = hashes::keccak_1600<256>;
using keccak_512 = hashes::keccak_1600<512>;
using sha2_256 = hashes::sha2<256>;
using poseidon_over_pallas = hashes::poseidon<nil::crypto3::hashes::detail::pasta_poseidon_policy<pallas_base_field>>;

using TestRunners = boost::mpl::list<
    /* Test pallas with different hashes */
    placeholder_common_data_test_runner<pallas_base_field, poseidon_over_pallas, poseidon_over_pallas>,
    placeholder_common_data_test_runner<pallas_base_field, keccak_256, keccak_256>,
    placeholder_common_data_test_runner<pallas_base_field, keccak_512, keccak_512>,

    /* Test case for different hashes of transcript and merkle tree */
    placeholder_common_data_test_runner<pallas_base_field, keccak_256, sha2_256>,

    /* Test other curves with keccak_256 */
    placeholder_common_data_test_runner<typename curves::bls12_381::scalar_field_type, keccak_256, keccak_256>,
    placeholder_common_data_test_runner<typename curves::alt_bn128_254::scalar_field_type, keccak_256, keccak_256>,
    placeholder_common_data_test_runner<typename curves::mnt4_298::scalar_field_type, keccak_256, keccak_256>,
    placeholder_common_data_test_runner<typename curves::mnt6_298::scalar_field_type, keccak_256, keccak_256>
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
