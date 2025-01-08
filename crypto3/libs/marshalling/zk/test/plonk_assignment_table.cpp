#define BOOST_TEST_MODULE crypto3_marshalling_plonk_assignment_table_test

#include <boost/test/unit_test.hpp>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <filesystem>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt6.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/variable.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/assignment_table.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include <nil/crypto3/test_tools/random_test_initializer.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include "detail/circuits.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::marshalling;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::zk::snark;

template<typename FieldType,
        typename merkle_hash_type,
        typename transcript_hash_type>
struct plonk_assignment_table_test_runner {
    using field_type = FieldType;

    struct placeholder_test_params {
        constexpr static const std::size_t lambda = 40;
        constexpr static const std::size_t m = 2;
    };

    typedef placeholder_circuit_params<field_type> circuit_params;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

    using lpc_params_type = commitments::list_polynomial_commitment_params<
            merkle_hash_type,
            transcript_hash_type,
            placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, lpc_placeholder_params_type>;
    using circuit_type = circuit_description<field_type, placeholder_circuit_params<field_type>>;

    plonk_assignment_table_test_runner(const circuit_type &circuit_in) :
        circuit(circuit_in),
        desc(circuit_in.table.witnesses().size(),
                circuit_in.table.public_inputs().size(),
                circuit_in.table.constants().size(),
                circuit_in.table.selectors().size(),
                circuit_in.usable_rows,
                circuit_in.table_rows),
        constraint_system(circuit.gates, circuit.copy_constraints, circuit.lookup_gates, circuit.lookup_tables),
        assignments(circuit.table), table_rows_log(std::log2(circuit_in.table_rows)),
        fri_params(1, table_rows_log, placeholder_test_params::lambda, 4)
    { }

    template<typename Endianness>
    bool test_assignment_table_description()
    {
        plonk_table_description<field_type> const& val = desc;
        using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;
        using value_marshalling_type = nil::crypto3::marshalling::types::plonk_assignment_table_description<TTypeBase>;

        auto filled_val = types::fill_assignment_table_description<Endianness, FieldType>(val);
        auto table_desc = types::make_assignment_table_description<Endianness, FieldType>(filled_val);
        BOOST_CHECK(val == table_desc);

        std::vector<std::uint8_t> cv;
        cv.resize(filled_val.length(), 0x00);

        auto write_iter = cv.begin();
        nil::crypto3::marshalling::status_type status = filled_val.write(write_iter, cv.size());
        value_marshalling_type test_val_read;
        auto read_iter = cv.begin();
        status = test_val_read.read(read_iter, cv.size());
        BOOST_CHECK(status == nil::crypto3::marshalling::status_type::success);
        table_desc = types::make_assignment_table_description<Endianness, FieldType>(test_val_read);

        BOOST_CHECK(val == table_desc);

        return true;
    }

    template<typename Endianness>
    bool test_assignment_table()
    {
        using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;
        using plonk_table = plonk_assignment_table<field_type>;
        using value_marshalling_type = nil::crypto3::marshalling::types::plonk_assignment_table<TTypeBase, plonk_table>;

        std::size_t usable_rows = desc.usable_rows_amount;
        plonk_table const& val = assignments;

        auto filled_val = nil::crypto3::marshalling::types::fill_assignment_table<Endianness, plonk_table>(usable_rows, val);
        auto table_desc_pair = types::make_assignment_table<Endianness, plonk_table>(filled_val);
        BOOST_CHECK(val == table_desc_pair.second);
        BOOST_CHECK(usable_rows == table_desc_pair.first.usable_rows_amount);

        std::vector<std::uint8_t> cv;
        cv.resize(filled_val.length(), 0x00);

        auto write_iter = cv.begin();
        nil::crypto3::marshalling::status_type status = filled_val.write(write_iter, cv.size());
        value_marshalling_type test_val_read;
        auto read_iter = cv.begin();
        status = test_val_read.read(read_iter, cv.size());
        BOOST_CHECK(status == nil::crypto3::marshalling::status_type::success);
        table_desc_pair = types::make_assignment_table<Endianness, plonk_table>(test_val_read);

        BOOST_CHECK(val == table_desc_pair.second);
        BOOST_CHECK(usable_rows == table_desc_pair.first.usable_rows_amount);

        return true;
    }

    bool run_test()
    {
        using Endianness = nil::crypto3::marshalling::option::big_endian;
        BOOST_CHECK(test_assignment_table_description<Endianness>());
        BOOST_CHECK(test_assignment_table<Endianness>());
        return true;
    }

    circuit_type circuit;
    plonk_table_description<field_type> desc;
    typename policy_type::constraint_system_type constraint_system;
    typename policy_type::variable_assignment_type assignments;
    std::size_t table_rows_log;
    typename lpc_type::fri_type::params_type fri_params;
};

BOOST_AUTO_TEST_SUITE(marshalling_assignment_table)

using pallas_base_field = typename curves::pallas::base_field_type;
using keccak_256 = hashes::keccak_1600<256>;
using keccak_512 = hashes::keccak_1600<512>;
using sha2_256 = hashes::sha2<256>;
using poseidon_over_pallas = hashes::poseidon<nil::crypto3::hashes::detail::pasta_poseidon_policy<pallas_base_field>>;

using TestRunners = boost::mpl::list<
    /* Test pallas with different hashes */
    plonk_assignment_table_test_runner<pallas_base_field, poseidon_over_pallas, poseidon_over_pallas>,
    plonk_assignment_table_test_runner<pallas_base_field, keccak_256, keccak_256>,
    plonk_assignment_table_test_runner<pallas_base_field, keccak_512, keccak_512>,

    /* Test case for different hashes of transcript and merkle tree */
    plonk_assignment_table_test_runner<pallas_base_field, keccak_256, sha2_256>,

    /* Test other curves with keccak_256 */
    plonk_assignment_table_test_runner<typename curves::bls12_381::scalar_field_type, keccak_256, keccak_256>,
    plonk_assignment_table_test_runner<typename curves::alt_bn128_254::scalar_field_type, keccak_256, keccak_256>,
    plonk_assignment_table_test_runner<typename curves::mnt4_298::scalar_field_type, keccak_256, keccak_256>,
    plonk_assignment_table_test_runner<typename curves::mnt6_298::scalar_field_type, keccak_256, keccak_256>
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
