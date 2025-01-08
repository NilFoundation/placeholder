#define BOOST_TEST_MODULE crypto3_marshalling_plonk_constraint_system_test

#include <boost/test/unit_test.hpp>
#include <iostream>
#include <iomanip>
#include <random>
#include <regex>
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

#include <nil/crypto3/marshalling/math/types/term.hpp>
#include <nil/crypto3/marshalling/math/types/expression.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/constraint.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/gate.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/constraint_system.hpp>

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
struct plonk_constraint_system_test_runner {

    using field_type = FieldType;

    typedef placeholder_circuit_params<field_type> circuit_params;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

    constexpr static std::size_t m = 2;
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

    plonk_constraint_system_test_runner(const circuit_type &circuit_in) :
        system(circuit_in.gates, circuit_in.copy_constraints, circuit_in.lookup_gates, circuit_in.lookup_tables)
    { }

    bool run_test()
    {
        using Endianness = nil::crypto3::marshalling::option::big_endian;
        using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;
        using value_marshalling_type = nil::crypto3::marshalling::types::plonk_constraint_system<TTypeBase, constraint_system>;

        auto filled_val = nil::crypto3::marshalling::types::fill_plonk_constraint_system<Endianness, constraint_system>(system);
        auto _val = types::make_plonk_constraint_system<Endianness, constraint_system>(filled_val);
        BOOST_CHECK(system == _val);

        std::vector<std::uint8_t> cv;
        cv.resize(filled_val.length(), 0x00);

        auto write_iter = cv.begin();
        nil::crypto3::marshalling::status_type status = filled_val.write(write_iter, cv.size());
        value_marshalling_type test_val_read;
        auto read_iter = cv.begin();
        status = test_val_read.read(read_iter, cv.size());
        BOOST_CHECK(status == nil::crypto3::marshalling::status_type::success);
        auto constructed_val_read = types::make_plonk_constraint_system<Endianness, constraint_system>(test_val_read);

        BOOST_CHECK(system == constructed_val_read);

        return true;
    }

    constraint_system system;
};


BOOST_AUTO_TEST_SUITE(plonk_constraint_system)
using pallas_base_field = typename curves::pallas::base_field_type;
using keccak_256 = hashes::keccak_1600<256>;
using keccak_512 = hashes::keccak_1600<512>;
using sha2_256 = hashes::sha2<256>;
using poseidon_over_pallas = hashes::poseidon<nil::crypto3::hashes::detail::pasta_poseidon_policy<pallas_base_field>>;

using TestRunners = boost::mpl::list<
    /* Test pallas with different hashes */
    plonk_constraint_system_test_runner<pallas_base_field, poseidon_over_pallas, poseidon_over_pallas>,
    plonk_constraint_system_test_runner<pallas_base_field, keccak_256, keccak_256>,
    plonk_constraint_system_test_runner<pallas_base_field, keccak_512, keccak_512>,

    /* Test case for different hashes of transcript and merkle tree */
    plonk_constraint_system_test_runner<pallas_base_field, keccak_256, sha2_256>,

    /* Test other curves with keccak_256 */
    plonk_constraint_system_test_runner<typename curves::bls12_381::scalar_field_type, keccak_256, keccak_256>,
    plonk_constraint_system_test_runner<typename curves::alt_bn128_254::scalar_field_type, keccak_256, keccak_256>,
    plonk_constraint_system_test_runner<typename curves::mnt4_298::scalar_field_type, keccak_256, keccak_256>,
    plonk_constraint_system_test_runner<typename curves::mnt6_298::scalar_field_type, keccak_256, keccak_256>
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

