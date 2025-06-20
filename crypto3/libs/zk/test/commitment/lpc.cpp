//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
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

#define BOOST_TEST_MODULE parallel_lpc_test

#include <string>
#include <random>
#include <regex>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>

#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>
#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/type_traits.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

using namespace nil::crypto3;

using dist_type = std::uniform_int_distribution<int>;

template<typename FieldType>
inline math::polynomial_dfs<typename FieldType::value_type> generate_random_polynomial_dfs(
        std::size_t degree,
        nil::crypto3::random::algebraic_engine<FieldType> &rnd
) {
    math::polynomial_dfs<typename FieldType::value_type> result(degree, degree + 1);
    std::generate(std::begin(result), std::end(result), [&rnd]() { return rnd(); });
    return result;
}

template<typename FieldType>
inline std::vector<math::polynomial_dfs<typename FieldType::value_type>> generate_random_polynomial_dfs_batch(
        std::size_t batch_size,
        std::size_t degree,
        nil::crypto3::random::algebraic_engine<FieldType> &rnd
) {
    std::vector<math::polynomial_dfs<typename FieldType::value_type>> result;

    for (std::size_t i = 0; i < batch_size; i++) {
        result.push_back(generate_random_polynomial_dfs(degree, rnd));
    }
    return result;
}

std::size_t test_global_seed = 0;
boost::random::mt11213b test_global_rnd_engine;
template<typename FieldType>
nil::crypto3::random::algebraic_engine<FieldType> test_global_alg_rnd_engine;

struct test_fixture {
    // Enumerate all fields used in tests;
    using field1_type = algebra::curves::bls12<381>::scalar_field_type;

    test_fixture() {
        test_global_seed = 0;

        for (std::size_t i = 0; i < std::size_t(boost::unit_test::framework::master_test_suite().argc - 1); i++) {
            if (std::string(boost::unit_test::framework::master_test_suite().argv[i]) == "--seed") {
                if (std::string(boost::unit_test::framework::master_test_suite().argv[i + 1]) == "random") {
                    std::random_device rd;
                    test_global_seed = rd();
                    std::cout << "Random seed=" << test_global_seed << std::endl;
                    break;
                }
                if (std::regex_match(boost::unit_test::framework::master_test_suite().argv[i + 1],
                                     std::regex(("((\\+|-)?[[:digit:]]+)(\\.(([[:digit:]]+)?))?")))) {
                    test_global_seed = atoi(boost::unit_test::framework::master_test_suite().argv[i + 1]);
                    break;
                }
            }
        }

        BOOST_TEST_MESSAGE("test_global_seed = " << test_global_seed);
        test_global_rnd_engine = boost::random::mt11213b(test_global_seed);
        test_global_alg_rnd_engine<field1_type> = nil::crypto3::random::algebraic_engine<field1_type>(test_global_seed);
    }

    ~test_fixture() {}
};

BOOST_AUTO_TEST_SUITE(lpc_math_polynomial_suite);

    BOOST_FIXTURE_TEST_CASE(lpc_basic_test, test_fixture) {
        // Setup types.
        typedef algebra::curves::bls12<381> curve_type;
        typedef typename curve_type::scalar_field_type FieldType;
        typedef typename FieldType::value_type value_type;
        typedef hashes::sha2<256> merkle_hash_type;
        typedef hashes::sha2<256> transcript_hash_type;
        typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;
        typedef typename math::polynomial_dfs<value_type> poly_type;

        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t k = 1;

        constexpr static const std::size_t d = 15;
        constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;

        constexpr static const std::size_t m = 2;

        typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m> fri_type;

        typedef zk::commitments::
        list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, m>
                lpc_params_type;
        typedef zk::commitments::list_polynomial_commitment<FieldType, lpc_params_type> lpc_type;

        static_assert(zk::is_commitment<fri_type>::value);
        static_assert(zk::is_commitment<lpc_type>::value);
        static_assert(!zk::is_commitment<merkle_hash_type>::value);
        static_assert(!zk::is_commitment<merkle_tree_type>::value);
        static_assert(!zk::is_commitment<std::size_t>::value);

        constexpr static const std::size_t d_extended = d;
        std::size_t extended_log = boost::static_log2<d_extended>::value;
        std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
                math::calculate_domain_set<FieldType>(extended_log, r);


        // Setup params
        std::size_t degree_log = std::ceil(std::log2(d - 1));
        typename fri_type::params_type fri_params(
                1, /*max_step*/
                degree_log,
                lambda,
                2, //expand_factor
                true, // use_grinding
                12 // grinding_parameter
                );

        using lpc_scheme_type = nil::crypto3::zk::commitments::lpc_commitment_scheme<lpc_type, poly_type>;
        lpc_scheme_type lpc_scheme_prover(fri_params);
        lpc_scheme_type lpc_scheme_verifier(fri_params);

        // Generate polynomials
        lpc_scheme_prover.append_to_batch(0, poly_type(15, {1u, 13u, 4u, 1u, 5u, 6u, 7u, 2u, 8u, 7u, 5u, 6u, 1u, 2u, 1u, 1u}));
        lpc_scheme_prover.append_to_batch(1, poly_type(1, {0u, 1u}));
        lpc_scheme_prover.append_to_batch(1, poly_type(2, {0u, 1u, 2u, 3u}));
        lpc_scheme_prover.append_to_batch(1, poly_type(2, {0u, 1u, 3u, 4u}));
        lpc_scheme_prover.append_to_batch(2, poly_type(0, std::initializer_list<value_type>{0u}));
        lpc_scheme_prover.append_to_batch(3, generate_random_polynomial_dfs(3, test_global_alg_rnd_engine<FieldType>));
        lpc_scheme_prover.append_to_batch(3, generate_random_polynomial_dfs(7, test_global_alg_rnd_engine<FieldType>));

        // Commit
        std::map<std::size_t, typename lpc_type::commitment_type> commitments;
        commitments[0] = lpc_scheme_prover.commit(0);
        commitments[1] = lpc_scheme_prover.commit(1);
        commitments[2] = lpc_scheme_prover.commit(2);
        commitments[3] = lpc_scheme_prover.commit(3);

        // Generate evaluation points. Choose poin1ts outside the domain
        auto point = algebra::fields::arithmetic_params<FieldType>::multiplicative_generator;
        lpc_scheme_prover.append_eval_point(0, point);
        lpc_scheme_prover.append_eval_point(1, point);
        lpc_scheme_prover.append_eval_point(2, point);
        lpc_scheme_prover.append_eval_point(3, point);

        std::array<std::uint8_t, 96> x_data{};

        // Prove
        zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);
        auto proof = lpc_scheme_prover.proof_eval(transcript);

        // Verify
        zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);
        lpc_scheme_verifier.set_batch_size(0, proof.z.get_batch_size(0));
        lpc_scheme_verifier.set_batch_size(1, proof.z.get_batch_size(1));
        lpc_scheme_verifier.set_batch_size(2, proof.z.get_batch_size(2));
        lpc_scheme_verifier.set_batch_size(3, proof.z.get_batch_size(3));

        lpc_scheme_verifier.append_eval_point(0, point);
        lpc_scheme_verifier.append_eval_point(1, point);
        lpc_scheme_verifier.append_eval_point(2, point);
        lpc_scheme_verifier.append_eval_point(3, point);

        BOOST_CHECK(lpc_scheme_verifier.verify_eval(proof, commitments, transcript_verifier));

        // Check transcript state
        typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
        typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();
        BOOST_CHECK(verifier_next_challenge == prover_next_challenge);
    }

    BOOST_FIXTURE_TEST_CASE(lpc_basic_skipping_layers_test, test_fixture) {
        // Setup types
        typedef algebra::curves::bls12<381> curve_type;
        typedef typename curve_type::scalar_field_type FieldType;
        typedef typename FieldType::value_type value_type;

        typedef hashes::sha2<256> merkle_hash_type;
        typedef hashes::sha2<256> transcript_hash_type;

        typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t k = 1;

        constexpr static const std::size_t d = 2047;

        constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
        constexpr static const std::size_t m = 2;

        typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m> fri_type;

        typedef zk::commitments::
        list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, m>
                lpc_params_type;
        typedef zk::commitments::list_polynomial_commitment<FieldType, lpc_params_type> lpc_type;

        static_assert(zk::is_commitment<fri_type>::value);
        static_assert(zk::is_commitment<lpc_type>::value);
        static_assert(!zk::is_commitment<merkle_hash_type>::value);
        static_assert(!zk::is_commitment<merkle_tree_type>::value);
        static_assert(!zk::is_commitment<std::size_t>::value);

        constexpr static const std::size_t d_extended = d;
        std::size_t extended_log = boost::static_log2<d_extended>::value;
        std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
                math::calculate_domain_set<FieldType>(extended_log, r);

        typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m> fri_type;

        // Setup params
        std::size_t degree_log = std::ceil(std::log2(d - 1));
        typename fri_type::params_type fri_params(
                5, /*max_step*/
                degree_log,
                lambda,
                2 //expand_factor
                );

        using lpc_scheme_type = nil::crypto3::zk::commitments::lpc_commitment_scheme<lpc_type, math::polynomial_dfs<value_type>>;
        lpc_scheme_type lpc_scheme_prover(fri_params);
        lpc_scheme_type lpc_scheme_verifier(fri_params);

        // Generate polynomials
        lpc_scheme_prover.append_many_to_batch(0, generate_random_polynomial_dfs_batch<FieldType>(
                dist_type(1, 10)(test_global_rnd_engine), d, test_global_alg_rnd_engine<FieldType>));
        lpc_scheme_prover.append_many_to_batch(1, generate_random_polynomial_dfs_batch<FieldType>(
                dist_type(1, 10)(test_global_rnd_engine), d, test_global_alg_rnd_engine<FieldType>));
        lpc_scheme_prover.append_many_to_batch(2, generate_random_polynomial_dfs_batch<FieldType>(
                dist_type(1, 10)(test_global_rnd_engine), d, test_global_alg_rnd_engine<FieldType>));
        lpc_scheme_prover.append_many_to_batch(3, generate_random_polynomial_dfs_batch<FieldType>(
                dist_type(1, 10)(test_global_rnd_engine), d, test_global_alg_rnd_engine<FieldType>));

        std::map<std::size_t, typename lpc_type::commitment_type> commitments;
        commitments[0] = lpc_scheme_prover.commit(0);
        commitments[1] = lpc_scheme_prover.commit(1);
        commitments[2] = lpc_scheme_prover.commit(2);
        commitments[3] = lpc_scheme_prover.commit(3);

        // Generate evaluation points. Choose poin1ts outside the domain
        auto point = algebra::fields::arithmetic_params<FieldType>::multiplicative_generator;
        lpc_scheme_prover.append_eval_point(0, point);
        lpc_scheme_prover.append_eval_point(1, point);
        lpc_scheme_prover.append_eval_point(2, point);
        lpc_scheme_prover.append_eval_point(3, point);

        std::array<std::uint8_t, 96> x_data{};

        // Prove
        zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);
        auto proof = lpc_scheme_prover.proof_eval(transcript);

        // Verify
        zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);
        lpc_scheme_verifier.set_batch_size(0, proof.z.get_batch_size(0));
        lpc_scheme_verifier.set_batch_size(1, proof.z.get_batch_size(1));
        lpc_scheme_verifier.set_batch_size(2, proof.z.get_batch_size(2));
        lpc_scheme_verifier.set_batch_size(3, proof.z.get_batch_size(3));

        lpc_scheme_verifier.append_eval_point(0, point);
        lpc_scheme_verifier.append_eval_point(1, point);
        lpc_scheme_verifier.append_eval_point(2, point);
        lpc_scheme_verifier.append_eval_point(3, point);
        BOOST_CHECK(lpc_scheme_verifier.verify_eval(proof, commitments, transcript_verifier));

        // Check transcript state
        typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
        typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();
        BOOST_CHECK(verifier_next_challenge == prover_next_challenge);
    }

    BOOST_FIXTURE_TEST_CASE(lpc_dfs_basic_test, test_fixture) {
        // Setup types
        typedef algebra::curves::bls12<381> curve_type;
        typedef typename curve_type::scalar_field_type FieldType;

        typedef hashes::sha2<256> merkle_hash_type;
        typedef hashes::sha2<256> transcript_hash_type;

        typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t k = 1;

        constexpr static const std::size_t d = 15;

        constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
        constexpr static const std::size_t m = 2;

        typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m> fri_type;

        typedef zk::commitments::
        list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, m>
                lpc_params_type;
        typedef zk::commitments::list_polynomial_commitment<FieldType, lpc_params_type> lpc_type;

        static_assert(zk::is_commitment<fri_type>::value);
        static_assert(zk::is_commitment<lpc_type>::value);
        static_assert(!zk::is_commitment<merkle_hash_type>::value);
        static_assert(!zk::is_commitment<merkle_tree_type>::value);
        static_assert(!zk::is_commitment<std::size_t>::value);

        // Setup params
        std::size_t degree_log = std::ceil(std::log2(d - 1));
        typename fri_type::params_type fri_params(
                1, /*max_step*/
                degree_log,
                lambda,
                2, //expand_factor
                true // use_grinding
                );

        using lpc_scheme_type = nil::crypto3::zk::commitments::lpc_commitment_scheme<lpc_type>;
        lpc_scheme_type lpc_scheme_prover(fri_params);
        lpc_scheme_type lpc_scheme_verifier(fri_params);

        // Generate polynomials
        std::array<std::vector<math::polynomial_dfs<typename FieldType::value_type>>, 4> f;
        lpc_scheme_prover.append_many_to_batch(0, generate_random_polynomial_dfs_batch<FieldType>(
                dist_type(1, 10)(test_global_rnd_engine), d, test_global_alg_rnd_engine<FieldType>));
        lpc_scheme_prover.append_many_to_batch(1, generate_random_polynomial_dfs_batch<FieldType>(
                dist_type(1, 10)(test_global_rnd_engine), d, test_global_alg_rnd_engine<FieldType>));
        lpc_scheme_prover.append_many_to_batch(2, generate_random_polynomial_dfs_batch<FieldType>(
                dist_type(1, 10)(test_global_rnd_engine), d, test_global_alg_rnd_engine<FieldType>));
        lpc_scheme_prover.append_many_to_batch(3, generate_random_polynomial_dfs_batch<FieldType>(
                dist_type(1, 10)(test_global_rnd_engine), d, test_global_alg_rnd_engine<FieldType>));

        std::map<std::size_t, typename lpc_type::commitment_type> commitments;
        commitments[0] = lpc_scheme_prover.commit(0);
        commitments[1] = lpc_scheme_prover.commit(1);
        commitments[2] = lpc_scheme_prover.commit(2);
        commitments[3] = lpc_scheme_prover.commit(3);

        // Generate evaluation points. Choose poin1ts outside the domain
        auto point = algebra::fields::arithmetic_params<FieldType>::multiplicative_generator;
        lpc_scheme_prover.append_eval_point(0, point);
        lpc_scheme_prover.append_eval_point(1, point);
        lpc_scheme_prover.append_eval_point(2, point);
        lpc_scheme_prover.append_eval_point(3, point);

        std::array<std::uint8_t, 96> x_data{};

        // Prove
        zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);
        auto proof = lpc_scheme_prover.proof_eval(transcript);

        // Verify
        zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);

        lpc_scheme_verifier.set_batch_size(0, proof.z.get_batch_size(0));
        lpc_scheme_verifier.set_batch_size(1, proof.z.get_batch_size(1));
        lpc_scheme_verifier.set_batch_size(2, proof.z.get_batch_size(2));
        lpc_scheme_verifier.set_batch_size(3, proof.z.get_batch_size(3));

        lpc_scheme_verifier.append_eval_point(0, point);
        lpc_scheme_verifier.append_eval_point(1, point);
        lpc_scheme_verifier.append_eval_point(2, point);
        lpc_scheme_verifier.append_eval_point(3, point);
        BOOST_CHECK(lpc_scheme_verifier.verify_eval(proof, commitments, transcript_verifier));

        // Check transcript state
        typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
        typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();
        BOOST_CHECK(verifier_next_challenge == prover_next_challenge);
    }

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(lpc_params_test_suite)

    BOOST_FIXTURE_TEST_CASE(lpc_batches_num_3_test, test_fixture) {
        // Setup types.
        typedef algebra::curves::bls12<381> curve_type;
        typedef typename curve_type::scalar_field_type FieldType;
        typedef typename FieldType::value_type value_type;
        typedef hashes::sha2<256> merkle_hash_type;
        typedef hashes::sha2<256> transcript_hash_type;
        typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;
        typedef typename math::polynomial_dfs<value_type> poly_type;

        constexpr static const std::size_t lambda = 40;
        constexpr static const std::size_t k = 1;

        constexpr static const std::size_t d = 15;

        constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
        constexpr static const std::size_t m = 2;

        typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m> fri_type;

        typedef zk::commitments::
        list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, m>
                lpc_params_type;
        typedef zk::commitments::list_polynomial_commitment<FieldType, lpc_params_type> lpc_type;

        static_assert(zk::is_commitment<fri_type>::value);
        static_assert(zk::is_commitment<lpc_type>::value);
        static_assert(!zk::is_commitment<merkle_hash_type>::value);
        static_assert(!zk::is_commitment<merkle_tree_type>::value);
        static_assert(!zk::is_commitment<std::size_t>::value);

        // Setup params
        std::size_t degree_log = std::ceil(std::log2(d - 1));
        typename fri_type::params_type fri_params(
                1, /*max_step*/
                degree_log,
                lambda,
                2, // expand_factor
                true, // use_grinding
                8
                );

        using lpc_scheme_type = nil::crypto3::zk::commitments::lpc_commitment_scheme<lpc_type, poly_type>;
        lpc_scheme_type lpc_scheme_prover(fri_params);
        lpc_scheme_type lpc_scheme_verifier(fri_params);

        // Generate polynomials
        lpc_scheme_prover.append_to_batch(0, poly_type(15, {1u, 13u, 4u, 1u, 5u, 6u, 7u, 2u, 8u, 7u, 5u, 6u, 1u, 2u, 1u, 1u}));
        lpc_scheme_prover.append_to_batch(2, poly_type(1, {0u, 1u}));
        lpc_scheme_prover.append_to_batch(2, poly_type(2, {0u, 1u, 2u, 3u}));
        lpc_scheme_prover.append_to_batch(2, poly_type(2, {0u, 1u, 3u, 4u}));
        lpc_scheme_prover.append_to_batch(3, poly_type(0, std::initializer_list<value_type>{0u}));
 
        // Commit
        std::map<std::size_t, typename lpc_type::commitment_type> commitments;
        commitments[0] = lpc_scheme_prover.commit(0);
        commitments[2] = lpc_scheme_prover.commit(2);
        commitments[3] = lpc_scheme_prover.commit(3);

        // Generate evaluation points. Generate points outside of the basic domain
        // Generate evaluation points. Choose poin1ts outside the domain
        auto point = algebra::fields::arithmetic_params<FieldType>::multiplicative_generator;
        lpc_scheme_prover.append_eval_point(0, point);
        lpc_scheme_prover.append_eval_point(2, point);
        lpc_scheme_prover.append_eval_point(3, point);

        std::array<std::uint8_t, 96> x_data{};

        // Prove
        zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);
        auto proof = lpc_scheme_prover.proof_eval(transcript);

        // Verify
        zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);

        lpc_scheme_verifier.set_batch_size(0, proof.z.get_batch_size(0));
        lpc_scheme_verifier.set_batch_size(2, proof.z.get_batch_size(2));
        lpc_scheme_verifier.set_batch_size(3, proof.z.get_batch_size(3));

        lpc_scheme_verifier.append_eval_point(0, point);
        lpc_scheme_verifier.append_eval_point(2, point);
        lpc_scheme_verifier.append_eval_point(3, point);
        BOOST_CHECK(lpc_scheme_verifier.verify_eval(proof, commitments, transcript_verifier));

        // Check transcript state
        typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
        typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();
        BOOST_CHECK(verifier_next_challenge == prover_next_challenge);
    }

    BOOST_FIXTURE_TEST_CASE(lpc_different_hash_types_test, test_fixture) {
        // Setup types.
        typedef algebra::curves::bls12<381> curve_type;
        typedef typename curve_type::scalar_field_type FieldType;
        typedef typename FieldType::value_type value_type;
        typedef hashes::keccak_1600<256> merkle_hash_type;
        typedef hashes::sha2<256> transcript_hash_type;
        typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;
        typedef typename math::polynomial_dfs<value_type> poly_type;

        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t k = 1;

        constexpr static const std::size_t d = 15;
        constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;

        constexpr static const std::size_t m = 2;

        typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m> fri_type;

        typedef zk::commitments::
        list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, m>
                lpc_params_type;
        typedef zk::commitments::list_polynomial_commitment<FieldType, lpc_params_type> lpc_type;

        static_assert(zk::is_commitment<fri_type>::value);
        static_assert(zk::is_commitment<lpc_type>::value);
        static_assert(!zk::is_commitment<merkle_hash_type>::value);
        static_assert(!zk::is_commitment<merkle_tree_type>::value);
        static_assert(!zk::is_commitment<std::size_t>::value);

        constexpr static const std::size_t d_extended = d;
        std::size_t extended_log = boost::static_log2<d_extended>::value;
        std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
                math::calculate_domain_set<FieldType>(extended_log, r);

        // Setup params
        std::size_t degree_log = std::ceil(std::log2(d - 1));
        typename fri_type::params_type fri_params(
                1, /*max_step*/
                degree_log,
                lambda,
                2 //expand_factor
                );

        using lpc_scheme_type = nil::crypto3::zk::commitments::lpc_commitment_scheme<lpc_type, poly_type>;
        lpc_scheme_type lpc_scheme_prover(fri_params);
        lpc_scheme_type lpc_scheme_verifier(fri_params);

        // Generate polynomials
        lpc_scheme_prover.append_to_batch(0, poly_type(15, {1u, 13u, 4u, 1u, 5u, 6u, 7u, 2u, 8u, 7u, 5u, 6u, 1u, 2u, 1u, 1u}));
        lpc_scheme_prover.append_to_batch(2, poly_type(1, {0u, 1u}));
        lpc_scheme_prover.append_to_batch(2, poly_type(2, {0u, 1u, 2u, 3u}));
        lpc_scheme_prover.append_to_batch(2, poly_type(2, {0u, 1u, 3u, 4u}));
        lpc_scheme_prover.append_to_batch(3, poly_type(0, std::initializer_list<value_type>{0u}));
        lpc_scheme_prover.append_to_batch(3, generate_random_polynomial_dfs(3, test_global_alg_rnd_engine<FieldType>));
        lpc_scheme_prover.append_to_batch(3, generate_random_polynomial_dfs(7, test_global_alg_rnd_engine<FieldType>));

        // Commit
        std::map<std::size_t, typename lpc_type::commitment_type> commitments;
        commitments[0] = lpc_scheme_prover.commit(0);
        commitments[1] = lpc_scheme_prover.commit(1);
        commitments[2] = lpc_scheme_prover.commit(2);
        commitments[3] = lpc_scheme_prover.commit(3);

        // Generate evaluation points. Choose poin1ts outside the domain
        auto point = algebra::fields::arithmetic_params<FieldType>::multiplicative_generator;
        lpc_scheme_prover.append_eval_point(0, point);
        lpc_scheme_prover.append_eval_point(1, point);
        lpc_scheme_prover.append_eval_point(2, point);
        lpc_scheme_prover.append_eval_point(3, point);

        std::array<std::uint8_t, 96> x_data{};

        // Prove
        zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);
        auto proof = lpc_scheme_prover.proof_eval(transcript);

        // Verify
        zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);
        lpc_scheme_verifier.set_batch_size(0, proof.z.get_batch_size(0));
        lpc_scheme_verifier.set_batch_size(1, proof.z.get_batch_size(1));
        lpc_scheme_verifier.set_batch_size(2, proof.z.get_batch_size(2));
        lpc_scheme_verifier.set_batch_size(3, proof.z.get_batch_size(3));

        lpc_scheme_verifier.append_eval_point(0, point);
        lpc_scheme_verifier.append_eval_point(1, point);
        lpc_scheme_verifier.append_eval_point(2, point);
        lpc_scheme_verifier.append_eval_point(3, point);
        BOOST_CHECK(lpc_scheme_verifier.verify_eval(proof, commitments, transcript_verifier));

        // Check transcript state
        typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
        typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();
        BOOST_CHECK(verifier_next_challenge == prover_next_challenge);
    }

BOOST_AUTO_TEST_SUITE_END()
