//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2024 Valeh Farzaliyev <estoniaa@nil.foundation>
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

#define BOOST_TEST_MODULE dfri_inuput_generator_test

#include <string>
#include <random>
#include <regex>
#include <iostream>
#include <fstream>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
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

#include <nil/crypto3/hash/poseidon.hpp>

using namespace nil::crypto3;

using dist_type = std::uniform_int_distribution<int>;

template<typename FieldType>
inline math::polynomial<typename FieldType::value_type>
    generate_random_polynomial(std::size_t degree, nil::crypto3::random::algebraic_engine<FieldType> &rnd) {
    math::polynomial<typename FieldType::value_type> result(degree);
    std::generate(std::begin(result), std::end(result), [&rnd]() { return rnd(); });
    return result;
}

template<typename FieldType>
inline math::polynomial_dfs<typename FieldType::value_type>
    generate_random_polynomial_dfs(std::size_t degree, nil::crypto3::random::algebraic_engine<FieldType> &rnd) {
    math::polynomial<typename FieldType::value_type> data = generate_random_polynomial(degree, rnd);
    math::polynomial_dfs<typename FieldType::value_type> result;
    result.from_coefficients(data);
    return result;
}

template<typename FieldType>
inline std::vector<math::polynomial<typename FieldType::value_type>>
    generate_random_polynomial_batch(std::size_t batch_size,
                                     std::size_t degree,
                                     nil::crypto3::random::algebraic_engine<FieldType> &rnd) {
    std::vector<math::polynomial<typename FieldType::value_type>> result;

    for (std::size_t i = 0; i < batch_size; i++) {
        result.push_back(generate_random_polynomial(degree, rnd));
    }
    return result;
}

template<typename FieldType>
inline std::vector<math::polynomial_dfs<typename FieldType::value_type>>
    generate_random_polynomial_dfs_batch(std::size_t batch_size,
                                         std::size_t degree,
                                         nil::crypto3::random::algebraic_engine<FieldType> &rnd) {
    auto data = generate_random_polynomial_batch(batch_size, degree, rnd);
    std::vector<math::polynomial_dfs<typename FieldType::value_type>> result;

    for (std::size_t i = 0; i < data.size(); i++) {
        math::polynomial_dfs<typename FieldType::value_type> dfs;
        dfs.from_coefficients(data[i]);
        result.push_back(dfs);
    }
    return result;
}

std::size_t test_global_seed = 0;
boost::random::mt11213b test_global_rnd_engine;
template<typename FieldType>
nil::crypto3::random::algebraic_engine<FieldType> test_global_alg_rnd_engine;
bool print_enabled = false;

struct test_fixture {
    // Enumerate all fields used in tests;
    using field1_type = algebra::curves::pallas::base_field_type;

    test_fixture() {
        test_global_seed = 0;
        print_enabled = false;
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
            if (std::string(boost::unit_test::framework::master_test_suite().argv[i]) == "--print") {
                print_enabled = true;
            }
        }
        for (std::size_t i = 0; i < std::size_t(boost::unit_test::framework::master_test_suite().argc); i++) {
            if (std::string(boost::unit_test::framework::master_test_suite().argv[i]) == "--print") {
                print_enabled = true;
            }
        }

        BOOST_TEST_MESSAGE("test_global_seed = " << test_global_seed);
        test_global_rnd_engine = boost::random::mt11213b(test_global_seed);
        test_global_alg_rnd_engine<field1_type> = nil::crypto3::random::algebraic_engine<field1_type>(test_global_seed);
    }

    ~test_fixture() {
    }
};

template<typename ProofType, typename ParamsType, typename ValueType>
void export_to_json(ProofType const &proof, ParamsType const &fri_params, std::map<std::pair<std::size_t, std::size_t>, std::pair<std::size_t, std::size_t>> &eval_map, std::vector<ValueType> &points, std::string filename) {

    std::ofstream out(filename);
        
    bool first = true;
    out << "{\"params\": {\"lambda\" : " << fri_params.lambda << ", \"expand_factor\": " << fri_params.expand_factor << ", \"batches_amount\": " <<  proof.z.get_batches().size();
    out << ", \"batch_size\": [";
    
    for(std::size_t i=0; i< proof.z.get_batches().size(); i++){
        if (!first)
            out << ",";
        else
            first = false;
        out << proof.z.get_batch_size(i);
    }
    out << "], \"evaluation_map\": [";
    first = true;
    for(auto &[k, v] : eval_map){
        if (!first)
            out << ",";
        else
            first = false;
        out << "[[" << std::get<0>(k) << ", " << std::get<1>(k) << "],[" << std::get<0>(v) << ", " << std::get<1>(v)<< "]]";
    }

    out << "]},\"evaluation_points\": [";
    first = true;
    for(auto &p : points){
        if (!first)
            out << ",";
        else
            first = false;
        out << p;
    }
    out << "], \"lpc_proof\" :{\"evaluations\": [";
    first = true;
    for (std::size_t i : proof.z.get_batches()) {
        if (!first)
            out << ",";
        else
            first = false;
        out << "{\"batch_id\":" << i << ", \"batch\": [";
        first = true;
        for (std::size_t j = 0; j < proof.z.get_batch_size(i); j++) {
            if (!first)
                out << ",";
            out << "{\"polynomial_index\":" << j << ", \"evaluation\":[";
            first = true;
            for (auto b : proof.z.get(i, j)) {
                if (!first)
                    out << ",";
                else
                    first = false;
                out << b << " ";
            }
            out << "]}";
            first = false;
        }
        first = false;
        out << "]}";
    }
    first = true;
    out << "], \"fri_proof\": { \"fri_roots\": [";
    for (auto &c : proof.fri_proof.fri_roots) {
        if (!first)
            out << ",";
        else
            first = false;
        out << c;
    }
    out << "],\"query_proofs\": [" << std::endl;
    first = true;
    for (auto &q : proof.fri_proof.query_proofs) {
        // initial round proof
        if (!first)
            out << ",";
        else
            first = false;
        out << "{\"initial_round_proof\": [";
        first = true;
        for (auto [k, init_proof] : q.initial_proof) {
            if (!first) out << ",";
            out << "{\"batch_id\":" << k << ", \"values\": [";
            first = true;
            for (auto &y : init_proof.values) {
                if (!first)
                    out << ",";
                else
                    first = false;
                out << "[" << y[0][0] << "," << y[0][1] << "]";
            }
            out << "],\"p\": {\"leaf_index\": " << init_proof.p.leaf_index() << ", \"root\": " << init_proof.p.root() << ",\"path\": [";
            first = true;
            for (auto &path : init_proof.p.path()) {
                if (!first)
                    out << ",";
                else
                    first = false;
                out << "{\"position\":" << path[0].position() << ", \"hash\" :" << path[0].hash() << "}";
            }
            out << "]}}";
            first = false;
        }
        // round proofs
        out << "], \"round_proofs\": [" << std::endl;
        first = true;
        for (auto &r : q.round_proofs) {
            if (!first)
                out << ",";
            out << "{\"y\": [" << r.y[0][0] << ", " << r.y[0][1] << "]," << std::endl;
            out << "\"p\": {\"leaf_index\": " << r.p.leaf_index() << ", \"root\": " << r.p.root() << ",\"path\": [";
            first = true;
            for (auto &path : r.p.path()) {
                if (!first)
                    out << ",";
                else
                    first = false;
                out << "{\"position\":" << path[0].position() << ", \"hash\" :" << path[0].hash() << "}";
            }
            out << "]}}";
            first = false;
        }
        out << "]}" << std::endl;
        first = false;
    }
    out << "],\"final_polynomial\": [";
    first = true;
    for (auto &coeff : proof.fri_proof.final_polynomial) {
        if (!first)
            out << ",";
        else
            first = false;
        out << coeff;
    }
    out << "]}}}" << std::endl;
    out.close();
}

BOOST_AUTO_TEST_SUITE(lpc_math_polynomial_suite);
BOOST_FIXTURE_TEST_CASE(lpc_basic_test, test_fixture) {
    // Setup types.
    typedef algebra::curves::pallas curve_type;
    typedef typename curve_type::base_field_type FieldType;
    typedef typename FieldType::value_type value_type;
    typedef hashes::poseidon<nil::crypto3::hashes::detail::pasta_poseidon_policy<FieldType>> merkle_hash_type;
    typedef hashes::poseidon<nil::crypto3::hashes::detail::pasta_poseidon_policy<FieldType>> transcript_hash_type;
    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;
    typedef typename math::polynomial_dfs<typename FieldType::value_type> poly_type;

    constexpr static const std::size_t lambda = 10;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d = 15;
    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;

    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m> fri_type;

    typedef zk::commitments::list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, m>
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
    typename fri_type::params_type fri_params(1, /*max_step*/
                                              degree_log,
                                              lambda,
                                              2,       // expand_factor
                                              true,    // use_grinding
                                              12       // grinding_parameter
    );

    using lpc_scheme_type = nil::crypto3::zk::commitments::lpc_commitment_scheme<
        lpc_type, poly_type>;

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
    std::vector<value_type> points;
    points.push_back(value_type(point));
    lpc_scheme_prover.append_eval_point(0, point);
    lpc_scheme_prover.append_eval_point(1, point);
    lpc_scheme_prover.append_eval_point(2, point);
    lpc_scheme_prover.append_eval_point(3, point);


    // auto native_eval_map = lpc_scheme_prover.build_eval_map();
    
    // for(std::size_t i = 0; i< native_eval_map.size(); i++){
    //     auto eval_map_i = native_eval_map.at(i);
    //     for()
    // }
    
    std::map<std::pair<std::size_t, std::size_t>, std::pair<std::size_t, std::size_t>> eval_map;
    eval_map.insert({std::make_pair(0, 0),std::make_pair(0, 0)});
    eval_map.insert({std::make_pair(1, 1),std::make_pair(0, 0)});
    eval_map.insert({std::make_pair(1, 2),std::make_pair(1, 0)});
    eval_map.insert({std::make_pair(1, 3),std::make_pair(2, 0)});
    eval_map.insert({std::make_pair(2, 4),std::make_pair(0, 0)});
    eval_map.insert({std::make_pair(3, 5),std::make_pair(0, 0)});
    eval_map.insert({std::make_pair(3, 6),std::make_pair(1, 0)});


    std::array<std::uint8_t, 96> x_data {};

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
    
    if(print_enabled) export_to_json(proof, fri_params, eval_map, points, "test1.json");
}

    // BOOST_FIXTURE_TEST_CASE(lpc_basic_skipping_layers_test, test_fixture) {
    //     // Setup types
    //     typedef algebra::curves::pallas curve_type;
    //     typedef typename curve_type::base_field_type FieldType;
    //     typedef typename FieldType::value_type value_type;
    //     typedef hashes::poseidon<nil::crypto3::hashes::detail::pasta_poseidon_policy<FieldType>> merkle_hash_type;
    //     typedef hashes::poseidon<nil::crypto3::hashes::detail::pasta_poseidon_policy<FieldType>> transcript_hash_type;

    //     typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    //     constexpr static const std::size_t lambda = 10;
    //     constexpr static const std::size_t k = 1;

    //     constexpr static const std::size_t d = 2047;

    //     constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    //     constexpr static const std::size_t m = 2;

    //     typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m> fri_type;

    //     typedef zk::commitments::
    //     list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, m>
    //             lpc_params_type;
    //     typedef zk::commitments::list_polynomial_commitment<FieldType, lpc_params_type> lpc_type;

    //     static_assert(zk::is_commitment<fri_type>::value);
    //     static_assert(zk::is_commitment<lpc_type>::value);
    //     static_assert(!zk::is_commitment<merkle_hash_type>::value);
    //     static_assert(!zk::is_commitment<merkle_tree_type>::value);
    //     static_assert(!zk::is_commitment<std::size_t>::value);

    //     constexpr static const std::size_t d_extended = d;
    //     std::size_t extended_log = boost::static_log2<d_extended>::value;
    //     std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
    //             math::calculate_domain_set<FieldType>(extended_log, r);

    //     typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m> fri_type;

    //     // Setup params
    //     std::size_t degree_log = std::ceil(std::log2(d - 1));
    //     typename fri_type::params_type fri_params(
    //             5, /*max_step*/
    //             degree_log,
    //             lambda,
    //             2 //expand_factor
    //             );

    //     using lpc_scheme_type = nil::crypto3::zk::commitments::lpc_commitment_scheme<lpc_type,
    //     math::polynomial<typename FieldType::value_type>>; lpc_scheme_type lpc_scheme_prover(fri_params);
    //     lpc_scheme_type lpc_scheme_verifier(fri_params);

    //     // Generate polynomials
    //     lpc_scheme_prover.append_many_to_batch(0, generate_random_polynomial_batch<FieldType>(
    //             dist_type(1, 10)(test_global_rnd_engine), d, test_global_alg_rnd_engine<FieldType>));
    //     lpc_scheme_prover.append_many_to_batch(1, generate_random_polynomial_batch<FieldType>(
    //             dist_type(1, 10)(test_global_rnd_engine), d, test_global_alg_rnd_engine<FieldType>));
    //     lpc_scheme_prover.append_many_to_batch(2, generate_random_polynomial_batch<FieldType>(
    //             dist_type(1, 10)(test_global_rnd_engine), d, test_global_alg_rnd_engine<FieldType>));
    //     lpc_scheme_prover.append_many_to_batch(3, generate_random_polynomial_batch<FieldType>(
    //             dist_type(1, 10)(test_global_rnd_engine), d, test_global_alg_rnd_engine<FieldType>));

    //     std::map<std::size_t, typename lpc_type::commitment_type> commitments;
    //     commitments[0] = lpc_scheme_prover.commit(0);
    //     commitments[1] = lpc_scheme_prover.commit(1);
    //     commitments[2] = lpc_scheme_prover.commit(2);
    //     commitments[3] = lpc_scheme_prover.commit(3);

    //     // Generate evaluation points. Choose poin1ts outside the domain
    //     auto point = algebra::fields::arithmetic_params<FieldType>::multiplicative_generator;
    //     lpc_scheme_prover.append_eval_point(0, point);
    //     lpc_scheme_prover.append_eval_point(1, point);
    //     lpc_scheme_prover.append_eval_point(2, point);
    //     lpc_scheme_prover.append_eval_point(3, point);

    //     auto native_eval_map = lpc_scheme_prover.build_eval_map();
    //     for(std::size_t i=0; i < 4; i++){

    //     }
    //     eval_map.insert({std::make_pair(0, 0),std::make_pair(0, 0)});

    //     std::array<std::uint8_t, 96> x_data{};

    //     // Prove
    //     zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);
    //     auto proof = lpc_scheme_prover.proof_eval(transcript);

    //     // Verify
    //     zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);
    //     lpc_scheme_verifier.set_batch_size(0, proof.z.get_batch_size(0));
    //     lpc_scheme_verifier.set_batch_size(1, proof.z.get_batch_size(1));
    //     lpc_scheme_verifier.set_batch_size(2, proof.z.get_batch_size(2));
    //     lpc_scheme_verifier.set_batch_size(3, proof.z.get_batch_size(3));

    //     lpc_scheme_verifier.append_eval_point(0, point);
    //     lpc_scheme_verifier.append_eval_point(1, point);
    //     lpc_scheme_verifier.append_eval_point(2, point);
    //     lpc_scheme_verifier.append_eval_point(3, point);
    //     BOOST_CHECK(lpc_scheme_verifier.verify_eval(proof, commitments, transcript_verifier));

    //     // Check transcript state
    //     typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
    //     typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();
    //     BOOST_CHECK(verifier_next_challenge == prover_next_challenge);

    //     if(print_enabled) export_to_json(proof, fri_params, eval_map, points, "test2.json");
    // }

    // BOOST_FIXTURE_TEST_CASE(lpc_dfs_basic_test, test_fixture) {
    //     // Setup types
    //     typedef algebra::curves::pallas curve_type;
    //     typedef typename curve_type::base_field_type FieldType;
    //     typedef typename FieldType::value_type value_type;
    //     typedef hashes::poseidon<nil::crypto3::hashes::detail::pasta_poseidon_policy<FieldType>> merkle_hash_type;
    //     typedef hashes::poseidon<nil::crypto3::hashes::detail::pasta_poseidon_policy<FieldType>> transcript_hash_type;

    //     typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    //     constexpr static const std::size_t lambda = 10;
    //     constexpr static const std::size_t k = 1;

    //     constexpr static const std::size_t d = 15;

    //     constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    //     constexpr static const std::size_t m = 2;

    //     typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m> fri_type;

    //     typedef zk::commitments::
    //     list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, m>
    //             lpc_params_type;
    //     typedef zk::commitments::list_polynomial_commitment<FieldType, lpc_params_type> lpc_type;

    //     static_assert(zk::is_commitment<fri_type>::value);
    //     static_assert(zk::is_commitment<lpc_type>::value);
    //     static_assert(!zk::is_commitment<merkle_hash_type>::value);
    //     static_assert(!zk::is_commitment<merkle_tree_type>::value);
    //     static_assert(!zk::is_commitment<std::size_t>::value);

    //     // Setup params
    //     std::size_t degree_log = std::ceil(std::log2(d - 1));
    //     typename fri_type::params_type fri_params(
    //             1, /*max_step*/
    //             degree_log,
    //             lambda,
    //             2, //expand_factor
    //             true // use_grinding
    //             );

    //     using lpc_scheme_type = nil::crypto3::zk::commitments::lpc_commitment_scheme<lpc_type>;
    //     lpc_scheme_type lpc_scheme_prover(fri_params);
    //     lpc_scheme_type lpc_scheme_verifier(fri_params);

    //     // Generate polynomials
    //     std::array<std::vector<math::polynomial_dfs<typename FieldType::value_type>>, 4> f;
    //     lpc_scheme_prover.append_many_to_batch(0, generate_random_polynomial_dfs_batch<FieldType>(
    //             dist_type(1, 10)(test_global_rnd_engine), d, test_global_alg_rnd_engine<FieldType>));
    //     lpc_scheme_prover.append_many_to_batch(1, generate_random_polynomial_dfs_batch<FieldType>(
    //             dist_type(1, 10)(test_global_rnd_engine), d, test_global_alg_rnd_engine<FieldType>));
    //     lpc_scheme_prover.append_many_to_batch(2, generate_random_polynomial_dfs_batch<FieldType>(
    //             dist_type(1, 10)(test_global_rnd_engine), d, test_global_alg_rnd_engine<FieldType>));
    //     lpc_scheme_prover.append_many_to_batch(3, generate_random_polynomial_dfs_batch<FieldType>(
    //             dist_type(1, 10)(test_global_rnd_engine), d, test_global_alg_rnd_engine<FieldType>));

    //     std::map<std::size_t, typename lpc_type::commitment_type> commitments;
    //     commitments[0] = lpc_scheme_prover.commit(0);
    //     commitments[1] = lpc_scheme_prover.commit(1);
    //     commitments[2] = lpc_scheme_prover.commit(2);
    //     commitments[3] = lpc_scheme_prover.commit(3);

    //     // Generate evaluation points. Choose poin1ts outside the domain
    //     auto point = algebra::fields::arithmetic_params<FieldType>::multiplicative_generator;
    //     lpc_scheme_prover.append_eval_point(0, point);
    //     lpc_scheme_prover.append_eval_point(1, point);
    //     lpc_scheme_prover.append_eval_point(2, point);
    //     lpc_scheme_prover.append_eval_point(3, point);

    //     std::array<std::uint8_t, 96> x_data{};

    //     // Prove
    //     zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);
    //     auto proof = lpc_scheme_prover.proof_eval(transcript);

    //     // Verify
    //     zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);

    //     lpc_scheme_verifier.set_batch_size(0, proof.z.get_batch_size(0));
    //     lpc_scheme_verifier.set_batch_size(1, proof.z.get_batch_size(1));
    //     lpc_scheme_verifier.set_batch_size(2, proof.z.get_batch_size(2));
    //     lpc_scheme_verifier.set_batch_size(3, proof.z.get_batch_size(3));

    //     lpc_scheme_verifier.append_eval_point(0, point);
    //     lpc_scheme_verifier.append_eval_point(1, point);
    //     lpc_scheme_verifier.append_eval_point(2, point);
    //     lpc_scheme_verifier.append_eval_point(3, point);
    //     BOOST_CHECK(lpc_scheme_verifier.verify_eval(proof, commitments, transcript_verifier));

    //     // Check transcript state
    //     typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
    //     typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();
    //     BOOST_CHECK(verifier_next_challenge == prover_next_challenge);

    //     if(print_enabled) export_to_json(proof, fri_params, eval_map, points, "test3.json");
    // }

BOOST_AUTO_TEST_SUITE_END()

