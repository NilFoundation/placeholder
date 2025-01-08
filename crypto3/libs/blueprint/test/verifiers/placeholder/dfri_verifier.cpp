//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2024 Valeh Farzaliyev <estoniaa@nil.foundation>
// Copyright (c) 2024 Elena Tatuzova <estoniaa@nil.foundation>
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

#define BOOST_TEST_MODULE dfri_verifier

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

#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>
#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/type_traits.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/blueprint/components/systems/snark/plonk/verifier/dfri_verifier.hpp>
#include <nil/crypto3/hash/poseidon.hpp>
#include "../../test_plonk_component.hpp"

using namespace nil;
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
void export_to_json(
    ProofType const &proof,
    ParamsType const &fri_params,
    const std::map<std::pair<std::size_t,std::size_t>, std::vector<std::size_t>> &eval_map,
    const std::vector<ValueType> &points,
    std::string filename
) {

    std::ofstream out(filename);

    bool first = true;
    out << "{\"params\": {\"lambda\" : " << fri_params.lambda << ", \"expand_factor\": " << fri_params.expand_factor << ", \"batches_amount\": " <<  proof.z.get_batches().size();
    out << ", \"batch_size\": [";

    for(const auto &[k,v] : proof.z.get_batch_info()){
        if (!first) out << ","; else first = false;
        out << v;
    }
    out << "], \"evaluation_map\": [";
    first = true;
    for(auto &[k, v] : eval_map){
        if (!first) out << ","; else first = false;
        out << "{\"batch_id\": " << k.first << ", \"poly_id\": " << k.second << ",\"points\": [";
        first = true;
        for(auto &p: v) {
            if (!first) out << ","; else first = false;
            out << p;
        }
        out << "]}";
        first = false;
    }

    out << "]},\"evaluation_points\": [";
    first = true;
    for(auto &p : points){
        if (!first) out << ","; else first = false;
        out << p;
    }
    out << "], \"lpc_proof\" :{\"evaluations\": [";
    first = true;
    for (std::size_t i : proof.z.get_batches()) {
        if (!first) out << ","; else first = false;
        out << "{\"batch_id\":" << i << ", \"batch\": [";
        first = true;
        for (std::size_t j = 0; j < proof.z.get_batch_size(i); j++) {
            if (!first) out << ","; else first = false;
            out << "{\"polynomial_index\":" << j << ", \"evaluation\":[";
            first = true;
            for (auto b : proof.z.get(i, j)) {
                if (!first) out << ","; else first = false;
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
        if (!first) out << ","; else first = false;
        out << c;
    }
    out << "],\"query_proofs\": [" << std::endl;
    first = true;
    for (auto &q : proof.fri_proof.query_proofs) {
        // initial round proof
        if (!first) out << ","; else first = false;
        out << "{\"initial_round_proof\": [";
        first = true;
        for (auto [k, init_proof] : q.initial_proof) {
            if (!first) out << ",";
            out << "{\"batch_id\":" << k << ", \"y\": [";
            first = true;
            for (auto &y : init_proof.values) {
                if (!first) out << ","; else first = false;
                out << "[" << y[0][0] << "," << y[0][1] << "]";
            }
            out << "],\"merkle_path\": [";
            first = true;
            for (auto &path : init_proof.p.path()) {
                if (!first) out << ","; else first = false;
                out << "{\"position\":" << path[0].position() << ", \"hash\" :" << path[0].hash() << "}";
            }
            out << "]}";
            first = false;
        }
        // round proofs
        out << "], \"round_proofs\": [" << std::endl;
        first = true;
        for (auto &r : q.round_proofs) {
            if (!first) out << ","; else first = false;
            out << "{\"y\": [" << r.y[0][0] << ", " << r.y[0][1] << "]," << std::endl;
            out << "\"merkle_path\": [";
            first = true;
            for (auto &path : r.p.path()) {
                if (!first) out << ","; else first = false;
                out << "{\"position\":" << path[0].position() << ", \"hash\" :" << path[0].hash() << "}";
            }
            out << "]}";
            first = false;
        }
        out << "]}" << std::endl;
        first = false;
    }
    out << "],\"final_polynomial\": [";
    first = true;
    for (auto &coeff : proof.fri_proof.final_polynomial) {
        if (!first) out << ","; else first = false;
        out << coeff;
    }
    out << "]}}}" << std::endl;
    out.close();
}

template<typename FieldType>
struct test_setup_struct{
    using field_type = FieldType;
    using component_type = nil::blueprint::components::plonk_dfri_verifier<field_type>;

    typename component_type::fri_params_type      component_fri_params;
    std::map<std::size_t, std::size_t>            batches_sizes; // It's a map just for compatibility with placeholder
    std::size_t                                   evaluation_points_amount;
    std::map<std::pair<std::size_t, std::size_t>, std::vector<std::size_t>> eval_map;
};

template<typename FieldType>
std::pair<test_setup_struct<FieldType>, nil::blueprint::components::detail::dfri_proof_wrapper<FieldType>>
prepare_small_test(bool print_enable = false){
    using field_type = FieldType;
    using merkle_hash_type = hashes::poseidon<nil::crypto3::hashes::detail::pasta_poseidon_policy<FieldType>>;
    using transcript_hash_type =  hashes::poseidon<nil::crypto3::hashes::detail::pasta_poseidon_policy<FieldType>>;

    using val = typename field_type::value_type;
    using integral_type = typename field_type::integral_type;

    constexpr static const std::size_t lambda = 10;
    constexpr static const std::size_t k = 1;
    constexpr static const std::size_t d = 16;
    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    constexpr static const std::size_t m = 2;

    using fri_type = zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m>;
    using lpc_params_type = zk::commitments::list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, m>;
    using lpc_type = zk::commitments::list_polynomial_commitment<FieldType, lpc_params_type>;

    static_assert(zk::is_commitment<fri_type>::value);
    static_assert(zk::is_commitment<lpc_type>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);
//    static_assert(!zk::is_commitment<merkle_tree_type>::value);
    static_assert(!zk::is_commitment<std::size_t>::value);

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    // Setup params
    std::size_t degree_log = std::ceil(std::log2(d - 1));
    typename fri_type::params_type fri_params(
        1,       // max_step
        degree_log,
        lambda,
        2,       // expand_factor
        false    // use_grinding
    );
    typename test_setup_struct<FieldType>::component_type::fri_params_type component_fri_params(fri_params);

    using lpc_scheme_type = nil::crypto3::zk::commitments::lpc_commitment_scheme<
        lpc_type, math::polynomial_dfs<typename FieldType::value_type>
    >;
    lpc_scheme_type lpc_scheme_prover(fri_params);
    lpc_scheme_type lpc_scheme_verifier(fri_params);

    std::map<std::size_t, std::size_t> batches_sizes;
    batches_sizes[0] = 1;
    batches_sizes[2] = 3;
    batches_sizes[3] = 1;
    batches_sizes[4] = 2;

    // Generate polynomials
    for(auto &[k,v]: batches_sizes){
        for(std::size_t i = 0; i < v; i++){
            lpc_scheme_prover.append_to_batch(k, generate_random_polynomial_dfs(fri_params.max_degree, test_global_alg_rnd_engine<field_type>));
        }
    }
    // Commit
    std::map<std::size_t, typename lpc_type::commitment_type> commitments;
    for(auto &[k,v]: batches_sizes){
        lpc_scheme_verifier.set_batch_size(k,v);
        commitments[k] = lpc_scheme_prover.commit(k);
    }

    std::size_t evaluation_points_amount = 3;
    std::vector<val> evaluation_points;
    for( std::size_t i = 0; i < evaluation_points_amount; i++ ){
        evaluation_points.push_back(test_global_alg_rnd_engine<field_type>());
    }

    // Generate eval_map
    std::map<std::pair<std::size_t,std::size_t>, std::vector<std::size_t>> eval_map;
    for(auto &[k,v]: batches_sizes){
        for(std::size_t i = 0; i < v; i++){
            eval_map[{k,i}] = {0};
            lpc_scheme_prover.append_eval_point(k, i, evaluation_points[0]);
            lpc_scheme_verifier.append_eval_point(k, i, evaluation_points[0]);
            for( std::size_t j = 1; j < evaluation_points_amount; j++ ){
                if( test_global_rnd_engine() % 2 == 1 ) {
                    eval_map[{k,i}].push_back(j);
                    lpc_scheme_prover.append_eval_point(k, i, evaluation_points[j]);
                    lpc_scheme_verifier.append_eval_point(k, i, evaluation_points[j]);
                }
            }
        }
    }

    // Prove
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_prover;
    auto proof = lpc_scheme_prover.proof_eval(transcript_prover);

    // Verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier;
    BOOST_CHECK(lpc_scheme_verifier.verify_eval(proof, commitments, transcript_verifier));

    // Check transcript state
    typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = transcript_prover.template challenge<FieldType>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);

    test_setup_struct<FieldType> component_setup = {
        component_fri_params,
        batches_sizes,
        evaluation_points_amount,
        eval_map
    };
    nil::blueprint::components::detail::dfri_proof_wrapper<FieldType> public_input(
        0, // transcript initial state
        commitments,
        evaluation_points,
        proof
    );

    if(print_enabled){
        export_to_json(proof, fri_params, eval_map, evaluation_points, "data.json");
    }

    return {component_setup, public_input};
}

template<typename FieldType, std::size_t WitnessAmount>
void test_dfri_verifier(
    const test_setup_struct<FieldType> &test_setup,
    const nil::blueprint::components::detail::dfri_proof_wrapper<FieldType> &test_input
){
    std::cout << "Test with " << WitnessAmount << " witnesses" << std::endl;

    using field_type = FieldType;
    using val = typename field_type::value_type;
    using constraint_system_type = nil::crypto3::zk::snark::plonk_constraint_system<field_type>;
    using table_description_type = nil::crypto3::zk::snark::plonk_table_description<field_type>;
    using ColumnType = nil::crypto3::zk::snark::plonk_column<field_type>;
    using assignment_table_type = nil::crypto3::zk::snark::plonk_table<field_type, ColumnType>;

    std::array<std::uint32_t, WitnessAmount> witnesses;
    for (std::uint32_t i = 0; i < WitnessAmount; i++) {
        witnesses[i] = i;
    }

    using component_type = nil::blueprint::components::plonk_dfri_verifier<field_type>;
    using var = crypto3::zk::snark::plonk_variable<val>;

    component_type component_instance(
        witnesses, std::array<std::uint32_t, 1>({0}), std::array<std::uint32_t, 0>(),
        test_setup.component_fri_params, test_setup.batches_sizes,
        test_setup.evaluation_points_amount, test_setup.eval_map //fri_params, batches_sizes, evaluation_points_num, eval_map
    );

    // TODO: remove it if we don't need test_plonk_component.
    bool expected_res = true;
    auto result_check = [&expected_res]( assignment_table_type &assignment, typename component_type::result_type &real_res) {
            return true;
    };

    nil::blueprint::components::detail::dfri_proof_input_vars<field_type> input_vars(
        test_setup.component_fri_params,
        test_setup.batches_sizes,
        test_setup.evaluation_points_amount,
        test_setup.eval_map
    );
    if(input_vars.all_vars().size() != test_input.vector().size())
        std::cout << "Wrong public input column length " << input_vars.all_vars().size() << " != " << test_input.vector().size() << std::endl;
    BOOST_ASSERT(input_vars.all_vars().size() == test_input.vector().size());

    table_description_type desc(WitnessAmount, 1, 1, 35); //Witness, public inputs, constants, selectors

    using poseidon_policy = nil::crypto3::hashes::detail::pasta_poseidon_policy<field_type>;
    using hash_type = nil::crypto3::hashes::poseidon<poseidon_policy>;
    nil::crypto3::test_component<component_type, field_type, hash_type, 9> (
        component_instance, desc, test_input.vector(), result_check,
        input_vars, nil::blueprint::connectedness_check_type::type::NONE,
        test_setup.component_fri_params, test_setup.batches_sizes,
        test_setup.evaluation_points_amount, test_setup.eval_map
    );
}

template<typename field_type>
void test_multiple_arithmetizations(
    const test_setup_struct<field_type> &test_setup,
    const nil::blueprint::components::detail::dfri_proof_wrapper<field_type> &test_input
){
    std::cout << "Load commitment params" << std::endl;
    std::cout << "Load transcript state" << std::endl;
    std::cout << "Load commitments" << std::endl;
    std::cout << "Load evaluation points" << std::endl;
    std::cout << "Load proof" << std::endl;

    test_dfri_verifier<field_type,  15>(test_setup, test_input);
    test_dfri_verifier<field_type,  42>(test_setup, test_input);
    test_dfri_verifier<field_type,  84>(test_setup, test_input);
    test_dfri_verifier<field_type, 168>(test_setup, test_input);
}


BOOST_AUTO_TEST_SUITE(dfri_pallas_suite);
    using curve_type = algebra::curves::pallas;
    using field_type = curve_type::base_field_type;
    using val = typename field_type::value_type;
BOOST_FIXTURE_TEST_CASE(lpc_basic_test, test_fixture) {
    const auto &[test_setup, test_input] = prepare_small_test<field_type>(print_enabled);
    test_multiple_arithmetizations<field_type>(test_setup, test_input);
}
BOOST_AUTO_TEST_SUITE_END()

