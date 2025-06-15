//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022-2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#define BOOST_TEST_MODULE crypto3_marshalling_lpc_commitment_test

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>

#include <iostream>
#include <iomanip>
#include <fstream>
#include <regex>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/lpc.hpp>

#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>

#include <nil/crypto3/test_tools/random_test_initializer.hpp>
#include <nil/crypto3/marshalling/zk/detail/random_test_data_generation.hpp>

using namespace nil::crypto3;

// *******************************************************************************
// * Test marshalling function
// ******************************************************************************* /

template<typename Endianness, typename LPC>
void test_lpc_proof(typename LPC::proof_type &proof, typename LPC::fri_type::params_type fri_params) {
    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;

    auto filled_proof = nil::crypto3::marshalling::types::fill_eval_proof<Endianness, LPC>(proof, fri_params);
    auto _proof = nil::crypto3::marshalling::types::make_eval_proof<Endianness, LPC>(filled_proof);
    BOOST_CHECK(proof == _proof);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_proof.length(), 0x00);
    auto write_iter = cv.begin();
    auto status = filled_proof.write(write_iter, cv.size());
    BOOST_CHECK(status == nil::crypto3::marshalling::status_type::success);

    typename nil::crypto3::marshalling::types::eval_proof<TTypeBase, LPC>::type test_val_read;
    auto read_iter = cv.begin();
    test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::crypto3::marshalling::status_type::success);
    typename LPC::proof_type constructed_val_read =
            nil::crypto3::marshalling::types::make_eval_proof<Endianness, LPC>(test_val_read);
    BOOST_CHECK(proof == constructed_val_read);
}

template<typename Endianness, typename LPC>
void test_lpc_aggregated_proof(typename LPC::aggregated_proof_type &proof) {
    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;

    auto filled_proof =
        nil::crypto3::marshalling::types::fill_aggregated_proof<Endianness, LPC>(proof);
    auto _proof = nil::crypto3::marshalling::types::make_aggregated_proof<Endianness, LPC>(filled_proof);
    BOOST_CHECK(proof == _proof);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_proof.length(), 0x00);
    auto write_iter = cv.begin();
    auto status = filled_proof.write(write_iter, cv.size());
    BOOST_CHECK(status == nil::crypto3::marshalling::status_type::success);

    typename nil::crypto3::marshalling::types::aggregated_proof<TTypeBase, LPC> test_val_read;
    auto read_iter = cv.begin();
    test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::crypto3::marshalling::status_type::success);
    typename LPC::aggregated_proof_type constructed_val_read =
            nil::crypto3::marshalling::types::make_aggregated_proof<Endianness, LPC>(test_val_read);
    BOOST_CHECK(proof == constructed_val_read);
}

// This function will test saving and restoring LPC commitment scheme state to a file/buffer.
template<typename Endianness, typename LPC>
void test_lpc_state_recovery(const LPC& lpc_commitment_scheme) {
    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;

    auto filled_lpc_scheme = nil::crypto3::marshalling::types::fill_commitment_scheme<Endianness, LPC>(lpc_commitment_scheme);
    auto _lpc_commitment_scheme = nil::crypto3::marshalling::types::make_commitment_scheme<Endianness, LPC>(filled_lpc_scheme);
    BOOST_CHECK(_lpc_commitment_scheme.has_value());
    BOOST_CHECK(lpc_commitment_scheme == _lpc_commitment_scheme.value());

    std::vector<std::uint8_t> cv;
    cv.resize(filled_lpc_scheme.length(), 0x00);
    auto write_iter = cv.begin();
    auto status = filled_lpc_scheme.write(write_iter, cv.size());
    BOOST_CHECK(status == nil::crypto3::marshalling::status_type::success);

    typename nil::crypto3::marshalling::types::commitment_scheme_state<TTypeBase, LPC>::type test_val_read;
    auto read_iter = cv.begin();
    test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::crypto3::marshalling::status_type::success);
    auto constructed_val_read =
            nil::crypto3::marshalling::types::make_commitment_scheme<Endianness, LPC>(test_val_read);
    BOOST_CHECK(constructed_val_read.has_value());
    BOOST_CHECK(lpc_commitment_scheme == constructed_val_read.value());
}

BOOST_AUTO_TEST_SUITE(marshalling_random)
    // setup
    static constexpr std::size_t lambda = 40;
    static constexpr std::size_t m = 2;

    constexpr static const std::size_t d = 15;
    constexpr static const std::size_t final_polynomial_degree = 1; // final polynomial degree
    constexpr static const std::size_t r = boost::static_log2<(d - final_polynomial_degree)>::value;

    using curve_type = nil::crypto3::algebra::curves::bls12<381>;
    using field_type = typename curve_type::scalar_field_type;
    using value_type = typename field_type::value_type;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;

    using Endianness = nil::crypto3::marshalling::option::big_endian;
    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;
    using FRI = typename nil::crypto3::zk::commitments::detail::basic_batched_fri<field_type, hash_type, hash_type, m>;
    using lpc_params_type = typename nil::crypto3::zk::commitments::list_polynomial_commitment_params<
            hash_type, hash_type, m
    >;
    using LPC = typename nil::crypto3::zk::commitments::batched_list_polynomial_commitment<field_type, lpc_params_type>;
    using poly_type = math::polynomial_dfs<typename field_type::value_type>;
    using lpc_scheme_type = nil::crypto3::zk::commitments::lpc_commitment_scheme<LPC, poly_type>;

BOOST_FIXTURE_TEST_CASE(lpc_proof_test, test_tools::random_test_initializer<field_type>) {

    typename FRI::params_type fri_params(1, r + 1, lambda, 4);

    auto proof = generate_random_lpc_proof<LPC>(
            final_polynomial_degree, 5,
            fri_params.step_list,
            lambda,
            false,
            alg_random_engines.template get_alg_engine<field_type>(),
            generic_random_engine
    );
    test_lpc_proof<Endianness, lpc_scheme_type>(proof, fri_params);
}

BOOST_FIXTURE_TEST_CASE(lpc_aggregated_proof_test, test_tools::random_test_initializer<field_type>) {
    typename FRI::params_type fri_params(1, r + 1, lambda, 4);

    auto proof = generate_random_lpc_aggregated_proof<LPC>(
            final_polynomial_degree, 5,
            fri_params.step_list,
            lambda,
            false,
            alg_random_engines.template get_alg_engine<field_type>(),
            generic_random_engine
    );
    test_lpc_aggregated_proof<Endianness, lpc_scheme_type>(proof);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(marshalling_real)
    // Setup common types.
    using Endianness = nil::crypto3::marshalling::option::big_endian;
    using curve_type = nil::crypto3::algebra::curves::vesta;
    using field_type = curve_type::scalar_field_type;
    using value_type = field_type::value_type;

    using merkle_hash_type = nil::crypto3::hashes::keccak_1600<256>;
    using transcript_hash_type = nil::crypto3::hashes::keccak_1600<256>;
    using merkle_tree_type = typename containers::merkle_tree<merkle_hash_type, 2>;

BOOST_FIXTURE_TEST_CASE(batches_num_3_test, test_tools::random_test_initializer<field_type>){
    // Setup types.
    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d = 15;

    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<field_type, merkle_hash_type, transcript_hash_type, m> fri_type;

    typedef zk::commitments::
        list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, m>
            lpc_params_type;
    typedef zk::commitments::list_polynomial_commitment<field_type, lpc_params_type> lpc_type;
    typedef math::polynomial_dfs<value_type> poly_type;

    static_assert(zk::is_commitment<fri_type>::value);
    static_assert(zk::is_commitment<lpc_type>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);
    static_assert(!zk::is_commitment<merkle_tree_type>::value);
    static_assert(!zk::is_commitment<std::size_t>::value);

    std::size_t degree_log = boost::static_log2<d>::value;

    // Setup params
    typename fri_type::params_type fri_params(
        1, /*max_step*/
        degree_log,
        lambda,
        2 /*expand_factor*/
    );

    using lpc_scheme_type = nil::crypto3::zk::commitments::lpc_commitment_scheme<lpc_type, poly_type>;
    lpc_scheme_type lpc_scheme_prover(fri_params);

    // Generate polynomials
    lpc_scheme_prover.append_to_batch(0, poly_type(15, {1u, 13u, 4u, 1u, 5u, 6u, 7u, 2u, 8u, 7u, 5u, 6u, 1u, 2u, 1u, 1u}));
    lpc_scheme_prover.append_to_batch(2, poly_type(1, {0u, 1u}));
    lpc_scheme_prover.append_to_batch(2, poly_type(2, {0u, 1u, 2u, 3u}));
    lpc_scheme_prover.append_to_batch(3, poly_type(2, {0u, 1u, 3u, 4u}));
    lpc_scheme_prover.append_to_batch(3, poly_type(0, std::initializer_list<value_type>{0u}));

    // Commit
    std::map<std::size_t, typename lpc_type::commitment_type> commitments;
    commitments[0] = lpc_scheme_prover.commit(0);
    commitments[2] = lpc_scheme_prover.commit(2);
    commitments[3] = lpc_scheme_prover.commit(3);

    auto filled_commitment = nil::crypto3::marshalling::types::fill_commitment<Endianness, lpc_scheme_type>(commitments[0]);
    auto _commitment = nil::crypto3::marshalling::types::make_commitment<Endianness, lpc_scheme_type>(filled_commitment);


    // Generate evaluation points. Generate points outside of the basic domain
    // Generate evaluation points. Choose poin1ts outside the domain
    auto point = algebra::fields::arithmetic_params<field_type>::multiplicative_generator;
    lpc_scheme_prover.append_eval_point(0, point);
    lpc_scheme_prover.append_eval_point(2, point);
    lpc_scheme_prover.append_eval_point(3, point);

    std::array<std::uint8_t, 96> x_data {};

    // Prove
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);
    auto proof = lpc_scheme_prover.proof_eval(transcript);

    test_lpc_proof<Endianness, lpc_scheme_type>(proof, fri_params);
    test_lpc_state_recovery<Endianness, lpc_scheme_type>(lpc_scheme_prover);
}

BOOST_AUTO_TEST_SUITE_END()
