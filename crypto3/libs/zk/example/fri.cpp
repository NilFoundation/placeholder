//---------------------------------------------------------------------------//
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
// This example shows the usage of FRI commitment scheme with polynomials
// in normal and DFS forms

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/type_traits.hpp>

using namespace nil::crypto3;

template<typename FieldType, typename PolynomialType>
void fri_basic_test()
{
    // setup
    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;
    constexpr static const std::size_t lambda = 40;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m> fri_type;

    typedef typename fri_type::proof_type proof_type;
    typedef typename fri_type::params_type params_type;


    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    std::size_t degree_log = std::ceil(std::log2(d - 1));
    params_type params(
            1, /*max_step*/
            degree_log,
            lambda,
            2, //expand_factor
            true, // use_grinding
            16 // grinding_parameter
            );

    // Polynomial to commit
    std::vector<typename FieldType::value_type> coefficients =
        {1u, 3u, 4u, 1u, 5u, 6u, 7u, 2u, 8u, 7u, 5u, 6u, 1u, 2u, 1u, 1u};

    PolynomialType f;
    if constexpr (std::is_same<math::polynomial_dfs<typename FieldType::value_type>,
            PolynomialType>::value) {
        f.from_coefficients(coefficients);
        if (f.size() != params.D[0]->size()) {
            f.resize(params.D[0]->size(), nullptr, params.D[0]);
        }
    } else {
        f = PolynomialType(coefficients);
    }

    // Construction of Merkle tree for polynomial coefficients
    typename fri_type::merkle_tree_type tree =
        zk::algorithms::precommit<fri_type>(f, params.D[0], params.step_list[0]);
    // Commitment to Merkle tree of polynomial coefficients
    auto root = zk::algorithms::commit<fri_type>(tree);

    // Random initialization vector for transcript
    std::vector<std::uint8_t> init_blob{0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(init_blob);

    // Polynomial is evaluated using random point sourced from transcript
    // Proof structure contains the value of polynomial with the actual FRI proof
    proof_type proof = zk::algorithms::proof_eval<fri_type>(f, tree, params, transcript);

    // On a verifier side the transcript must be initialized with the same data as on prover side
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(init_blob);

    bool verify_result = zk::algorithms::verify_eval<fri_type>(proof, root, params, transcript_verifier);

    std::cout << "Verification result: " << std::boolalpha << verify_result << std::endl;

    typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();

    // During the verification and proving process the challenges are sourced
    // from transcripts and the transcript is updated with data.
    // Check that transcripts of prover and verifier synchronized, i.e. the next
    // challenge sourced from both transcripts are the same.
    if (verifier_next_challenge == prover_next_challenge) {
        std::cout << "Transcripts are synchronized" << std::endl;
    } else {
        std::cout << "Transcripts are out of sync" << std::endl;
    }
}

int main()
{
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;
    using PolynomialType = math::polynomial<FieldType::value_type>;
    using PolynomialType_dfs = math::polynomial_dfs<FieldType::value_type>;

    fri_basic_test<FieldType, PolynomialType>();
    fri_basic_test<FieldType, PolynomialType_dfs>();

    return 0;
}

