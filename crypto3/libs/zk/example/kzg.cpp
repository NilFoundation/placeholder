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
// This example show the usage of KZG commitment scheme for single polynomial
// and for a batch of polynomials

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/algorithms/pair.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>

#include <nil/crypto3/zk/commitments/polynomial/kzg.hpp>

#include <nil/crypto3/marshalling/algebra/processing/bls12.hpp>


using namespace nil::crypto3;
using namespace nil::crypto3::math;

/* Test of commitment to single polynomial*/
void run_basic_test() {
    using curve_type = curves::bls12_381;
    using scalar_value_type = typename curve_type::scalar_field_type::value_type;

    using kzg_type = zk::commitments::kzg<curve_type>;

    /* Trusted setup */
    scalar_value_type alpha = 10u;
    std::size_t n = 16;

    /* Evaluation point */
    scalar_value_type z = 2u;

    /* Polynomial: 3x^3 + 2x^2 + x - 1 */
    const polynomial<scalar_value_type> f = {{scalar_value_type::modulus - 1u, 1u, 2u, 3u}};

    auto params = typename kzg_type::params_type(n, alpha);
    auto commit = zk::algorithms::commit<kzg_type>(params, f);

    /* Commitment is f(alpha)*G */
    if (f.evaluate(alpha) * curve_type::template g1_type<>::value_type::one() == commit) {
        std::cout << "Commitment value is ok" << std::endl;
    }

    typename kzg_type::public_key_type pk = {commit, z, f.evaluate(z)};
    auto proof = zk::algorithms::proof_eval<kzg_type>(params, f, pk);

    std::cout << "Proof: " << std::endl;
    std::cout << proof << std::endl;

    bool verify_result = zk::algorithms::verify_eval<kzg_type>(params, proof, pk);
    std::cout << "Verification result: " << std::boolalpha << verify_result << std::endl;
}

/* Commitment to multiple polynomials */
void run_batched_test()
{
    using curve_type = curves::bls12_381;
    using scalar_value_type = typename curve_type::scalar_field_type::value_type;
    using transcript_hash_type = hashes::sha2<256>;
    using kzg_type = zk::commitments::batched_kzg<curve_type, transcript_hash_type, math::polynomial<scalar_value_type>>;
    using transcript_type = typename kzg_type::transcript_type;

    /* Set of polynomials */
    typename kzg_type::batch_of_polynomials_type polys = {{
        {{ 1u,  2u,  3u,  4u,  5u,  6u,  7u,  8u}},
        {{11u, 12u, 13u, 14u, 15u, 16u, 17u, 18u}},
        {{21u, 22u, 23u, 24u, 25u, 26u, 27u, 28u}},
        {{31u, 32u, 33u, 34u, 35u, 36u, 37u, 38u}}
    }};

    /* Trusted setup */
    scalar_value_type alpha = 7u;
    auto params = typename kzg_type::params_type(8, 8, alpha);

    /* Set of points, where each polynomial must be evaluated */
    std::vector<std::vector<scalar_value_type>> S = {{
        {101u, 2u, 3u},
        {102u, 2u, 3u},
        {  1u, 3u},
        {101u, 4u}
    }};
    std::vector<scalar_value_type> T = zk::algorithms::merge_eval_points<kzg_type>(S);

    auto rs = zk::algorithms::create_evals_polys<kzg_type>(polys, S);

    auto commits = zk::algorithms::commit<kzg_type>(params, polys);
    /* Commitment to each polynomial is a curve point */
    std::cout << "Commitment:" << std::endl;
    for(auto const& c: commits) {
        std::cout << c << std::endl;
    }
    auto pk = typename kzg_type::public_key_type(commits, T, S, rs);

    transcript_type transcript;
    auto proof = zk::algorithms::proof_eval<kzg_type>(params, polys, pk, transcript);

    /* Proof of evaluation of the whole batch is one curve point */
    std::cout << "Proof: " << std::endl;
    std::cout << proof << std::endl;

    transcript_type transcript_verification;
    bool verify_result = zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verification);

    std::cout << "Verification result: " << std::boolalpha << verify_result << std::endl;
}

int main()
{
    run_basic_test();
    run_batched_test();

    return 0;
}
