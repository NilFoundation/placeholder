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
// This example demonstrates the usage of the transcript used in Fiat-Shamir
// schemes

#include <vector>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>

#include <nil/crypto3/hash/block_to_field_elements_wrapper.hpp>
#include <nil/crypto3/hash/poseidon.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>

#include <nil/crypto3/marshalling/algebra/processing/bls12.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::hashes;

void keccak_transcript_example()
{
    std::cout << "Setting up transcript with keccak_1600<256> hash" << std::endl;
    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    transcript::fiat_shamir_heuristic_sequential<hashes::keccak_1600<256>> tr(init_blob);
    using field_type = nil::crypto3::algebra::fields::bls12_base_field<381>;
    using g1_curve = nil::crypto3::algebra::curves::bls12_381::template g1_type<>;
    using g2_curve = nil::crypto3::algebra::curves::bls12_381::template g2_type<>;
    using g2_field_type = typename g2_curve::field_type;


    std::cout << "Updating transcript with Fp element.." << std::endl;
    typename field_type::value_type b = 0x123;
    tr(b);

    std::cout << "Updating transcript with Fp2 element.." << std::endl;
    typename g2_field_type::value_type x(0x01_big_uint256, 0x02_big_uint256);
    tr(x);

    std::cout << "Updating transcript with G1 element.." << std::endl;
    typename g1_curve::value_type g1_generator = g1_curve::value_type::one();
    tr(g1_generator);

    std::cout << "Updating transcript with G2 element.." << std::endl;
    typename g2_curve::value_type g2_generator = g2_curve::value_type::one();
    tr(g2_generator);

    std::cout << "Sourcing element from transcript.." << std::endl;
    typename field_type::value_type a = tr.challenge<field_type>();
    std::cout << a << std::endl;

}

void poseidon_transcript_example()
{
    std::cout << "Setting up transcript with poseidon over bls12_381 scalar field" << std::endl;
    using field_type = nil::crypto3::algebra::fields::bls12_scalar_field<381>;
    constexpr size_t security_bits = 128;
    constexpr size_t rate = 4;
    using policy = hashes::detail::poseidon_policy<field_type, security_bits, rate>;
    using hash_type = poseidon<policy>;
    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    transcript::fiat_shamir_heuristic_sequential<hash_type> tr {
        hashes::block_to_field_elements_wrapper<field_type, std::vector<std::uint8_t>>(init_blob)
    };

    using g1_curve = nil::crypto3::algebra::curves::bls12_381::template g1_type<>;
    using g2_curve = nil::crypto3::algebra::curves::bls12_381::template g2_type<>;
    using g2_field_type = typename g2_curve::field_type;


    std::cout << "Updating transcript with element.." << std::endl;
    typename field_type::value_type b = 0x123;
    tr(b);

    std::cout << "Sourcing element from transcript.." << std::endl;
    typename field_type::value_type a = tr.challenge<field_type>();
    std::cout << a << std::endl;
}

int main()
{
    keccak_transcript_example();
    poseidon_transcript_example();
    return 0;
}
