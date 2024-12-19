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
// This example shows usage of hashes

#include <iostream>

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/sha3.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/poseidon.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <type_traits>

using namespace nil::crypto3::hashes;

template<typename hash_type, typename enable = void>
struct hash_usage_example {
    static void run()
    {
        std::string empty = nil::crypto3::hash<hash_type>(std::array<uint8_t,0>{});
        std::cout << "Hash of empty string: " << empty << std::endl;

        std::string input = "A quick brown fox jumps over the lazy dog";
        std::string fox_hash = nil::crypto3::hash<hash_type>(input.begin(), input.end());
        std::cout << "Hash of fox string  : " << fox_hash << std::endl;
    }
};


template<typename hash_type>
struct hash_usage_example<hash_type, typename std::enable_if<is_poseidon<hash_type>::value>::type>
{
    static void run()
    {
        using policy = typename hash_type::policy_type;
        using field_type = typename policy::field_type;
        std::vector<typename field_type::value_type> field_input = {
            0x000123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCD_big_uint255,
            0x00000000000000000000000000000000000000000000000000000000000000EF_big_uint255,
        };

        typename policy::digest_type result = nil::crypto3::hash<hash_type>(field_input);
        std::cout << result << std::endl;
    }
};


int main() {
    std::cout << "SHA2-256" << std::endl;
    hash_usage_example<sha2<256>>::run();

    std::cout << "SHA3-256" << std::endl;
    hash_usage_example<sha3<256>>::run();

    std::cout << "keccak" << std::endl;
    hash_usage_example<keccak_1600<256>>::run();

    std::cout << "Poseidon @ BLS12-381 scalar" << std::endl;

    using field_type = nil::crypto3::algebra::fields::bls12_scalar_field<381>;
    constexpr size_t security_bits = 128;
    constexpr size_t rate = 4;
    using policy = detail::poseidon_policy<field_type, security_bits, rate>;
    using hash_type = poseidon<policy>;


    hash_usage_example<hash_type>::run();

    return 0;
}
