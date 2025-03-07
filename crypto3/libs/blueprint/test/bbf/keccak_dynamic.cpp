//---------------------------------------------------------------------------//
// Copyright (c) 2023 Polina Chernyshova <pockvokhbtra@nil.foundation>
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

#define BOOST_TEST_MODULE plonk_keccak_dyncamic_test

#include <array>
#include <boost/test/unit_test.hpp>
#include <cstdlib>
#include <ctime>
#include <random>
#include <nil/blueprint/bbf/components/hashes/keccak/keccak_dynamic.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/blueprint/bbf/circuit_builder.hpp>
#include <nil/crypto3/test_tools/random_test_initializer.hpp>

using namespace nil::crypto3;
using namespace nil::blueprint;

template <typename BlueprintFieldType, std::size_t max_blocks = 10>
void test_keccaks(
    std::vector<std::tuple<
        std::vector<uint8_t>,
        std::pair<typename BlueprintFieldType::value_type, typename BlueprintFieldType::value_type>
    >> input,
    nil::crypto3::test_tools::random_test_initializer<BlueprintFieldType> &rnd
){
    std::cout << "Test keccak with " << input.size() << " messages, max_blocks = " << max_blocks << std::endl;

    auto B = bbf::circuit_builder<BlueprintFieldType, bbf::keccak_dynamic, std::size_t>(max_blocks);
    auto [at, A, desc] = B.assign({
        rnd.alg_random_engines.template get_alg_engine<BlueprintFieldType>()(),
        input
    });
    bool is_satisfied = B.is_satisfied(at);
    std::cout << "Is_satisfied = " << is_satisfied << std::endl;
    assert(is_satisfied);
}

template <typename BlueprintFieldType>
std::pair<typename BlueprintFieldType::value_type, typename BlueprintFieldType::value_type>
calculate_hash(std::vector<std::uint8_t> input){
    hashes::keccak_1600<256>::digest_type d = nil::crypto3::hash<nil::crypto3::hashes::keccak_1600<256>>(input);
    nil::crypto3::algebra::fields::field<256>::integral_type n(d);
    nil::crypto3::algebra::fields::field<256>::integral_type mask = ((nil::crypto3::algebra::fields::field<256>::integral_type(1) << 128) - 1);
    std::pair<typename BlueprintFieldType::value_type, typename BlueprintFieldType::value_type> result;
    result.first =  typename BlueprintFieldType::value_type(n >> 128);
    result.second = typename BlueprintFieldType::value_type(n & mask);

    std::cout << "Message hash = " << std::hex << result.first << " " << result.second << std::dec << std::endl;
    return result;
}

BOOST_AUTO_TEST_SUITE(bn254_test_suite)
    using field_type = nil::crypto3::algebra::curves::alt_bn128_254::base_field_type;

BOOST_AUTO_TEST_CASE(keccak_1_short_message) {
    nil::crypto3::test_tools::random_test_initializer<field_type> rnd;
    test_keccaks<field_type, 2>({{{0},calculate_hash<field_type>({0})}}, rnd);
}

BOOST_AUTO_TEST_CASE(keccak_2_short_messages) {
    nil::crypto3::test_tools::random_test_initializer<field_type> rnd;
    test_keccaks<field_type, 10>({{{0, 0},calculate_hash<field_type>({0, 0})}, {{1,2,3,4,5}, calculate_hash<field_type>({1,2,3,4,5})}}, rnd);
}
BOOST_AUTO_TEST_CASE(keccak_1_N_message) {
    nil::crypto3::test_tools::random_test_initializer<field_type> rnd;
    std::size_t N = 5;
    for (std::size_t i = 0; i < std::size_t(boost::unit_test::framework::master_test_suite().argc - 1); i++) {
        std:: cout << boost::unit_test::framework::master_test_suite().argv[i] << std::endl;
        if (std::string(boost::unit_test::framework::master_test_suite().argv[i]) == "--n") {
            if (std::regex_match(boost::unit_test::framework::master_test_suite().argv[i + 1],
                                std::regex(("((\\+|-)?[[:digit:]]+)(\\.(([[:digit:]]+)?))?")))) {
                N = atoi(boost::unit_test::framework::master_test_suite().argv[i + 1]);
                break;
            }
        }
    }
    std::vector<std::uint8_t> msg(N);
    for( std::size_t i = 0; i < N; i++ ){ msg[i] = (rnd.generic_random_engine()) % 256; }
    test_keccaks<field_type>({{msg,calculate_hash<field_type>(msg)}}, rnd);
}
BOOST_AUTO_TEST_CASE(keccak_1_N_zeroes) {
    nil::crypto3::test_tools::random_test_initializer<field_type> rnd;
    std::size_t N = 5;
    for (std::size_t i = 0; i < std::size_t(boost::unit_test::framework::master_test_suite().argc - 1); i++) {
        std:: cout << boost::unit_test::framework::master_test_suite().argv[i] << std::endl;
        if (std::string(boost::unit_test::framework::master_test_suite().argv[i]) == "--n") {
            if (std::regex_match(boost::unit_test::framework::master_test_suite().argv[i + 1],
                                std::regex(("((\\+|-)?[[:digit:]]+)(\\.(([[:digit:]]+)?))?")))) {
                N = atoi(boost::unit_test::framework::master_test_suite().argv[i + 1]);
                break;
            }
        }
    }
    std::vector<std::uint8_t> msg(N, 0x0);
    test_keccaks<field_type>({{msg,calculate_hash<field_type>(msg)}}, rnd);
}
BOOST_AUTO_TEST_CASE(keccak_1_long_message) {
    nil::crypto3::test_tools::random_test_initializer<field_type> rnd;
    std::vector<uint8_t> msg(500, 5);
    test_keccaks<field_type>({{msg,calculate_hash<field_type>(msg)}}, rnd);
}
BOOST_AUTO_TEST_CASE(keccak_2_long_messages) {
    nil::crypto3::test_tools::random_test_initializer<field_type> rnd;
    std::vector<uint8_t> msg1(136, 6);
    std::vector<uint8_t> msg2(277, 7);
    test_keccaks<field_type>({{msg1,calculate_hash<field_type>(msg1)}, {msg2,calculate_hash<field_type>(msg2)}}, rnd);
}

BOOST_AUTO_TEST_CASE(keccak_test_hello_world){
    nil::crypto3::test_tools::random_test_initializer<field_type> rnd;
    std::vector<std::uint8_t> msg = {
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x33,
        0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x77,
        0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x99,
        0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb,
        0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xdd,
        0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x68,
        0x65, 0x6c, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c};
    test_keccaks<field_type>({{msg, calculate_hash<field_type>(msg)}}, rnd);
}
BOOST_AUTO_TEST_SUITE_END()
