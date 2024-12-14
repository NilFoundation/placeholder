//---------------------------------------------------------------------------//
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

#define BOOST_TEST_MODULE plonk_sha512_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/hashes/sha2/plonk/sha512_process.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_sha512_process) {

    using curve_type = crypto3::algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 10;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;

    using component_type = blueprint::components::sha512_process<ArithmetizationType>;

    typename BlueprintFieldType::value_type s = typename BlueprintFieldType::value_type(2).pow(59);
    std::array<typename ArithmetizationType::field_type::value_type, 24> public_input = {0x6a09e667f3bcc908_big_uint64,
                                                                                         0xbb67ae8584caa73b_big_uint64,
                                                                                         0x3c6ef372fe94f82b_big_uint64,
                                                                                         0xa54ff53a5f1d36f1_big_uint64,
                                                                                         0x510e527fade682d1_big_uint64,
                                                                                         0x9b05688c2b3e6c1f_big_uint64,
                                                                                         0x1f83d9abfb41bd6b_big_uint64,
                                                                                         0x5be0cd19137e2179_big_uint64,
                                                                                         s - 5,
                                                                                         s + 5,
                                                                                         s - 6,
                                                                                         s + 6,
                                                                                         s - 7,
                                                                                         s + 7,
                                                                                         s - 8,
                                                                                         s + 8,
                                                                                         s - 9,
                                                                                         s + 9,
                                                                                         s + 10,
                                                                                         s - 10,
                                                                                         s + 11,
                                                                                         s - 11,
                                                                                         s + 12,
                                                                                         s - 12};
    std::array<var, 8> input_state_var = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input),
        var(0, 4, false, var::column_type::public_input), var(0, 5, false, var::column_type::public_input),
        var(0, 6, false, var::column_type::public_input), var(0, 7, false, var::column_type::public_input)};

    std::array<typename BlueprintFieldType::integral_type, 80> round_constant = {
        0x428a2f98d728ae22_big_uint64, 0x7137449123ef65cd_big_uint64, 0xb5c0fbcfec4d3b2f_big_uint64, 0xe9b5dba58189dbbc_big_uint64,
        0x3956c25bf348b538_big_uint64, 0x59f111f1b605d019_big_uint64, 0x923f82a4af194f9b_big_uint64, 0xab1c5ed5da6d8118_big_uint64,
        0xd807aa98a3030242_big_uint64, 0x12835b0145706fbe_big_uint64, 0x243185be4ee4b28c_big_uint64, 0x550c7dc3d5ffb4e2_big_uint64,
        0x72be5d74f27b896f_big_uint64, 0x80deb1fe3b1696b1_big_uint64, 0x9bdc06a725c71235_big_uint64, 0xc19bf174cf692694_big_uint64,
        0xe49b69c19ef14ad2_big_uint64, 0xefbe4786384f25e3_big_uint64, 0x0fc19dc68b8cd5b5_big_uint64, 0x240ca1cc77ac9c65_big_uint64,
        0x2de92c6f592b0275_big_uint64, 0x4a7484aa6ea6e483_big_uint64, 0x5cb0a9dcbd41fbd4_big_uint64, 0x76f988da831153b5_big_uint64,
        0x983e5152ee66dfab_big_uint64, 0xa831c66d2db43210_big_uint64, 0xb00327c898fb213f_big_uint64, 0xbf597fc7beef0ee4_big_uint64,
        0xc6e00bf33da88fc2_big_uint64, 0xd5a79147930aa725_big_uint64, 0x06ca6351e003826f_big_uint64, 0x142929670a0e6e70_big_uint64,
        0x27b70a8546d22ffc_big_uint64, 0x2e1b21385c26c926_big_uint64, 0x4d2c6dfc5ac42aed_big_uint64, 0x53380d139d95b3df_big_uint64,
        0x650a73548baf63de_big_uint64, 0x766a0abb3c77b2a8_big_uint64, 0x81c2c92e47edaee6_big_uint64, 0x92722c851482353b_big_uint64,
        0xa2bfe8a14cf10364_big_uint64, 0xa81a664bbc423001_big_uint64, 0xc24b8b70d0f89791_big_uint64, 0xc76c51a30654be30_big_uint64,
        0xd192e819d6ef5218_big_uint64, 0xd69906245565a910_big_uint64, 0xf40e35855771202a_big_uint64, 0x106aa07032bbd1b8_big_uint64,
        0x19a4c116b8d2d0c8_big_uint64, 0x1e376c085141ab53_big_uint64, 0x2748774cdf8eeb99_big_uint64, 0x34b0bcb5e19b48a8_big_uint64,
        0x391c0cb3c5c95a63_big_uint64, 0x4ed8aa4ae3418acb_big_uint64, 0x5b9cca4f7763e373_big_uint64, 0x682e6ff3d6b2b8a3_big_uint64,
        0x748f82ee5defb2fc_big_uint64, 0x78a5636f43172f60_big_uint64, 0x84c87814a1f0ab72_big_uint64, 0x8cc702081a6439ec_big_uint64,
        0x90befffa23631e28_big_uint64, 0xa4506cebde82bde9_big_uint64, 0xbef9a3f7b2c67915_big_uint64, 0xc67178f2e372532b_big_uint64,
        0xca273eceea26619c_big_uint64, 0xd186b8c721c0c207_big_uint64, 0xeada7dd6cde0eb1e_big_uint64, 0xf57d4f7fee6ed178_big_uint64,
        0x06f067aa72176fba_big_uint64, 0x0a637dc5a2c898a6_big_uint64, 0x113f9804bef90dae_big_uint64, 0x1b710b35131c471b_big_uint64,
        0x28db77f523047d84_big_uint64, 0x32caab7b40c72493_big_uint64, 0x3c9ebe0a15c9bebc_big_uint64, 0x431d67c49c100d4c_big_uint64,
        0x4cc5d4becb3e42b6_big_uint64, 0x597f299cfc657e2a_big_uint64, 0x5fcb6fab3ad6faec_big_uint64, 0x6c44198c4a475817_big_uint64};

    std::array<var, 16> input_words_var;
    for (int i = 0; i < 16; i++) {
        input_words_var[i] = var(0, 8 + i, false, var::column_type::public_input);
    }
    std::array<typename BlueprintFieldType::integral_type, 80> message_schedule_array;
    for (std::size_t i = 0; i < 16; i++) {
        message_schedule_array[i] = typename BlueprintFieldType::integral_type(public_input[8 + i].data);
    }
    for(std::size_t i = 16; i < 80; i ++){
        typename BlueprintFieldType::integral_type s0 = ((message_schedule_array[i - 15] >> 1)|((message_schedule_array[i - 15] << (64 - 1))
        & typename BlueprintFieldType::integral_type((typename BlueprintFieldType::value_type(2).pow(64) - 1).data))) ^
        ((message_schedule_array[i - 15] >> 8)|((message_schedule_array[i - 15] << (64 - 8))
        & typename BlueprintFieldType::integral_type((typename BlueprintFieldType::value_type(2).pow(64) - 1).data)))
         ^ (message_schedule_array[i - 15] >> 7);
        typename BlueprintFieldType::integral_type s1 = ((message_schedule_array[i - 2] >> 19)|((message_schedule_array[i - 2] << (64 - 19))
        & typename BlueprintFieldType::integral_type((typename BlueprintFieldType::value_type(2).pow(64) - 1).data))) ^
        ((message_schedule_array[i - 2] >> 61)|((message_schedule_array[i - 2] << (64 - 61))
        & typename BlueprintFieldType::integral_type((typename BlueprintFieldType::value_type(2).pow(64) - 1).data)))
         ^ (message_schedule_array[i - 2] >> 6);
        message_schedule_array[i] = (message_schedule_array[i - 16] + s0 + s1 + message_schedule_array[i - 7])%
        typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(64).data);
    }
    typename ArithmetizationType::field_type::integral_type a =
        typename ArithmetizationType::field_type::integral_type(public_input[0].data);
    typename ArithmetizationType::field_type::integral_type b =
        typename ArithmetizationType::field_type::integral_type(public_input[1].data);
    typename ArithmetizationType::field_type::integral_type c =
        typename ArithmetizationType::field_type::integral_type(public_input[2].data);
    typename ArithmetizationType::field_type::integral_type d =
        typename ArithmetizationType::field_type::integral_type(public_input[3].data);
    typename ArithmetizationType::field_type::integral_type e =
        typename ArithmetizationType::field_type::integral_type(public_input[4].data);
    typename ArithmetizationType::field_type::integral_type f =
        typename ArithmetizationType::field_type::integral_type(public_input[5].data);
    typename ArithmetizationType::field_type::integral_type g =
        typename ArithmetizationType::field_type::integral_type(public_input[6].data);
    typename ArithmetizationType::field_type::integral_type h =
        typename ArithmetizationType::field_type::integral_type(public_input[7].data);
    for (std::size_t i = 0; i < 80; i++) {
        typename BlueprintFieldType::integral_type S0 =
            ((a >> 28) | ((a << (64 - 28)) & typename BlueprintFieldType::integral_type(
                                                 (typename BlueprintFieldType::value_type(2).pow(64) - 1).data))) ^
            ((a >> 34) | ((a << (64 - 34)) & typename BlueprintFieldType::integral_type(
                                                 (typename BlueprintFieldType::value_type(2).pow(64) - 1).data))) ^
            ((a >> 39) | ((a << (64 - 39)) & typename BlueprintFieldType::integral_type(
                                                 (typename BlueprintFieldType::value_type(2).pow(64) - 1).data)));

        typename BlueprintFieldType::integral_type S1 =
            ((e >> 14) | ((e << (64 - 14)) & typename BlueprintFieldType::integral_type(
                                                 (typename BlueprintFieldType::value_type(2).pow(64) - 1).data))) ^
            ((e >> 18) | ((e << (64 - 18)) & typename BlueprintFieldType::integral_type(
                                                 (typename BlueprintFieldType::value_type(2).pow(64) - 1).data))) ^
            ((e >> 41) | ((e << (64 - 41)) & typename BlueprintFieldType::integral_type(
                                                 (typename BlueprintFieldType::value_type(2).pow(64) - 1).data)));

        typename BlueprintFieldType::integral_type maj = (a & b) ^ (a & c) ^ (b & c);
        typename BlueprintFieldType::integral_type ch = (e & f) ^ ((~e) & g);
        typename BlueprintFieldType::integral_type tmp1 = h + S1 + ch + round_constant[i] + message_schedule_array[i];
        typename BlueprintFieldType::integral_type tmp2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = (d + tmp1)%
        typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(64).data);
        d = c;
        c = b;
        b = a;
        a = (tmp1 + tmp2)%
        typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(64).data);
    }
    std::array<typename BlueprintFieldType::integral_type, 8> result_state = {(a + typename ArithmetizationType::field_type::integral_type(public_input[0].data))%
        typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(64).data),
    (b + typename ArithmetizationType::field_type::integral_type(public_input[1].data))%
        typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(64).data),
    (c + typename ArithmetizationType::field_type::integral_type(public_input[2].data))%
        typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(64).data),
    (d + typename ArithmetizationType::field_type::integral_type(public_input[3].data))%
        typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(64).data),
    (e + typename ArithmetizationType::field_type::integral_type(public_input[4].data))%
        typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(64).data),
    (f + typename ArithmetizationType::field_type::integral_type(public_input[5].data))%
        typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(64).data),
    (g + typename ArithmetizationType::field_type::integral_type(public_input[6].data))%
        typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(64).data),
    (h + typename ArithmetizationType::field_type::integral_type(public_input[7].data))%
        typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(64).data)};
    auto result_check = [result_state](AssignmentType &assignment,
        component_type::result_type &real_res) {
            for (std::size_t i = 0; i < 8; i++) {
                assert(result_state[i] == typename ArithmetizationType::field_type::integral_type(var_value(assignment, real_res.output_state[i]).data));
            }
    };
    typename component_type::input_type instance_input = {input_state_var, input_words_var};

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8},{0},{});
    crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>(
        component_instance, desc, public_input, result_check, instance_input);
}

BOOST_AUTO_TEST_SUITE_END()