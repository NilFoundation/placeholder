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
#define BOOST_TEST_MODULE plonk_keccak_test
#include <array>
#include <boost/test/unit_test.hpp>
#include <cstdlib>
#include <ctime>
#include <random>
#include <nil/blueprint/bbf/circuit_builder.hpp>
#include <nil/blueprint/bbf/components/hashes/keccak/keccak_round.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>

const int r[5][5] = {{0, 36, 3, 41, 18},
                     {1, 44, 10, 45, 2},
                     {62, 6, 43, 15, 61},
                     {28, 55, 25, 21, 56},
                     {27, 20, 39, 8, 14}};
template<typename BlueprintFieldType>
typename BlueprintFieldType::value_type to_sparse(typename BlueprintFieldType::value_type value) {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    integral_type value_integral = integral_type(value.to_integral());
    integral_type result_integral = 0;
    integral_type power = 1;
    for (int i = 0; i < 64; ++i) {
        integral_type bit = value_integral & 1;
        result_integral = result_integral + bit * power;
        value_integral = value_integral >> 1;
        power = power << 3;
    }
    return value_type(result_integral);
}
template<typename BlueprintFieldType, bool xor_with_mes>
std::array<typename BlueprintFieldType::value_type, 25> sparse_round_function(
    std::array<typename BlueprintFieldType::value_type, 25> inner_state,
    std::array<typename BlueprintFieldType::value_type, 17> padded_message_chunk,
    typename BlueprintFieldType::value_type RC) {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    bool last_round_call = false;
    std::array<std::array<integral_type, 5>, 5> inner_state_integral;
    std::array<integral_type, 17> padded_message_chunk_integral;
    integral_type RC_integral = integral_type(RC.to_integral());
    for (int x = 0; x < 5; ++x) {
        for (int y = 0; y < 5; ++y) {
            inner_state_integral[x][y] =
                integral_type(inner_state[x + 5 * y].to_integral());
        }
    }
    for (int i = 0; i < 17; ++i) {
        padded_message_chunk_integral[i] =
            integral_type(padded_message_chunk[i].to_integral());
    }
    auto rot = [](integral_type x, const int s) {
        return ((x << (3 * s)) | (x >> (192 - 3 * s))) & ((integral_type(1) << 192) - 1);
    };
    if (xor_with_mes) {
        for (int x = 0; x < 5; ++x) {
            for (int y = 0; y < 5; ++y) {
                if (last_round_call && (x + 5 * y == 16)) {
                    continue;
                }
                if (x + 5 * y < 17) {
                    inner_state_integral[x][y] =
                        inner_state_integral[x][y] ^ padded_message_chunk_integral[x + 5 * y];
                }
            }
        }
        if (last_round_call) {
            value_type last_round_const =
                to_sparse<BlueprintFieldType>(value_type(0x8000000000000000));
            integral_type last_round_const_integral =
                integral_type(last_round_const.to_integral());
            inner_state_integral[1][3] = inner_state_integral[1][3] ^
                                         padded_message_chunk_integral[16] ^
                                         last_round_const_integral;
        }
    }
    // theta
    std::array<integral_type, 5> C;
    for (int x = 0; x < 5; ++x) {
        for (int y = 0; y < 5; ++y) {
            C[x] ^= inner_state_integral[x][y];
        }
    }
    std::array<integral_type, 5> D;
    for (int x = 0; x < 5; ++x) {
        D[x] = C[(x + 4) % 5] ^ rot(C[(x + 1) % 5], 1);
    }
    for (int x = 0; x < 5; ++x) {
        for (int y = 0; y < 5; ++y) {
            inner_state_integral[x][y] ^= D[x];
        }
    }
    // rho and pi
    std::array<std::array<integral_type, 5>, 5> B;
    for (int x = 0; x < 5; ++x) {
        for (int y = 0; y < 5; ++y) {
            B[y][(2 * x + 3 * y) % 5] = rot(inner_state_integral[x][y], r[x][y]);
        }
    }
    // chi
    for (int x = 0; x < 5; ++x) {
        for (int y = 0; y < 5; ++y) {
            inner_state_integral[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y]);
        }
    }
    // iota
    inner_state_integral[0][0] = inner_state_integral[0][0] ^ RC_integral;
    for (int x = 0; x < 5; ++x) {
        for (int y = 0; y < 5; ++y) {
            inner_state[x + 5 * y] = value_type(inner_state_integral[x][y]);
        }
    }
    return inner_state;
}
using namespace nil::crypto3;
using namespace nil::blueprint;
template<typename field_type>
void test_bbf_keccak_round(const std::array<typename field_type::value_type, 25> &inner_state,
                           const std::array<typename field_type::value_type, 17> &message_chunks,
                           typename field_type::value_type RC, bool xor_with_mes,
                           const std::array<typename field_type::value_type, 25> &expected_res) {

    typename bbf::keccak_round<field_type, bbf::GenerationStage::ASSIGNMENT>::input_type
        input = {inner_state, message_chunks, RC};
    auto B = bbf::circuit_builder<field_type, bbf::keccak_round, bool>(xor_with_mes);
    auto [at, A, desc] = B.assign(input);
    BOOST_TEST(B.is_satisfied(at), "constraints are not satisfied");
    for (std::size_t i = 0; i < 25; i++) {
        BOOST_CHECK(expected_res[i] == A.inner_state[i]);
    }
}
template<typename BlueprintFieldType, bool xor_with_mes>
void test_keccak_round_bbf_random() {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    std::array<value_type, 25> inner_state;
    std::array<value_type, 17> padded_message_chunk;
    value_type RC;
    integral_type mask = (integral_type(1) << 64) - 1;
    for (int i = 0; i < 25; ++i) {
        auto random_value = integral_type(dis(gen)) & mask;
        inner_state[i] = to_sparse<BlueprintFieldType>(value_type(random_value));
    }
    for (int i = 0; i < 17; ++i) {
        auto random_value = integral_type(dis(gen)) & mask;
        padded_message_chunk[i] = to_sparse<BlueprintFieldType>(value_type(random_value));
    }
    auto random_value = integral_type(dis(gen)) & mask;
    RC = to_sparse<BlueprintFieldType>(value_type(random_value));
    auto expected_result = sparse_round_function<BlueprintFieldType, xor_with_mes>(
        inner_state, padded_message_chunk, RC);
    test_bbf_keccak_round<BlueprintFieldType>(inner_state, padded_message_chunk, RC, xor_with_mes,
                                              expected_result);
}
BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)
BOOST_AUTO_TEST_CASE(blueprint_plonk_hashes_keccak_round_bbf_random_pallas) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;
    test_keccak_round_bbf_random<field_type, false>();
    test_keccak_round_bbf_random<field_type, true>();
}
BOOST_AUTO_TEST_CASE(blueprint_plonk_hashes_keccak_round_bbf_not_random_pallas) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;
    // round 0
    std::array<value_type, 25> state = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    std::array<value_type, 17> message = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    value_type rc;
    std::array<value_type, 25> expected_result;
    std::array<value_type, 24> round_constants = {value_type(1),
                                                  value_type(0x8082),
                                                  value_type(0x800000000000808A),
                                                  value_type(0x8000000080008000),
                                                  value_type(0x808B),
                                                  value_type(0x80000001),
                                                  value_type(0x8000000080008081),
                                                  value_type(0x8000000000008009),
                                                  value_type(0x8A),
                                                  value_type(0x88),
                                                  value_type(0x80008009),
                                                  value_type(0x8000000A),
                                                  value_type(0x8000808B),
                                                  value_type(0x800000000000008B),
                                                  value_type(0x8000000000008089),
                                                  value_type(0x8000000000008003),
                                                  value_type(0x8000000000008002),
                                                  value_type(0x8000000000000080),
                                                  value_type(0x800A),
                                                  value_type(0x800000008000000A),
                                                  value_type(0x8000000080008081),
                                                  value_type(0x8000000000008080),
                                                  value_type(80000001),
                                                  value_type(0x8000000080008008)};
    for (std::size_t i = 0; i < 24; i++) {
        rc = to_sparse<field_type>((round_constants[i]));
        expected_result = sparse_round_function<field_type, false>(state, message, rc);
        test_bbf_keccak_round<field_type>(state, message, rc, false, expected_result);
        state = expected_result;
    }
}
BOOST_AUTO_TEST_SUITE_END()
