//---------------------------------------------------------------------------//
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

#pragma once

#include <utility>

#include <nil/blueprint/bbf/components/hashes/keccak/keccak_round.hpp>
#include <nil/blueprint/bbf/components/hashes/keccak/util.hpp>
#include <nil/blueprint/bbf/generic.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            // Component for keccak table
            template<typename FieldType, GenerationStage stage>
            class keccak_dynamic : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;

              public:
                using typename generic_component<FieldType, stage>::TYPE;
                using typename generic_component<FieldType, stage>::table_params;
                using integral_type = typename FieldType::integral_type;
                using value_type = typename FieldType::value_type;
                using KECCAK_ROUND = typename bbf::keccak_round<FieldType, stage>;

                struct input_type {
                    TYPE rlc_challenge;

                    std::conditional_t<
                        stage == GenerationStage::ASSIGNMENT,
                        std::vector<std::tuple<
                            std::vector<std::uint8_t>,
                            std::pair<value_type, value_type>>>,
                        std::monostate
                    > input;
                };

                const std::size_t block_rows_amount = 6247;
                const std::size_t state_rows_amount = 5;
                const std::size_t chunks_rows_amount = 34;
                const std::size_t unsparser_rows_amount = 4;

                const integral_type sparse_x80 =
                    calculate_sparse(integral_type(0x8000000000000000)) >> 144;
                const integral_type sparse_x7f =
                    calculate_sparse(integral_type(0x8000000000000000 - 1)) >> 144;

                integral_type calculate_sparse(const integral_type &value) const {
                    integral_type result = 0;
                    integral_type power = 1;
                    integral_type val = value;
                    while (val > 0) {
                        result += (val & 1) * power;
                        power <<= 3;
                        val >>= 1;
                    }
                    return result;
                }

                const std::size_t round_constant[24] = {1,
                                                        0x8082,
                                                        0x800000000000808a,
                                                        0x8000000080008000,
                                                        0x808b,
                                                        0x80000001,
                                                        0x8000000080008081,
                                                        0x8000000000008009,
                                                        0x8a,
                                                        0x88,
                                                        0x80008009,
                                                        0x8000000a,
                                                        0x8000808b,
                                                        0x800000000000008b,
                                                        0x8000000000008089,
                                                        0x8000000000008003,
                                                        0x8000000000008002,
                                                        0x8000000000000080,
                                                        0x800a,
                                                        0x800000008000000a,
                                                        0x8000000080008081,
                                                        0x8000000000008080,
                                                        0x80000001,
                                                        0x8000000080008008};

                struct header_map {
                    TYPE hash_hi;
                    TYPE hash_lo;
                    TYPE RLC;
                    TYPE is_first;
                    TYPE is_last;
                    TYPE L;
                    TYPE l;
                    TYPE hash_cur_hi;
                    TYPE hash_cur_lo;
                    TYPE rlc_before;
                    TYPE rlc_after;
                    TYPE r;
                };

                struct state_map {
                    TYPE is_first;
                    TYPE s0;
                    TYPE s1;
                    TYPE s2;
                    TYPE s3;
                    TYPE s4;
                    TYPE S0;
                    TYPE S1;
                    TYPE S2;
                    TYPE S3;
                    TYPE S4;
                    TYPE rng;
                    TYPE XOR;
                    TYPE ch;
                    TYPE out;
                };

                struct chunks_map {
                    TYPE b0;
                    TYPE b1;
                    TYPE b2;
                    TYPE b3;
                    TYPE sp0;
                    TYPE sp1;
                    TYPE chunk;
                    TYPE l;
                    TYPE l_before;
                    TYPE rlc;
                    TYPE rlc_before;
                    TYPE r;
                    TYPE r2;
                    TYPE r4;
                    TYPE first_in_block;
                };

                struct unsparser_map {
                    TYPE SP;  // sparsed 64 bit round output
                    TYPE sp0;
                    TYPE sp1;
                    TYPE sp2;
                    TYPE sp3;  // 16-bit chunks for SP
                    TYPE ch0;
                    TYPE ch1;
                    TYPE ch2;
                    TYPE ch3;         // unpacked 16-bit chunks
                    TYPE hash_chunk;  // 64 bit final chunk -- used only in last block but
                                      // we compute it for all blocks
                };

                struct keccak_map {
                    header_map h;
                    header_map f;
                    state_map s[5];
                    chunks_map c[34];
                    unsparser_map u[4];
                };

                static table_params get_minimal_requirements(std::size_t max_blocks) {
                    constexpr std::size_t witness = 16;
                    constexpr std::size_t public_inputs = 1;
                    constexpr std::size_t constants = 1;
                    std::size_t rows = 6247 * max_blocks;
                    rows = rows < 72000 ? 72000 : rows;
                    return {witness, public_inputs, constants, rows};
                }

                static void allocate_public_inputs(
                        context_type &context_object, input_type &input, std::size_t max_blocks) {
                    context_object.allocate(input.rlc_challenge, 0, 0,
                                            column_type::public_input);
                }
                
                std::size_t max_blocks;
                std::vector<keccak_map> m = std::vector<keccak_map>(max_blocks);

                keccak_dynamic(context_type &context_object, input_type instance_input,
                               std::size_t max_blocks_, bool make_links = true)
                    : max_blocks(max_blocks_), generic_component<FieldType, stage>(context_object) {
                    using integral_type = typename FieldType::integral_type;
                    using value_type = typename FieldType::value_type;

                    std::size_t block_counter = 0;
                    std::size_t input_idx = 0;
                    std::size_t l;
                    std::size_t l_before;
                    std::size_t first_in_block;
                    TYPE rlc;
                    TYPE rlc_before;
                    TYPE RLC;
                    // constants

                    std::array<TYPE, 25> state;
                    std::vector<uint8_t> msg = std::vector<uint8_t>();
                    std::vector<uint8_t> padded_msg = std::vector<uint8_t>();
                    std::pair<TYPE, TYPE> hash;

                    TYPE C[26];
                    std::vector<TYPE> selector(6247 * max_blocks);

                    C[0] = value_type(0);
                    allocate(C[0], 0, 0, column_type::constant);
                    C[1] = value_type(1);
                    allocate(C[1], 0, 1, column_type::constant);
                    for (std::size_t i = 2; i < 26; i++) {
                        C[i] = value_type(
                            calculate_sparse(integral_type(round_constant[i - 2])));
                        allocate(C[i], 0, i, column_type::constant);
                    }

                    std::size_t row = 0;
                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        TYPE theta = instance_input.rlc_challenge;
                        // std::cout << "RLC challenge = " << theta << std::endl;

                        while (block_counter < max_blocks) {
                            if (input_idx < instance_input.input.size()) {
                                msg = std::get<0>(instance_input.input[input_idx]);
                                hash = std::get<1>(instance_input.input[input_idx]);
                                input_idx++;
                            } else {
                                msg = {};
                                hash = {
                                    TYPE(integral_type(
                                        0xc5d2460186f7233c927e7db2dcc703c0_big_uint256)),
                                    TYPE(integral_type(
                                        0xe500b653ca82273b7bfad8045d85a470_big_uint256))};
                            }

                            padded_msg = msg;
                            padded_msg.push_back(1);
                            while (padded_msg.size() % 136 != 0) {
                                padded_msg.push_back(0);
                            }
                            RLC = calculateRLC<FieldType>(msg, theta);
                            // std::cout << "RLC = " << std::hex << RLC << std::dec <<
                            // std::endl;

                            for (std::size_t block = 0; block < padded_msg.size() / 136;
                                 block++) {
                                l = msg.size() - block * 136;
                                bool is_first = (block == 0 ? 1 : 0);
                                bool is_last =
                                    ((block == padded_msg.size() / 136 - 1) ? 1 : 0);
                                // std::cout << "Is_last = " << is_last << std::endl;
                                if (is_first) rlc = msg.size();

                                m[block_counter].h.is_first = is_first;
                                m[block_counter].h.is_last = is_last;
                                m[block_counter].h.L = msg.size();
                                m[block_counter].h.l = msg.size() - block * 136;
                                m[block_counter].h.hash_hi = hash.first;
                                m[block_counter].h.hash_lo = hash.second;
                                m[block_counter].h.RLC = RLC;
                                m[block_counter].h.rlc_before = rlc;
                                m[block_counter].h.r = theta;

                                m[block_counter].f.is_first = is_first;
                                m[block_counter].f.is_last = is_last;
                                m[block_counter].f.L = msg.size();
                                m[block_counter].f.l = msg.size() - block * 136;
                                m[block_counter].f.hash_hi = hash.first;
                                m[block_counter].f.hash_lo = hash.second;
                                m[block_counter].f.RLC = RLC;
                                m[block_counter].f.r = theta;

                                selector[row] = 1;

                                for (std::size_t i = 0; i < state_rows_amount; i++) {
                                    m[block_counter].s[i].s0 = state[5 * i];
                                    m[block_counter].s[i].s1 = state[5 * i + 1];
                                    m[block_counter].s[i].s2 = state[5 * i + 2];
                                    m[block_counter].s[i].s3 = state[5 * i + 3];
                                    m[block_counter].s[i].s4 = state[5 * i + 4];

                                    m[block_counter].s[i].is_first = is_first;
                                    m[block_counter].s[i].S0 =
                                        is_first ? 0 : state[5 * i];
                                    m[block_counter].s[i].S1 =
                                        is_first ? 0 : state[5 * i + 1];
                                    m[block_counter].s[i].S2 =
                                        is_first ? 0 : state[5 * i + 2];
                                    m[block_counter].s[i].S3 =
                                        is_first ? 0 : state[5 * i + 3];
                                    m[block_counter].s[i].S4 =
                                        is_first ? 0 : state[5 * i + 4];
                                }

                                TYPE s16 = m[block_counter].s[3].S1;
                                std::array<TYPE, 4> s16_chunks =
                                    sparsed_64bits_to_4_chunks<FieldType>(s16);
                                TYPE mod = s16_chunks[0].to_integral() >= sparse_x80
                                               ? s16_chunks[0] - sparse_x80
                                               : sparse_x7f - s16_chunks[0];
                                TYPE XOR = s16_chunks[0].to_integral() >= sparse_x80
                                               ? s16_chunks[0] - sparse_x80
                                               : s16_chunks[0] + sparse_x80;

                                m[block_counter].s[0].rng = mod;
                                m[block_counter].s[1].rng = s16_chunks[0];
                                m[block_counter].s[2].rng = s16_chunks[1];
                                m[block_counter].s[3].rng = s16_chunks[2];
                                m[block_counter].s[4].rng = s16_chunks[3];

                                m[block_counter].s[0].XOR = XOR;
                                m[block_counter].s[1].XOR = is_last ? XOR : s16_chunks[0];
                                m[block_counter].s[2].XOR = s16_chunks[2];
                                m[block_counter].s[3].XOR = s16_chunks[0];
                                m[block_counter].s[4].XOR = s16_chunks[2];

                                m[block_counter].s[0].ch = is_last;
                                m[block_counter].s[1].ch = s16_chunks[1];
                                m[block_counter].s[2].ch = s16_chunks[3];
                                m[block_counter].s[3].ch = s16_chunks[1];
                                m[block_counter].s[4].ch = s16_chunks[3];

                                for (std::size_t i = 1; i < state_rows_amount; i++) {
                                    m[block_counter].s[i].out =
                                        m[block_counter].s[i - 1].XOR *
                                            (integral_type(1) << (48 * 3)) +
                                        m[block_counter].s[i - 1].ch *
                                            (integral_type(1) << (48 * 2)) +
                                        m[block_counter].s[i].XOR *
                                            (integral_type(1) << 48) +
                                        m[block_counter].s[i].ch;
                                }

                                for (std::size_t i = 0; i < chunks_rows_amount; i++) {
                                    first_in_block = (i == 0) ? 1 : 0;
                                    l_before = l;
                                    rlc_before = rlc;
                                    if (l > 4)
                                        l -= 4;
                                    else
                                        l = 0;

                                    std::size_t msg_idx = 136 * block + 4 * i;
                                    m[block_counter].c[i].r = theta;
                                    m[block_counter].c[i].b0 = padded_msg[msg_idx];
                                    m[block_counter].c[i].b1 = padded_msg[msg_idx + 1];
                                    m[block_counter].c[i].b2 = padded_msg[msg_idx + 2];
                                    m[block_counter].c[i].b3 = padded_msg[msg_idx + 3];

                                    auto sp0 = pack<FieldType>(
                                        integral_type(padded_msg[msg_idx + 1]) * 256 +
                                        integral_type(padded_msg[msg_idx]));
                                    auto sp1 = pack<FieldType>(
                                        integral_type(padded_msg[msg_idx + 3]) * 256 +
                                        integral_type(padded_msg[msg_idx + 2]));
                                    TYPE sp0_prev =
                                        (i > 0) ? m[block_counter].c[i - 1].sp0 : 0;
                                    TYPE sp1_prev =
                                        (i > 0) ? m[block_counter].c[i - 1].sp1 : 0;
                                    m[block_counter].c[i].sp0 = sp0;
                                    m[block_counter].c[i].sp1 = sp1;

                                    TYPE chunk_factor = TYPE(integral_type(1) << 48);
                                    TYPE chunk = sp1 * chunk_factor + sp0;
                                    chunk = chunk * chunk_factor + sp1_prev;
                                    chunk = chunk * chunk_factor + sp0_prev;

                                    m[block_counter].c[i].chunk = chunk;
                                    m[block_counter].c[i].first_in_block = first_in_block;
                                    m[block_counter].c[i].l = l;
                                    m[block_counter].c[i].l_before = l_before;
                                    m[block_counter].c[i].rlc_before = rlc_before;
                                    m[block_counter].c[i].r2 = theta * theta;
                                    m[block_counter].c[i].r4 =
                                        theta * theta * theta * theta;

                                    if (l_before - l == 4)
                                        rlc = rlc_before * theta * theta * theta * theta +
                                              msg[msg_idx] * theta * theta * theta +
                                              msg[msg_idx + 1] * theta * theta +
                                              msg[msg_idx + 2] * theta + msg[msg_idx + 3];
                                    else if (l_before - l == 3)
                                        rlc = rlc_before * theta * theta * theta +
                                              msg[msg_idx] * theta * theta +
                                              msg[msg_idx + 1] * theta + msg[msg_idx + 2];
                                    else if (l_before - l == 2)
                                        rlc = rlc_before * theta * theta +
                                              msg[msg_idx] * theta + msg[msg_idx + 1];
                                    else if (l_before - l == 1)
                                        rlc = rlc_before * theta + msg[msg_idx];
                                    else
                                        rlc = rlc_before;

                                    m[block_counter].c[i].rlc = rlc;
                                    // std::cout << std::hex <<
                                    // std::size_t(padded_msg[msg_idx])
                                    //           << ", " << std::size_t(padded_msg[msg_idx
                                    //           + 1])
                                    //           << ", " << std::size_t(padded_msg[msg_idx
                                    //           + 2])
                                    //           << ", " << std::size_t(padded_msg[msg_idx
                                    //           + 3])
                                    //           << std::dec << "  l=" << l
                                    //           << "  l_before=" << l_before << std::hex
                                    //           << "  rlc=" << rlc << "  rlc_before=" <<
                                    //           rlc_before
                                    //           << std::dec << " first_in_block = " <<
                                    //           first_in_block
                                    //           << std::endl;
                                }

                                m[block_counter].h.rlc_after = rlc;
                                m[block_counter].f.rlc_before = rlc;

                                std::array<TYPE, 25> inner_state;
                                for (std::size_t i = 0; i < 5; i++) {
                                    inner_state[5 * i] = m[block_counter].s[i].S0;
                                    inner_state[5 * i + 1] = m[block_counter].s[i].S1;
                                    inner_state[5 * i + 2] = m[block_counter].s[i].S2;
                                    inner_state[5 * i + 3] = m[block_counter].s[i].S3;
                                    inner_state[5 * i + 4] = m[block_counter].s[i].S4;
                                }
                                inner_state[16] = m[block_counter].s[2].out;

                                std::size_t offset = 0;
                                std::array<TYPE, 17> pmc;
                                for (std::size_t i = 0; i < 17; i++) {
                                    pmc[i] = m[block_counter].c[2 * i + 1].chunk;
                                }

                                row += 40;
                                for (std::size_t j = 0; j < 24; ++j) {
                                    typename KECCAK_ROUND::input_type round_input = {
                                        inner_state, pmc, C[j + 2]};

                                    if (j == 0) {
                                        context_type ct = context_object.subcontext(
                                            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
                                             14},
                                            row, row + 291);
                                        auto round_tf =
                                            KECCAK_ROUND(ct, round_input, true);
                                        for (std::size_t k = 0; k < 25; k++)
                                            inner_state[k] = round_tf.inner_state[k];
                                        row += 291;
                                    } else {
                                        context_type ct = context_object.subcontext(
                                            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
                                             14},
                                            row, row + 257);
                                        auto round_ff =
                                            KECCAK_ROUND(ct, round_input, false, false);
                                        for (std::size_t k = 0; k < 25; k++)
                                            inner_state[k] = round_ff.inner_state[k];
                                        row += 257;
                                    }
                                }

                                for (std::size_t i = 0; i < 25; i++) {
                                    state[i] = inner_state[i];
                                }

                                // std::cout << "Sparse hash chunks : " << std::endl;
                                std::array<TYPE, 4> result;
                                for (std::size_t i = 0; i < 4; i++) {
                                    TYPE sparse_value = inner_state[i];
                                    result[i] = sparse_value;
                                    // std::cout << "\t" << std::hex << sparse_value <<
                                    // std::dec << std::endl;
                                    TYPE regular = unpack<FieldType>(sparse_value);
                                    std::cout << "\t" << std::hex << regular << std::dec
                                              << " ";
                                }
                                std::cout << std::endl;

                                integral_type chunk_factor = integral_type(1) << 16;
                                for (std::size_t i = 0; i < unsparser_rows_amount; i++) {
                                    auto chunks =
                                        sparsed_64bits_to_4_chunks<FieldType>(result[i]);
                                    m[block_counter].u[i].SP = result[i];
                                    m[block_counter].u[i].sp0 = chunks[0];
                                    m[block_counter].u[i].sp1 = chunks[1];
                                    m[block_counter].u[i].sp2 = chunks[2];
                                    m[block_counter].u[i].sp3 = chunks[3];
                                    m[block_counter].u[i].ch0 = swap_bytes<FieldType>(
                                        unpack<FieldType>(chunks[0]));
                                    m[block_counter].u[i].ch1 = swap_bytes<FieldType>(
                                        unpack<FieldType>(chunks[1]));
                                    m[block_counter].u[i].ch2 = swap_bytes<FieldType>(
                                        unpack<FieldType>(chunks[2]));
                                    m[block_counter].u[i].ch3 = swap_bytes<FieldType>(
                                        unpack<FieldType>(chunks[3]));
                                    if (i == 0) {
                                        m[block_counter].u[i].hash_chunk =
                                            m[block_counter].u[i].ch3 *
                                                (chunk_factor << (16 * 2)) +
                                            m[block_counter].u[i].ch2 *
                                                (chunk_factor << (16)) +
                                            m[block_counter].u[i].ch1 * chunk_factor +
                                            m[block_counter].u[i].ch0;
                                    } else {
                                        m[block_counter].u[i].hash_chunk =
                                            m[block_counter].u[i - 1].ch3 *
                                                (chunk_factor << (16 * 6)) +
                                            m[block_counter].u[i - 1].ch2 *
                                                (chunk_factor << (16 * 5)) +
                                            m[block_counter].u[i - 1].ch1 *
                                                (chunk_factor << (16 * 4)) +
                                            m[block_counter].u[i - 1].ch0 *
                                                (chunk_factor << (16 * 3)) +
                                            m[block_counter].u[i].ch3 *
                                                (chunk_factor << (16 * 2)) +
                                            m[block_counter].u[i].ch2 *
                                                (chunk_factor << (16)) +
                                            m[block_counter].u[i].ch1 * chunk_factor +
                                            m[block_counter].u[i].ch0;
                                    }
                                }
                                m[block_counter].h.hash_cur_hi =
                                    m[block_counter].u[1].hash_chunk;
                                m[block_counter].h.hash_cur_lo =
                                    m[block_counter].u[3].hash_chunk;

                                // if (is_last) {
                                //     std::cout << "Previous hash: " << std::hex
                                //               << m[block_counter].h.hash_hi << " "
                                //               << m[block_counter].h.hash_lo << " " <<
                                //               std::endl;
                                //     std::cout << "Current hash: " << std::hex
                                //               << m[block_counter].h.hash_cur_hi << " "
                                //               << m[block_counter].h.hash_cur_lo << " "
                                //               << std::endl;
                                //     std::cout << "Final hash: " << std::hex
                                //               << m[block_counter].u[1].hash_chunk << "
                                //               "
                                //               << m[block_counter].u[3].hash_chunk <<
                                //               std::dec
                                //               << std::endl;
                                // }
                                row += 5;
                                block_counter++;
                            }
                        }
                    }

                    row = 0;
                    std::array<TYPE, 25> inner_state;
                    std::fill(inner_state.begin(), inner_state.end(), C[0]);
                    for (std::size_t i = 0; i < 6247 * max_blocks; i++) {
                        allocate(selector[i], 15, i);
                    }
                    for (std::size_t block_counter = 0; block_counter < max_blocks;
                         block_counter++) {
                        allocate(m[block_counter].h.L, 0, row);
                        allocate(m[block_counter].h.RLC, 1, row);
                        allocate(m[block_counter].h.hash_hi, 2, row);
                        allocate(m[block_counter].h.hash_lo, 3, row);
                        allocate(m[block_counter].h.rlc_before, 4, row);
                        allocate(m[block_counter].h.rlc_after, 5, row);
                        allocate(m[block_counter].h.l, 6, row);
                        allocate(m[block_counter].h.hash_cur_hi, 7, row);
                        allocate(m[block_counter].h.hash_cur_lo, 8, row);
                        allocate(m[block_counter].h.is_last, 9, row);
                        allocate(m[block_counter].h.is_first, 10, row);
                        allocate(m[block_counter].h.r, 14, row);

                        row++;
                        for (std::size_t i = 0; i < state_rows_amount; i++) {
                            allocate(m[block_counter].s[i].s0, 0, row);
                            allocate(m[block_counter].s[i].s1, 1, row);
                            allocate(m[block_counter].s[i].s2, 2, row);
                            allocate(m[block_counter].s[i].s3, 3, row);
                            allocate(m[block_counter].s[i].s4, 4, row);
                            allocate(m[block_counter].s[i].S0, 5, row);
                            allocate(m[block_counter].s[i].S1, 6, row);
                            allocate(m[block_counter].s[i].S2, 7, row);
                            allocate(m[block_counter].s[i].S3, 8, row);
                            allocate(m[block_counter].s[i].S4, 9, row);
                            allocate(m[block_counter].s[i].is_first, 10, row);
                            allocate(m[block_counter].s[i].rng, 11, row);
                            allocate(m[block_counter].s[i].XOR, 12, row);
                            allocate(m[block_counter].s[i].ch, 13, row);
                            allocate(m[block_counter].s[i].out, 14, row);
                            row++;
                        }

                        for (std::size_t i = 0; i < chunks_rows_amount; i++) {
                            allocate(m[block_counter].c[i].b0, 0, row);
                            allocate(m[block_counter].c[i].b1, 1, row);
                            allocate(m[block_counter].c[i].b2, 2, row);
                            allocate(m[block_counter].c[i].b3, 3, row);
                            allocate(m[block_counter].c[i].sp0, 4, row);
                            allocate(m[block_counter].c[i].sp1, 5, row);
                            allocate(m[block_counter].c[i].chunk, 6, row);
                            allocate(m[block_counter].c[i].l, 7, row);
                            allocate(m[block_counter].c[i].l_before, 8, row);
                            allocate(m[block_counter].c[i].rlc, 9, row);
                            allocate(m[block_counter].c[i].rlc_before, 10, row);
                            allocate(m[block_counter].c[i].r2, 11, row);
                            allocate(m[block_counter].c[i].r4, 12, row);
                            allocate(m[block_counter].c[i].first_in_block, 13, row);
                            allocate(m[block_counter].c[i].r, 14, row);
                            row++;
                        }

                        size_t old_row = row;
                        if (stage == GenerationStage::CONSTRAINTS) {
                            for (std::size_t i = 0; i < 5; i++) {
                                // ST2
                                copy_constrain(inner_state[5 * i],
                                               m[block_counter].s[i].s0);
                                copy_constrain(inner_state[5 * i + 1],
                                               m[block_counter].s[i].s1);
                                copy_constrain(inner_state[5 * i + 2],
                                               m[block_counter].s[i].s2);
                                copy_constrain(inner_state[5 * i + 3],
                                               m[block_counter].s[i].s3);
                                copy_constrain(inner_state[5 * i + 4],
                                               m[block_counter].s[i].s4);
                            }
                            std::array<TYPE, 17> pmc;
                            for (std::size_t i = 0; i < 17; i++) {
                                pmc[i] = m[block_counter].c[2 * i + 1].chunk;
                            }

                            for (std::size_t i = 0; i < 5; i++) {
                                inner_state[5 * i] = m[block_counter].s[i].S0;
                                inner_state[5 * i + 1] = m[block_counter].s[i].S1;
                                inner_state[5 * i + 2] = m[block_counter].s[i].S2;
                                inner_state[5 * i + 3] = m[block_counter].s[i].S3;
                                inner_state[5 * i + 4] = m[block_counter].s[i].S4;
                            }
                            inner_state[16] = m[block_counter].s[2].out;

                            for (std::size_t j = 0; j < 24; ++j) {
                                typename KECCAK_ROUND::input_type round_input = {
                                    inner_state, pmc, C[j + 2]};

                                if (j == 0) {
                                    context_type ct = context_object.subcontext(
                                        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
                                         14},
                                        row, row + 291);
                                    auto round_tf = KECCAK_ROUND(ct, round_input, true);
                                    for (std::size_t k = 0; k < 25; k++)
                                        inner_state[k] = round_tf.inner_state[k];
                                    row += 291;
                                } else {
                                    context_type ct = context_object.subcontext(
                                        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
                                         14},
                                        row, row + 257);
                                    auto round_ff = KECCAK_ROUND(ct, round_input, false);
                                    for (std::size_t k = 0; k < 25; k++)
                                        inner_state[k] = round_ff.inner_state[k];
                                    row += 257;
                                }
                            }
                        }

                        if (row == old_row)
                            row += 6202;  // 6202 = 291 + 23*257 total round rows

                        for (std::size_t i = 0; i < unsparser_rows_amount; i++) {
                            allocate(m[block_counter].u[i].SP, 0, row);
                            allocate(m[block_counter].u[i].sp0, 1, row);
                            allocate(m[block_counter].u[i].sp1, 2, row);
                            allocate(m[block_counter].u[i].sp2, 3, row);
                            allocate(m[block_counter].u[i].sp3, 4, row);
                            allocate(m[block_counter].u[i].ch0, 5, row);
                            allocate(m[block_counter].u[i].ch1, 6, row);
                            allocate(m[block_counter].u[i].ch2, 7, row);
                            allocate(m[block_counter].u[i].ch3, 8, row);
                            allocate(m[block_counter].u[i].hash_chunk, 9, row);
                            row++;

                            if (stage == GenerationStage::CONSTRAINTS) {
                                copy_constrain(m[block_counter].u[i].SP,
                                               inner_state[i]);  // UN1
                            }
                        }

                        allocate(m[block_counter].f.L, 0, row);
                        allocate(m[block_counter].f.RLC, 1, row);
                        allocate(m[block_counter].f.hash_hi, 2, row);
                        allocate(m[block_counter].f.hash_lo, 3, row);
                        allocate(m[block_counter].f.rlc_before, 4, row);
                        allocate(m[block_counter].f.rlc_after, 5, row);
                        allocate(m[block_counter].f.l, 6, row);
                        allocate(m[block_counter].f.hash_cur_hi, 7, row);
                        allocate(m[block_counter].f.hash_cur_lo, 8, row);
                        allocate(m[block_counter].f.is_last, 9, row);
                        allocate(m[block_counter].f.is_first, 10, row);
                        allocate(m[block_counter].f.r, 14, row);
                        row++;
                    }

                    // gates:
                    for (std::size_t i = 0; i < 6247 * max_blocks; i++) {
                        constrain(selector[i] * (1 - selector[i]), "KECCAK_DYNAMIC_SELECTOR");
                    }
                    for (std::size_t block_counter = 0; block_counter < max_blocks;
                         block_counter++) {
                        // Is_first and is_last definition
                        constrain(m[block_counter].h.is_first *
                                  (m[block_counter].h.is_first - 1), "HF1");  // HF1
                        constrain(m[block_counter].h.is_last *
                                  (m[block_counter].h.is_last - 1), "HF2");  // HF2
                        constrain(m[block_counter].h.is_first *
                                  (m[block_counter].h.L - m[block_counter].h.l), "HF3");  // HF3
                        lookup(m[block_counter].h.is_last * m[block_counter].h.l,  // HF4
                               "keccak_pack_table/range_check_135");

                        // Hash computation correctness
                        constrain(m[block_counter].h.is_last *
                                  (m[block_counter].h.hash_hi -
                                   m[block_counter].h.hash_cur_hi), "HF5");  // HF5
                        constrain(m[block_counter].h.is_last *
                                  (m[block_counter].h.hash_lo -
                                   m[block_counter].h.hash_cur_lo), "HF6");  // HF6

                        // RLC computation correctness
                        constrain(m[block_counter].h.is_first *
                                  (m[block_counter].h.rlc_before -
                                   m[block_counter].h.L), "HF7");  // HF7
                        constrain(m[block_counter].h.is_last *
                                  (m[block_counter].h.rlc_after -
                                   m[block_counter].h.RLC), "HF8");  // HF8

                        // copy constraint r with public input
                        if (make_links) {
                            copy_constrain(instance_input.rlc_challenge,
                                           m[block_counter].h.r);  // HF9
                        }

                        // BT3
                        copy_constrain(m[block_counter].h.is_first,
                                       m[block_counter].f.is_first);
                        copy_constrain(m[block_counter].h.is_last,
                                       m[block_counter].f.is_last);
                        copy_constrain(m[block_counter].h.L, m[block_counter].f.L);
                        copy_constrain(m[block_counter].h.l, m[block_counter].f.l);
                        copy_constrain(m[block_counter].h.hash_hi,
                                       m[block_counter].f.hash_hi);
                        copy_constrain(m[block_counter].h.hash_lo,
                                       m[block_counter].f.hash_lo);
                        copy_constrain(m[block_counter].h.RLC, m[block_counter].f.RLC);
                        copy_constrain(m[block_counter].h.r, m[block_counter].f.r);

                        constrain((1 - m[0].h.is_first), "BT1");  // BT1
                        lookup(m[block_counter].h.L,
                               "keccak_pack_table/range_check_16bit");
                        lookup(m[block_counter].h.l,
                               "keccak_pack_table/range_check_16bit");
                        if (block_counter > 0) {
                            constrain((1 - m[block_counter - 1].f.is_last) *
                                      m[block_counter].h.is_first, "BT2");  // BT2
                            // Transition between blocks
                            constrain((1 - m[block_counter].h.is_first) *
                                      (m[block_counter].h.L -
                                       m[block_counter - 1].f.L), "BT4");  // BT4
                            constrain((1 - m[block_counter].h.is_first) *
                                      (m[block_counter].h.RLC -
                                       m[block_counter - 1].f.RLC), "BT5");  // BT5
                            constrain((1 - m[block_counter].h.is_first) *
                                      (m[block_counter].h.hash_hi -
                                       m[block_counter - 1].f.hash_hi), "BT6");  // BT6
                            constrain((1 - m[block_counter].h.is_first) *
                                      (m[block_counter].h.hash_lo -
                                       m[block_counter - 1].f.hash_lo), "BT7");  // BT7
                            constrain((1 - m[block_counter].h.is_first) *
                                      (m[block_counter].h.rlc_before -
                                       m[block_counter - 1].f.rlc_before), "BT8");  // BT8
                            constrain((1 - m[block_counter].h.is_first) *
                                      (1 - m[block_counter].h.is_last) *
                                      (m[block_counter - 1].f.l - m[block_counter].h.l -
                                       136), "BT9");  // BT9
                        }

                        copy_constrain(m[block_counter].s[3].S1,
                                       m[block_counter].s[4].out);  // ST11
                        copy_constrain(m[block_counter].s[0].ch,
                                       m[block_counter].h.is_last);  // ST8
                        // ST12
                        copy_constrain(m[block_counter].s[2].rng,
                                       m[block_counter].s[1].ch);
                        copy_constrain(m[block_counter].s[3].rng,
                                       m[block_counter].s[2].XOR);
                        copy_constrain(m[block_counter].s[4].rng,
                                       m[block_counter].s[2].ch);

                        // ST10
                        copy_constrain(m[block_counter].s[1].rng,
                                       m[block_counter].s[3].XOR);
                        copy_constrain(m[block_counter].s[2].rng,
                                       m[block_counter].s[3].ch);
                        copy_constrain(m[block_counter].s[3].rng,
                                       m[block_counter].s[4].XOR);
                        copy_constrain(m[block_counter].s[4].rng,
                                       m[block_counter].s[4].ch);

                        // State transitions
                        for (std::size_t i = 0; i < state_rows_amount; i++) {
                            constrain(m[block_counter].s[i].S0 -
                                      (1 - m[block_counter].s[i].is_first) *
                                          m[block_counter].s[i].s0, "ST3");  // ST3
                            constrain(m[block_counter].s[i].S1 -
                                      (1 - m[block_counter].s[i].is_first) *
                                          m[block_counter].s[i].s1, "ST4");  // ST4
                            constrain(m[block_counter].s[i].S2 -
                                      (1 - m[block_counter].s[i].is_first) *
                                          m[block_counter].s[i].s2, "ST5");  // ST5
                            constrain(m[block_counter].s[i].S3 -
                                      (1 - m[block_counter].s[i].is_first) *
                                          m[block_counter].s[i].s3, "ST6");  // ST6
                            constrain(m[block_counter].s[i].S4 -
                                      (1 - m[block_counter].s[i].is_first) *
                                          m[block_counter].s[i].s4, "ST7");  // ST7
                            if (i > 0) {
                                constrain(m[block_counter].s[i].is_first -
                                          m[block_counter].s[i - 1].is_first, "ST1");  // ST1
                                constrain(m[block_counter].s[i].out -
                                          m[block_counter].s[i - 1].XOR *
                                              (integral_type(1) << (48 * 3)) -
                                          m[block_counter].s[i - 1].ch *
                                              (integral_type(1) << (48 * 2)) -
                                          m[block_counter].s[i].XOR *
                                              (integral_type(1) << (48)) -
                                          m[block_counter].s[i].ch, "ST9");  // ST9
                            }
                            // lookup constraint s.rng at keccak_pack_table/sparse_16bit
                            lookup(m[block_counter].s[i].rng,
                                   "keccak_pack_table/sparse_16bit");  // ST8
                        }
                        // XOR constraints
                        constrain((m[block_counter].s[1].rng - sparse_x80 -
                                   m[block_counter].s[0].rng) *
                                  (m[block_counter].s[0].rng - sparse_x7f +
                                   m[block_counter].s[1].rng), "XOR1");  // XOR1
                        constrain((m[block_counter].s[1].rng - sparse_x7f +
                                   m[block_counter].s[0].rng) *
                                  (m[block_counter].s[0].XOR + sparse_x80 -
                                   m[block_counter].s[1].rng), "XOR2");  // XOR2
                        constrain((m[block_counter].s[1].rng - sparse_x80 -
                                   m[block_counter].s[0].rng) *
                                  (m[block_counter].s[0].XOR - sparse_x80 -
                                   m[block_counter].s[1].rng), "XOR3");  // XOR3
                        constrain((m[block_counter].s[1].XOR -
                                   m[block_counter].s[0].ch * m[block_counter].s[0].XOR -
                                   (1 - m[block_counter].s[0].ch) *
                                       m[block_counter].s[1].rng), "XOR4");  // XOR4

                        // Chunk constraints
                        TYPE chunk_factor = TYPE(integral_type(1) << 48);

                        copy_constrain(m[block_counter].c[0].l_before,
                                       m[block_counter].h.l);  // LC2
                        copy_constrain(m[block_counter].c[0].rlc_before,
                                       m[block_counter].h.rlc_before);  // RLC1
                        copy_constrain(m[block_counter].c[chunks_rows_amount - 1].rlc,
                                       m[block_counter].h.rlc_after);  // RLC2
                        for (std::size_t i = 0; i < chunks_rows_amount; i++) {
                            if (make_links) {
                                copy_constrain(instance_input.rlc_challenge,
                                               m[block_counter].c[i].r);  // RLC3
                            }

                            auto diff =
                                m[block_counter].c[i].l_before - m[block_counter].c[i].l;
                            constrain(diff * (diff - 1) * (diff - 2) * (diff - 3) *
                                      (diff - 4), "LC4");  // LC4
                            constrain(diff * (diff - 1) * (diff - 2) * (diff - 4) *
                                      (m[block_counter].c[i].b3 - 1), "PC1");  // PC1
                            constrain(diff * (diff - 1) * (diff - 3) * (diff - 4) *
                                      (m[block_counter].c[i].b2 - 1), "PC2");  // PC2
                            constrain(diff * (diff - 1) * (diff - 3) * (diff - 4) *
                                      m[block_counter].c[i].b3, "PC3");  // PC3
                            constrain(diff * (diff - 2) * (diff - 3) * (diff - 4) *
                                      (m[block_counter].c[i].b1 - 1), "PC4");  // PC4
                            constrain(diff * (diff - 2) * (diff - 3) * (diff - 4) *
                                      m[block_counter].c[i].b2, "PC5");  // PC5
                            constrain(diff * (diff - 2) * (diff - 3) * (diff - 4) *
                                      m[block_counter].c[i].b3, "PC6");  // PC6
                            constrain(m[block_counter].c[i].first_in_block * (diff - 1) *
                                      (diff - 2) * (diff - 3) * (diff - 4) *
                                      (m[block_counter].c[i].b0 - 1), "PC11");  // PC11
                            constrain(m[block_counter].c[i].first_in_block * (diff - 1) *
                                      (diff - 2) * (diff - 3) * (diff - 4) *
                                      m[block_counter].c[i].b1, "PC12");  // PC12
                            constrain(m[block_counter].c[i].first_in_block * (diff - 1) *
                                      (diff - 2) * (diff - 3) * (diff - 4) *
                                      m[block_counter].c[i].b2, "PC13");  // PC13
                            constrain(m[block_counter].c[i].first_in_block * (diff - 1) *
                                      (diff - 2) * (diff - 3) * (diff - 4) *
                                      m[block_counter].c[i].b3, "PC14");  // PC14
                            if (i > 0) {
                                copy_constrain(m[block_counter].c[i].first_in_block,
                                               C[0]);  // LC1

                                constrain(m[block_counter].c[i].chunk -
                                          m[block_counter].c[i].sp1 * chunk_factor *
                                              chunk_factor * chunk_factor -
                                          m[block_counter].c[i].sp0 * chunk_factor *
                                              chunk_factor -
                                          m[block_counter].c[i - 1].sp1 * chunk_factor -
                                          m[block_counter].c[i - 1].sp0, "CH7");  // CH7

                                auto diff_prev = m[block_counter].c[i - 1].l_before -
                                                 m[block_counter].c[i - 1].l;
                                constrain((1 - m[block_counter].c[i].first_in_block) *
                                          (m[block_counter].c[i].l_before -
                                           m[block_counter].c[i - 1].l), "LC3");  // LC3
                                constrain((1 - m[block_counter].c[i].first_in_block) *
                                          diff * (diff_prev - 4), "LC5");  // LC5
                                constrain((1 - m[block_counter].c[i].first_in_block) *
                                          (diff_prev - diff) * (diff_prev - diff - 1) *
                                          (diff_prev - diff - 2) *
                                          (diff_prev - diff - 3) *
                                          (m[block_counter].c[i].b0 - 1), "PC7");  // PC7
                                constrain((1 - m[block_counter].c[i].first_in_block) *
                                          (diff_prev - diff) * (diff_prev - diff - 1) *
                                          (diff_prev - diff - 2) *
                                          (diff_prev - diff - 3) *
                                          m[block_counter].c[i].b1, "PC8");  // PC8
                                constrain((1 - m[block_counter].c[i].first_in_block) *
                                          (diff_prev - diff) * (diff_prev - diff - 1) *
                                          (diff_prev - diff - 2) *
                                          (diff_prev - diff - 3) *
                                          m[block_counter].c[i].b2, "PC9");  // PC9
                                constrain((1 - m[block_counter].c[i].first_in_block) *
                                          (diff_prev - diff) * (diff_prev - diff - 1) *
                                          (diff_prev - diff - 2) *
                                          (diff_prev - diff - 3) *
                                          m[block_counter].c[i].b3, "PC10");  // PC10

                                constrain((1 - m[block_counter].c[i].first_in_block) *
                                          (m[block_counter].c[i].rlc_before -
                                           m[block_counter].c[i - 1].rlc), "RLC6");  // RLC6
                            } else {
                                copy_constrain(m[block_counter].c[i].first_in_block,
                                               C[1]);  // LC1
                            }

                            lookup(m[block_counter].c[i].b0,
                                   "keccak_pack_table/range_check");  // CH1
                            lookup(m[block_counter].c[i].b1,
                                   "keccak_pack_table/range_check");  // CH2
                            lookup(m[block_counter].c[i].b2,
                                   "keccak_pack_table/range_check");  // CH3
                            lookup(m[block_counter].c[i].b3,
                                   "keccak_pack_table/range_check");  // CH4
                            lookup({m[block_counter].c[i].b1 * 256 +
                                        m[block_counter].c[i].b0,
                                    m[block_counter].c[i].sp0},
                                   "keccak_pack_table/extended");  // CH5
                            lookup({m[block_counter].c[i].b3 * 256 +
                                        m[block_counter].c[i].b2,
                                    m[block_counter].c[i].sp1},
                                   "keccak_pack_table/extended");  // CH6

                            constrain(m[block_counter].c[i].r2 -
                                      m[block_counter].c[i].r *
                                          m[block_counter].c[i].r, "RLC4");  // RLC4
                            constrain(m[block_counter].c[i].r4 -
                                      m[block_counter].c[i].r2 *
                                          m[block_counter].c[i].r2, "RLC5");  // RLC5
                            constrain(
                                diff * (diff - 1) * (diff - 2) * (diff - 3) *
                                (m[block_counter].c[i].rlc -
                                 m[block_counter].c[i].r4 *
                                     m[block_counter].c[i].rlc_before -
                                 m[block_counter].c[i].r2 * m[block_counter].c[i].r *
                                     m[block_counter].c[i].b0 -
                                 m[block_counter].c[i].r2 * m[block_counter].c[i].b1 -
                                 m[block_counter].c[i].r * m[block_counter].c[i].b2 -
                                 m[block_counter].c[i].b3), "RLC7");  // RLC7

                            constrain(
                                diff * (diff - 1) * (diff - 2) * (diff - 4) *
                                (m[block_counter].c[i].rlc -
                                 m[block_counter].c[i].r2 * m[block_counter].c[i].r *
                                     m[block_counter].c[i].rlc_before -
                                 m[block_counter].c[i].r2 * m[block_counter].c[i].b0 -
                                 m[block_counter].c[i].r * m[block_counter].c[i].b1 -
                                 m[block_counter].c[i].b2), "RLC8");  // RLC8

                            constrain(
                                diff * (diff - 1) * (diff - 3) * (diff - 4) *
                                (m[block_counter].c[i].rlc -
                                 m[block_counter].c[i].r2 *
                                     m[block_counter].c[i].rlc_before -
                                 m[block_counter].c[i].r * m[block_counter].c[i].b0 -
                                 m[block_counter].c[i].b1), "RLC9");  // RLC9

                            constrain(diff * (diff - 2) * (diff - 3) * (diff - 4) *
                                      (m[block_counter].c[i].rlc -
                                       m[block_counter].c[i].r *
                                           m[block_counter].c[i].rlc_before -
                                       m[block_counter].c[i].b0), "RLC10");  // RLC10

                            constrain((diff - 1) * (diff - 2) * (diff - 3) * (diff - 4) *
                                      (m[block_counter].c[i].rlc -
                                       m[block_counter].c[i].rlc_before), "RLC11");  // RLC11
                        }

                        // Unparser constraints
                        copy_constrain(m[block_counter].h.hash_cur_hi,
                                       m[block_counter].u[1].hash_chunk);  // UN8
                        copy_constrain(m[block_counter].h.hash_cur_lo,
                                       m[block_counter].u[3].hash_chunk);  // UN8
                        integral_type sparsed_factor = (integral_type(1) << 48);
                        integral_type ufactor = (integral_type(1) << 16);
                        for (std::size_t i = 0; i < unsparser_rows_amount; i++) {
                            constrain(m[block_counter].u[i].SP -
                                      m[block_counter].u[i].sp0 * (sparsed_factor << 96) -
                                      m[block_counter].u[i].sp1 * (sparsed_factor << 48) -
                                      m[block_counter].u[i].sp2 * sparsed_factor -
                                      m[block_counter].u[i].sp3, "UN2");  // UN2
                            if (i > 0) {
                                constrain(m[block_counter].u[i].hash_chunk -
                                          m[block_counter].u[i - 1].ch3 *
                                              (ufactor << (16 * 6)) -
                                          m[block_counter].u[i - 1].ch2 *
                                              (ufactor << (16 * 5)) -
                                          m[block_counter].u[i - 1].ch1 *
                                              (ufactor << (16 * 4)) -
                                          m[block_counter].u[i - 1].ch0 *
                                              (ufactor << (16 * 3)) -
                                          m[block_counter].u[i].ch3 *
                                              (ufactor << (16 * 2)) -
                                          m[block_counter].u[i].ch2 * (ufactor << (16)) -
                                          m[block_counter].u[i].ch1 * ufactor -
                                          m[block_counter].u[i].ch0, "UN7");  // UN7
                            }
                            lookup({m[block_counter].u[i].ch0,
                                    m[block_counter].u[i].sp0},  // UN3
                                   "keccak_pack_table/extended_swap");
                            lookup({m[block_counter].u[i].ch1, m[block_counter].u[i].sp1},
                                   "keccak_pack_table/extended_swap");  // UN4
                            lookup({m[block_counter].u[i].ch2, m[block_counter].u[i].sp2},
                                   "keccak_pack_table/extended_swap");  // UN5
                            lookup({m[block_counter].u[i].ch3, m[block_counter].u[i].sp3},
                                   "keccak_pack_table/extended_swap");  // UN6
                        }
                    }
                    lookup_table("keccak_dynamic", {{15, 1, 2, 3, 9}}, 0,
                                 6247 * max_blocks);
                }
            };
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil
