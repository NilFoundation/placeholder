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
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/bbf/hashes/keccak/keccak_round.hpp>
#include <nil/blueprint/bbf/hashes/keccak/util.hpp>

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
                using integral_type = typename FieldType::integral_type;
                using value_type = typename FieldType::value_type;
                using round_type = typename keccak_round<FieldType, stage>;

                struct input_type {
                    TYPE rlc_challenge;
                    std::vector<
                        std::pair<std::vector<std::uint8_t>, std::pair<value_type, value_type>>>
                        input;
                }

                const std::size_t block_rows_amount = 6020;
                const std::size_t state_rows_amount = 5;
                const std::size_t chunks_rows_amount = 34;
                const std::size_t unsparser_rows_amount = 4;
                round_type round_tf;
                round_type round_ff;
                const integral_type sparse_x80 = round_tf.sparse_x80 >> 144;
                const integral_type sparse_x7f = round_tf.sparse_x7f >> 144;

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

                    TYPE hash_hi_prev;
                    TYPE hash_lo_prev;
                    TYPE RLC_prev;
                    TYPE L_prev;
                    TYPE l_prev;
                    TYPE is_first_prev;
                    TYPE is_last_prev;
                    TYPE hash_cur_hi_prev;
                    TYPE hash_cur_lo_prev;
                    TYPE rlc_before_prev;
                    TYPE rlc_after_prev;
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

                    TYPE is_first_prev;
                    TYPE XOR_prev;
                    TYPE ch_prev;

                    TYPE rng_next;
                    TYPE XOR_next;
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
                    TYPE r2;
                    TYPE r4;
                    TYPE first_in_block;
                    // First row is length before -- controlled by copy constraints -- other rows 0

                    TYPE sp0_prev;
                    TYPE sp1_prev;
                    TYPE l_prev;
                    TYPE l_before_prev;
                    TYPE diff_prev;
                    TYPE rlc_prev;
                    TYPE rlc_before_prev;
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
                    TYPE hash_chunk;  // 64 bit final chunk -- used only in last block but we
                                      // compute it for all blocks

                    TYPE ch0_prev;
                    TYPE ch1_prev;
                    TYPE ch2_prev;
                    TYPE ch3_prev;
                };

                struct keccak_map {
                    header_map h;
                    header_map f;
                    state_map s[5];
                    chunks_map c[24];
                    unsparser_map u;
                    TYPE r;    // rlc_challenge
                    TYPE r_f;  // rlc_challenge footer row
                    TYPE r_prev;
                }

                keccak_dynamic(context_type &context_object, input_type input,
                               std::size_t max_blocks bool make_links = true)
                    : generic_component<FieldType, stage>(context_object) {
                    using integral_type = typename FieldType::integral_type;
                    using value_type = typename FieldType::value_type;

                    std::size_t block_counter = 0;
                    std::size_t header_row = start_row_index;
                    std::size_t footer_row = header_row + component.block_rows_amount - 1;
                    std::size_t input_idx = 0;
                    std::size_t l;
                    std::size_t l_before;
                    std::size_t first_in_block;
                    TYPE rlc;
                    TYPE rlc_before;
                    TYPE RLC[max_blocks];
                    // constants
                    TYPE C[40];
                    keccak_map m[max_blocks];
                    std::array<TYPE, 25> state;
                    std::vector<std::vector<uint8_t>> msg =
                        std::vector<std::vector<uint8_t>>(max_blcoks);
                    std::vector<std::vector<uint8_t>> padded_msg =
                        std::vector<std::vector<uint8_t>>(max_blcoks);
                    std::vector<std::pair<TYPE, TYPE>> hash =
                        std::vector<std::pair<TYPE, TYPE>>(max_blocks);
                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        TYPE theta = input.rlc_challenge;
                        std::cout << "RLC challenge = " << theta << std::endl;

                        while (block_counter < max_blocks) {
                            if (input_idx < instance_input.input.size()) {
                                msg[block_counter] = std::get<0>(instance_input.input[input_idx]);
                                hash[block_counter] = std::get<1>(instance_input.input[input_idx]);
                                input_idx++;
                            } else {
                                msg[block_counter] = {};
                                hash[block_counter] = keccak_component_hash<FieldType>(msg);
                            }

                            padded_msg[block_counter] = msg[block_counter];
                            padded_msg[block_counter].push_back(1);
                            while (padded_msg[block_counter].size() % 136 != 0) {
                                padded_msg[block_counter].push_back(0);
                            }
                            RLC[block_counter] =
                                calculateRLC<BlueprintFieldType>(msg[block_counter], theta);
                            std::cout << "RLC = " << std::hex << RLC[block_counter] << std::dec
                                      << std::endl;

                            for (std::size_t block = 0; block < padded_msg.size() / 136; block++) {
                                l = msg.size() - block * 136;
                                bool is_first = (block == 0 ? 1 : 0);
                                bool is_last = ((block == padded_msg.size() / 136 - 1) ? 1 : 0);
                                std::cout << "Is_last = " << is_last << std::endl;
                                if (is_first) rlc = msg.size();

                                m[block_counter].h.is_first = is_first;
                                m[block_counter].h.is_last = is_last;
                                m[block_counter].h.L = msg.size();
                                m[block_counter].h.l = msg.size() - block * 136;
                                m[block_counter].h.hash_hi = hash.first;
                                m[block_counter].h.hash_lo = hash.second;
                                m[block_counter].h.RLC = RLC : m[block_counter].r = theta;
                                m[block_counter].h.rlc_before = rlc;

                                m[block_counter].f.is_first = is_first;
                                m[block_counter].f.is_last = is_last;
                                m[block_counter].f.L = msg.size();
                                m[block_counter].f.l = msg.size() - block * 136;
                                m[block_counter].f.hash_hi = hash.first;
                                m[block_counter].f.hash_lo = hash.second;
                                m[block_counter].f.RLC = RLC : m[block_counter].r_f = theta;

                                for (std::size_t i = 0; i < state_rows_amount; i++) {
                                    m[block_counter].s[i].s0 = state[5 * i];
                                    m[block_counter].s[i].s1 = state[5 * i + 1];
                                    m[block_counter].s[i].s2 = state[5 * i + 2];
                                    m[block_counter].s[i].s3 = state[5 * i + 3];
                                    m[block_counter].s[i].s4 = state[5 * i + 4];

                                    m[block_counter].s[i].is_first = is_first;
                                    m[block_counter].s[i].S0 = is_first ? 0 : state[5 * i];
                                    m[block_counter].s[i].S1 = is_first ? 0 : state[5 * i + 1];
                                    m[block_counter].s[i].S2 = is_first ? 0 : state[5 * i + 2];
                                    m[block_counter].s[i].S3 = is_first ? 0 : state[5 * i + 3];
                                    m[block_counter].s[i].S4 = is_first ? 0 : state[5 * i + 4];
                                }

                                TYPE s16 = m[block_counter].s[3].S1;
                                std::array<TYPE, 4> s16_chunks =
                                    sparsed_64bits_to_4_chunks<FieldType>(s16);
                                TYPE mod = integral_type(s16_chunks[0].data) >= sparse_x80
                                               ? s16_chunks[0] - sparse_x80
                                               : sparse_x7f - s16_chunks[0];
                                TYPE XOR = integral_type(s16_chunks[0].data) >= sparse_x80
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

                                for (std::size_t i = 0; i < state_rows_amount;
                                     i++) {  // check i-1 when i = 0
                                    m[block_counter].s[i].out =
                                        m[block_counter].s[i - 1].XOR *
                                            (integral_type(1) << (48 * 3)) +
                                        m[block_counter].s[i - 1].ch *
                                            (integral_type(1) << (48 * 2)) +
                                        m[block_counter].s[i].XOR * (integral_type(1) << 48) +
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
                                    m[block_counter].r = theta;
                                    m[block_counter].c[i].b0 = padded_msg[msg_index];
                                    m[block_counter].c[i].b1 = padded_msg[msg_index + 1];
                                    m[block_counter].c[i].b2 = padded_msg[msg_index + 2];
                                    m[block_counter].c[i].b3 = padded_msg[msg_index + 3];

                                    auto sp0 = pack<FieldType>(
                                        integral_type(padded_msg[msg_idx + 1]) * 256 +
                                        integral_type(padded_msg[msg_idx]));
                                    auto sp1 = pack<FieldType>(
                                        integral_type(padded_msg[msg_idx + 3]) * 256 +
                                        integral_type(padded_msg[msg_idx + 2]));
                                    TYPE sp0_prev = m[block_counter].c[i - 1].sp0;
                                    TYPE sp1_prev = m[block_counter].c[i - 1].sp1;
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
                                    m[block_counter].c[i].r4 = theta * theta * theta * theta;

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
                                        rlc = rlc_before * theta * theta + msg[msg_idx] * theta +
                                              msg[msg_idx + 1];
                                    else if (l_before - l == 1)
                                        rlc = rlc_before * theta + msg[msg_idx];
                                    else
                                        rlc = rlc_before;

                                    m[block_counter].c[i].rlc = rlc;
                                    std::cout << std::hex << std::size_t(padded_msg[msg_idx])
                                              << ", " << std::size_t(padded_msg[msg_idx + 1])
                                              << ", " << std::size_t(padded_msg[msg_idx + 2])
                                              << ", " << std::size_t(padded_msg[msg_idx + 3])
                                              << std::dec << "  l=" << l
                                              << "  l_before=" << l_before << std::hex
                                              << "  rlc=" << rlc << "  rlc_before=" << rlc_before
                                              << std::dec << " first_in_block = " << first_in_block
                                              << std::endl;
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

                                for (std::size_t j = 0; j < 24; ++j) {
                                    typename round_type::input_type round_input = {inner_state, pmc,
                                                                                   C[j + 2]};

                                    if (j == 0) {
                                        context_type ct = context_object.subcontext(
                                            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, 0,
                                            291);
                                        inner_state =
                                            round_tf(ct, round_input, true, false).inner_state;
                                    } else {
                                        context_type ct = context_object.subcontext(
                                            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, 0,
                                            257);
                                        inner_state =
                                            round_ff(ct, round_input, false, false).inner_state;
                                    }
                                }

                                for (std::size_t i = 0; i < 25; i++) {
                                    state[i] = inner_state[i];
                                }

                                std::cout << "Sparse hash chunks : " << std::endl;
                                std::array<TYPE, 4> result;
                                for (std::size_t i = 0; i < 4; i++) {
                                    TYPE sparse_value = inner_state[i];
                                    result[i] = sparse_value;
                                    // std::cout << "\t" << std::hex << sparse_value << std::dec <<
                                    // std::endl;
                                    TYPE regular = unpack<BlueprintFieldType>(sparse_value);
                                    std::cout << "\t" << std::hex << regular << std::dec << " ";
                                }
                                std::cout << std::endl;

                                integral_type chunk_factor = integral_type(1) << 16;
                                for (std::size_t i = 0; i < unsparser_rows_amount; i++) {
                                    auto chunks = sparsed_64bits_to_4_chunks<FieldType>(result[i]);
                                    m[block_counter].u[i].SP = result[i];
                                    m[block_counter].u[i].sp0 = chunks[0];
                                    m[block_counter].u[i].sp1 = chunks[1];
                                    m[block_counter].u[i].sp2 = chunks[2];
                                    m[block_counter].u[i].sp3 = chunks[3];
                                    m[block_counter].u[i].ch0 =
                                        swap_bytes<FieldType>(unpack<FieldType>(chunks[0]));
                                    m[block_counter].u[i].ch1 =
                                        swap_bytes<FieldType>(unpack<FieldType>(chunks[1]));
                                    m[block_counter].u[i].ch2 =
                                        swap_bytes<FieldType>(unpack<FieldType>(chunks[2]));
                                    m[block_counter].u[i].ch3 =
                                        swap_bytes<FieldType>(unpack<FieldType>(chunks[3]));
                                    m[block_counter].u[i].hash_chunk =
                                        m[block_counter].u[i - 1].ch3 * (chunk_factor << (16 * 6)) +
                                        m[block_counter].u[i - 1].ch2 * (chunk_factor << (16 * 5)) +
                                        m[block_counter].u[i - 1].ch1 * (chunk_factor << (16 * 4)) +
                                        m[block_counter].u[i - 1].ch0 * (chunk_factor << (16 * 3)) +
                                        m[block_counter].u[i].ch3 * (chunk_factor << (16 * 2)) +
                                        m[block_counter].u[i].ch2 * (chunk_factor << (16)) +
                                        m[block_counter].u[i].ch1 * chunk_factor +
                                        m[block_counter].u[i].ch0;
                                }
                                m[block_counter].h.hash_cur_hi = m[block_counter].u[1].hash_chunk;
                                m[block_counter].h.hash_cur_lo = m[block_counter].u[3].hash_chunk;

                                if (is_last) {
                                    std::cout << "Previous hash: " << std::hex
                                              << m[block_counter].h.hash_hi << " "
                                              << m[block_counter].h.hash_lo << " " << std::endl;
                                    std::cout << "Current hash: " << std::hex
                                              << m[block_counter].h.hash_cur_hi << " "
                                              << m[block_counter].h.hash_cur_lo << " " << std::endl;
                                    std::cout << "Final hash: " << std::hex
                                              << m[block_counter].u[1].hash_chunk << " "
                                              << m[block_counter].u[3].hash_chunk << std::dec
                                              << std::endl;
                                }

                                block_counter++;
                                header_row += block_rows_amount;
                                footer_row += block_rows_amount;
                            }
                        }

                        std::size_t row = 0;
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

                            row++;
                            for (std::size_t i = 0; i < state_rows_amount; i++) {
                                allocate(m[block_counter].s[i].s0, 0, row);
                                allocate(m[block_counter].s[i].s1, 1, row);
                                allocate(m[block_counter].s[i].s2, 2, row);
                                allocate(m[block_counter].s[i].s3, 3, row);
                                allocate(m[block_counter].s[i].s4, 4, row);
                                allocate(m[block_counter].s[i].S0, 0, row);
                                allocate(m[block_counter].s[i].S1, 1, row);
                                allocate(m[block_counter].s[i].S2, 2, row);
                                allocate(m[block_counter].s[i].S3, 3, row);
                                allocate(m[block_counter].s[i].S4, 4, row);
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
                                row++;
                            }

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
                            row++;
                            std::cout << "final rows: " << row << std::endl;
                        }

                        // gates:
                        for (std::size_t block_counter = 0; block_counter < max_blocks;
                             block_counter++) {
                            // Is_first and is_last definition
                            constrain(m[block_counter].h.is_first *
                                      (m[block_counter].h.is_first - 1));
                            constrain(m[block_counter].h.is_last *
                                      (m[block_counter].h.is_last - 1));
                            constrain(m[block_counter].h.is_first *
                                      (m[block_counter].h.L - m[block_counter].h.l));
                            // lookup constraint m.h.is_last * m.h.l at
                            // keccak_pack_table/range_check_135

                            // Hash computation correctness
                            constrain(
                                m[block_counter].h.is_last *
                                (m[block_counter].h.hash_hi - m[block_counter].h.hash_cur_hi));
                            constrain(
                                m[block_counter].h.is_last *
                                (m[block_counter].h.hash_lo - m[block_counter].h.hash_cur_lo));

                            // RLC computation correctness
                            constrain(m[block_counter].h.is_first *
                                      (m[block_counter].h.rlc_before - m[block_counter].h.L));
                            constrain(m[block_counter].h.is_last *
                                      (m[block_counter].h.rlc_after - m[block_counter].h.RLC));

                            // copy constraint r with public input

                            constrain((1 - m[block_counter].h.is_first));
                            constrain((1 - m[block_counter].f.is_first));
                            if (block_counter > 0) {
                                constrain((1 - m[block_counter - 1].f.is_first) *
                                          m[block_counter].h.is_first);
                                // Transition between blocks
                                constrain((1 - m[block_counter].h.is_first) *
                                          (m[block_counter].h.L - m[block_counter - 1].f.L));
                                constrain((1 - m[block_counter].h.is_first) *
                                          (m[block_counter].h.RLC - m[block_counter - 1].f.RLC));
                                constrain(
                                    (1 - m[block_counter].h.is_first) *
                                    (m[block_counter].h.hash_hi - m[block_counter - 1].f.hash_hi));
                                constrain(
                                    (1 - m[block_counter].h.is_first) *
                                    (m[block_counter].h.hash_lo - m[block_counter - 1].f.hash_lo));
                                constrain((1 - m[block_counter].h.is_first) *
                                          (m[block_counter].h.rlc_before -
                                           m[block_counter - 1].f.rlc_before));
                                constrain((1 - m[block_counter].h.is_first) *
                                          (1 - m[block_counter].h.is_last) *
                                          (m[block_counter].h.l - m[block_counter - 1].f.l - 136));
                                // lookup constraint m.h.L, m.h.l at
                                // keccak_pack_table/range_check_16bit
                            }

                            // State transitions
                            for (std::size_t i = 0; i < state_rows_amount; i++) {
                                constrain(m[block_counter].s[i].S0 -
                                          (1 - m[block_counter].s[i].is_first) *
                                              m[block_counter].s[i].s0);
                                constrain(m[block_counter].s[i].S1 -
                                          (1 - m[block_counter].s[i].is_first) *
                                              m[block_counter].s[i].s1);
                                constrain(m[block_counter].s[i].S2 -
                                          (1 - m[block_counter].s[i].is_first) *
                                              m[block_counter].s[i].s2);
                                constrain(m[block_counter].s[i].S3 -
                                          (1 - m[block_counter].s[i].is_first) *
                                              m[block_counter].s[i].s3);
                                constrain(m[block_counter].s[i].S4 -
                                          (1 - m[block_counter].s[i].is_first) *
                                              m[block_counter].s[i].s4);
                                if (i > 0) {
                                    constrain(m[block_counter].s[i].is_first -
                                              m[block_counter].s[i - 1].is_first);
                                    constrain(m[block_counter].s[i].out -
                                              m[block_counter].s[i - 1].XOR *
                                                  (integral_type(1) << (48 * 3)) -
                                              m[block_counter].s[i - 1].ch *
                                                  (integral_type(1) << (48 * 2)) -
                                              m[block_counter].s[i].XOR *
                                                  (integral_type(1) << (48)) -
                                              m[block_counter].s[i].ch);
                                }
                                // lookup constraint s.rng at keccak_pack_table/sparse_16bit
                                // lookup(m[block_counter].s[i].rng,
                                // "keccak_pack_table/sparse_16bit");

                                // XOR constraints
                                if (i < state_rows_amount - 1) {
                                    constrain((m[block_counter].s[i + 1].rng - sparse_x80 -
                                               m[block_counter].s[i].rng) *
                                              (m[block_counter].s[i].rng - sparse_x7f +
                                               m[block_counter].s[i + 1].rng));
                                    constrain((m[block_counter].s[i + 1].rng - sparse_x7f -
                                               m[block_counter].s[i].rng) *
                                              (m[block_counter].s[i].XOR + sparse_x80 -
                                               m[block_counter].s[i + 1].rng));
                                    constrain((m[block_counter].s[i + 1].rng - sparse_x80 -
                                               m[block_counter].s[i].rng) *
                                              (m[block_counter].s[i].XOR - sparse_x80 -
                                               m[block_counter].s[i + 1].rng));
                                    constrain(
                                        (m[block_counter].s[i + 1].XOR -
                                         m[block_counter].s[i].ch * m[block_counter].s[i].XOR -
                                         (1 - m[block_counter].s[i].ch) *
                                             m[block_counter].s[i + 1].rng));
                                }
                            }

                            TYPE chunk_factor = TYPE(integral_type(1) << 48);
                            ;
                            for (std::size_t i = 0; i < chunks_rows_amount; i++) {
                                if (i > 0) {
                                    constrain(m[block_counter].c[i].chunk -
                                              m[block_counter].c[i].sp1 * chunk_factor * chunk_factor * chunk_factor -
                                              m[block_counter].c[i].sp0 * chunk_factor * chunk_factor -
                                              m[block_counter].c[i - 1].sp1 * chunk_factor -
                                              m[block_counter].c[i - 1].sp0);
                                }
                            }
                        }
                    }
                }
            };
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil
