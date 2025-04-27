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

namespace nil {
    namespace blueprint {
        namespace bbf {

            // Component for keccak round
            template<typename FieldType, GenerationStage stage>
            class keccak_round : public generic_component<FieldType, stage> {
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

                struct input_type {
                    std::array<TYPE, 25> inner_state;
                    std::array<TYPE, 17> padded_message_chunk;
                    TYPE round_constant;
                };

                TYPE inner_state[25];  // output state
                const std::size_t normalize3_chunk_size = 30;
                const std::size_t normalize4_chunk_size = 21;
                const std::size_t normalize6_chunk_size = 18;
                const std::size_t chi_chunk_size = 18;
                const std::size_t rotate_chunk_size = 24;

                const std::size_t normalize3_num_chunks = 7;
                const std::size_t normalize4_num_chunks = 10;
                const std::size_t normalize6_num_chunks = 11;
                const std::size_t chi_num_chunks = 11;
                const std::size_t rotate_num_chunks = 8;

                const integral_type big_rot_const = calculate_sparse((integral_type(1) << 64) - 1);

                const std::array<std::size_t, 25> rho_offsets = {0,  1,  3,  6,  10, 15, 21, 28, 36,
                                                                 45, 55, 2,  14, 27, 41, 56, 8,  25,
                                                                 43, 62, 18, 39, 61, 20, 44};

                const std::size_t perm[25] = {1,  10, 7,  11, 17, 18, 3,  5,  16, 8, 21, 24, 4,
                                              15, 23, 19, 13, 12, 2,  20, 14, 22, 9, 6,  1};
                const integral_type sparse_3 =
                    0x6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB_big_uint192;
                const integral_type sparse_x80 =
                    calculate_sparse(integral_type(0x8000000000000000));
                const integral_type sparse_x7f =
                    calculate_sparse(integral_type(0x8000000000000000 - 1));

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

                std::array<std::array<integral_type, 2>, 29> calculate_rot_consts() const {
                    std::array<std::array<integral_type, 2>, 29> result;
                    for (int i = 0; i < 5; ++i) {
                        result[i][0] = calculate_sparse((integral_type(1) << 1) - 1);
                        result[i][1] = calculate_sparse((integral_type(1) << 63) - 1);
                    }
                    for (int i = 1; i < 25; ++i) {
                        result[i + 4][0] =
                            calculate_sparse((integral_type(1) << rho_offsets[i]) - 1);
                        result[i + 4][1] =
                            calculate_sparse((integral_type(1) << (64 - rho_offsets[i])) - 1);
                    }
                    return result;
                }

                integral_type normalize(const integral_type &integral_value) const {
                    integral_type result = 0;
                    integral_type value = integral_value;
                    integral_type power = 1;
                    while (value > 0) {
                        result += (value & 1) * power;
                        power <<= 3;
                        value >>= 3;
                    }
                    return result;
                }

                integral_type chi(const integral_type &integral_value) const {
                    integral_type result = 0;
                    integral_type value = integral_value;
                    integral_type power = 1;
                    integral_type mask = 7;
                    int table[5] = {0, 1, 1, 0, 0};
                    while (value > 0) {
                        int bit = table[int(value & mask)];
                        result += bit * power;
                        power <<= 3;
                        value >>= 3;
                    }
                    return result;
                }

                static table_params get_minimal_requirements(bool xor_with_mes) {
                    constexpr std::size_t witness = 15;
                    constexpr std::size_t public_inputs = 1;
                    constexpr std::size_t constants = 1;
                    std::size_t rows = (xor_with_mes) ? 291 : 257;
                    return {witness, public_inputs, constants, rows};
                }

                static void allocate_public_inputs(
                        context_type &context_object, input_type &input,
                        bool xor_with_mes = false) {
                    for (std::size_t i = 0; i < 25; i++) {
                        context_object.allocate(input.inner_state[i], 0, i,
                                                column_type::public_input);
                    }
                    for (std::size_t i = 0; i < 17; i++) {
                        context_object.allocate(input.padded_message_chunk[i], 0, 25 + i,
                                                column_type::public_input);
                    }
                    context_object.allocate(input.round_constant, 0, 42, column_type::public_input);
                }

                keccak_round(context_type &context_object, input_type input,
                             bool xor_with_mes = false, bool make_links = true)
                    : generic_component<FieldType, stage>(context_object) {
                    using integral_type = typename FieldType::integral_type;
                    using value_type = typename FieldType::value_type;

                    TYPE message[17], state[17], A0[17], A0_sum[17];
                    TYPE A1[25], A1_copy[25];  // inner_state ^ padded_message_chunk
                    std::vector<std::vector<TYPE>> A0_chunks = std::vector<std::vector<TYPE>>(
                        17, std::vector<TYPE>(normalize3_num_chunks));
                    std::vector<std::vector<TYPE>> A0_normalized_chunks =
                        std::vector<std::vector<TYPE>>(17,
                                                       std::vector<TYPE>(normalize3_num_chunks));
                    // theta
                    TYPE C[5], C_sum[5], C_copy[5], C_second_copy[5][5];
                    std::vector<std::vector<TYPE>> C_chunks =
                        std::vector<std::vector<TYPE>>(5, std::vector<TYPE>(normalize6_num_chunks));
                    std::vector<std::vector<TYPE>> C_chunks_normalized =
                        std::vector<std::vector<TYPE>>(5, std::vector<TYPE>(normalize6_num_chunks));
                    TYPE C_rot[5], C_rot_shift[5], C_rot_shift_minus[5], C_rot_copy[5][5];
                    TYPE C_smaller_part[5], C_bigger_part[5];
                    TYPE C_bound_smaller[5], C_bound_bigger[5];
                    std::vector<std::vector<TYPE>> C_rot_small_chunks =
                        std::vector<std::vector<TYPE>>(5, std::vector<TYPE>(rotate_chunk_size));
                    std::vector<std::vector<TYPE>> C_rot_big_chunks =
                        std::vector<std::vector<TYPE>>(5, std::vector<TYPE>(rotate_chunk_size));
                    TYPE A2[25], A2_sum[25], A2_copy[25];
                    std::vector<std::vector<TYPE>> A2_chunks = std::vector<std::vector<TYPE>>(
                        25, std::vector<TYPE>(normalize4_num_chunks));
                    std::vector<std::vector<TYPE>> A2_normalized_chunks =
                        std::vector<std::vector<TYPE>>(25,
                                                       std::vector<TYPE>(normalize4_num_chunks));

                    // rho/phi
                    TYPE B[25], B_copy[25], B_rot_shift[24], B_rot_shift_minus[24];
                    TYPE B_smaller_part[24], B_bigger_part[24];
                    TYPE B_bound_smaller[24], B_bound_bigger[24];
                    std::vector<std::vector<TYPE>> B_small_chunks =
                        std::vector<std::vector<TYPE>>(24, std::vector<TYPE>(rotate_chunk_size));
                    std::vector<std::vector<TYPE>> B_big_chunks =
                        std::vector<std::vector<TYPE>>(24, std::vector<TYPE>(rotate_chunk_size));
                    TYPE B_extra[25][3];
                    // chi
                    TYPE A3[25], A3_sum[25];
                    std::vector<std::vector<TYPE>> A3_chunks =
                        std::vector<std::vector<TYPE>>(25, std::vector<TYPE>(chi_num_chunks));
                    std::vector<std::vector<TYPE>> A3_chi_chunks =
                        std::vector<std::vector<TYPE>>(25, std::vector<TYPE>(chi_num_chunks));

                    // iota
                    TYPE A3_0copy, A4, RC, A4_sum;
                    std::vector<TYPE> A4_chunks = std::vector<TYPE>(normalize3_num_chunks);
                    std::vector<TYPE> A4_normalized_chunks =
                        std::vector<TYPE>(normalize3_num_chunks);

                    // additional ROT chunks
                    TYPE ROT_extra[29][2];
                    std::vector<std::vector<TYPE>> ROT_extra_small_chunks =
                        std::vector<std::vector<TYPE>>(29, std::vector<TYPE>(rotate_chunk_size));
                    std::vector<std::vector<TYPE>> ROT_extra_big_chunks =
                        std::vector<std::vector<TYPE>>(29, std::vector<TYPE>(rotate_chunk_size));

                    TYPE rot_constants[29][2];
                    TYPE big_rot_constant[29];

                    TYPE x80_const = value_type(sparse_x80);

                    // constant assignments
                    auto rot_consts = calculate_rot_consts();
                    for (std::size_t j = 0; j < 29; j++) {
                        rot_constants[j][0] = value_type(rot_consts[j][0]);
                        rot_constants[j][1] = value_type(rot_consts[j][1]);
                        big_rot_constant[j] = value_type(big_rot_const);
                    }

                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        if (xor_with_mes) {
                            int upper_bound = 17;
                            for (int index = 0; index < upper_bound; ++index) {
                                state[index] = input.inner_state[index];
                                message[index] = input.padded_message_chunk[index];
                                TYPE sum = state[index] + message[index];
                                integral_type integral_sum = sum.to_integral();
                                std::vector<integral_type> integral_chunks;
                                std::vector<integral_type> integral_normalized_chunks;
                                integral_type mask =
                                    (integral_type(1) << normalize3_chunk_size) - 1;
                                integral_type power = 1;
                                integral_type integral_normalized_sum = 0;
                                for (std::size_t j = 0; j < normalize3_num_chunks; ++j) {
                                    integral_chunks.push_back(integral_sum & mask);
                                    integral_sum >>= normalize3_chunk_size;
                                    integral_normalized_chunks.push_back(
                                        normalize(integral_chunks.back()));
                                    integral_normalized_sum +=
                                        integral_normalized_chunks.back() * power;
                                    power <<= normalize3_chunk_size;
                                }
                                A0[index] = TYPE(integral_normalized_sum);
                                A0_sum[index] = sum;
                                for (std::size_t j = 0; j < normalize3_num_chunks; ++j) {
                                    A0_chunks[index][j] = integral_chunks[j];
                                    A0_normalized_chunks[index][j] = integral_normalized_chunks[j];
                                }
                            }
                            for (int i = 0; i < 17; ++i) {
                                A1[i] = A0[i];
                            }
                            for (int i = 17; i < 25; ++i) {
                                A1[i] = input.inner_state[i];
                            }
                            for (int i = 0; i < 25; ++i) {
                                A1_copy[i] = A1[i];
                            }
                        } else {
                            for (int i = 0; i < 25; ++i) {
                                A1[i] = input.inner_state[i];
                                A1_copy[i] = A1[i];
                            }
                        }

                        // theta
                        for (int index = 0; index < 5; ++index) {
                            TYPE sum = 0;
                            for (int j = 0; j < 5; ++j) {
                                sum += A1[index + 5 * j];
                            }
                            C_sum[index] = sum;

                            integral_type integral_sum = sum.to_integral();
                            std::vector<integral_type> integral_chunks;
                            std::vector<integral_type> integral_normalized_chunks;
                            integral_type mask = (integral_type(1) << normalize6_chunk_size) - 1;
                            integral_type power = 1;
                            integral_type integral_normalized_sum = 0;
                            for (std::size_t j = 0; j < normalize6_num_chunks; ++j) {
                                integral_chunks.push_back(integral_sum & mask);
                                integral_sum >>= normalize6_chunk_size;
                                integral_normalized_chunks.push_back(
                                    normalize(integral_chunks.back()));
                                integral_normalized_sum +=
                                    integral_normalized_chunks.back() * power;
                                power <<= normalize6_chunk_size;
                            }
                            C[index] = TYPE(integral_normalized_sum);

                            for (std::size_t j = 0; j < normalize6_num_chunks; ++j) {
                                C_chunks[index][j] = integral_chunks[j];
                                C_chunks_normalized[index][j] = integral_normalized_chunks[j];
                            }

                            C_copy[index] = C[index];
                            for (std::size_t j = 0; j < 5; j++) {
                                C_second_copy[index][j] = C[index];
                            }
                        }

                        std::vector<integral_type> additional_rot_chunks;
                        for (int index = 0; index < 5; ++index) {
                            integral_type integral_C = C[index].to_integral();
                            integral_type smaller_part = integral_C >> 189;
                            integral_type bigger_part =
                                integral_C & ((integral_type(1) << 189) - 1);
                            integral_type integral_C_rot = (bigger_part << 3) + smaller_part;
                            C_rot[index] = TYPE(integral_C_rot);

                            additional_rot_chunks.push_back(smaller_part);
                            additional_rot_chunks.push_back(bigger_part);
                            // integral_type bound_smaller = smaller_part - (integral_type(1) << 3)
                            // + (integral_type(1) << 192); integral_type bound_bigger = bigger_part
                            // - (integral_type(1) << 189) + (integral_type(1) << 192);
                            integral_type bound_smaller =
                                smaller_part + big_rot_const - rot_consts[index][0];
                            ;
                            integral_type bound_bigger =
                                bigger_part + big_rot_const - rot_consts[index][1];
                            ;
                            auto copy_bound_smaller = bound_smaller;
                            auto copy_bound_bigger = bound_bigger;
                            std::vector<integral_type> integral_small_chunks;
                            std::vector<integral_type> integral_big_chunks;
                            integral_type mask = (integral_type(1) << rotate_chunk_size) - 1;
                            for (std::size_t j = 0; j < rotate_num_chunks; ++j) {
                                integral_small_chunks.push_back(bound_smaller & mask);
                                bound_smaller >>= rotate_chunk_size;
                                integral_big_chunks.push_back(bound_bigger & mask);
                                bound_bigger >>= rotate_chunk_size;
                            }

                            for (std::size_t j = 0; j < rotate_num_chunks; ++j) {
                                C_rot_small_chunks[index][j] = TYPE(integral_small_chunks[j]);
                                C_rot_big_chunks[index][j] = TYPE(integral_big_chunks[j]);
                            }
                            C_smaller_part[index] = TYPE(smaller_part);
                            C_bigger_part[index] = TYPE(bigger_part);
                            C_bound_smaller[index] = TYPE(copy_bound_smaller);
                            C_bound_bigger[index] = TYPE(copy_bound_bigger);
                            C_rot_shift[index] = TYPE(integral_type(1) << 3);
                            C_rot_shift_minus[index] = TYPE(integral_type(1) << 189);

                            for (std::size_t j = 0; j < 5; j++) {
                                C_rot_copy[index][j] = C_rot[index];
                            }
                        }

                        for (int index = 0; index < 25; ++index) {
                            int x = index % 5;
                            TYPE sum = A1[index] + C_rot[(x + 1) % 5] + C[(x + 4) % 5];
                            integral_type integral_sum = sum.to_integral();
                            std::vector<integral_type> integral_chunks;
                            std::vector<integral_type> integral_normalized_chunks;
                            integral_type mask = (integral_type(1) << normalize4_chunk_size) - 1;
                            integral_type power = 1;
                            integral_type integral_normalized_sum = 0;
                            for (std::size_t j = 0; j < normalize4_num_chunks; ++j) {
                                integral_chunks.push_back(integral_sum & mask);
                                integral_sum >>= normalize4_chunk_size;
                                integral_normalized_chunks.push_back(
                                    normalize(integral_chunks.back()));
                                integral_normalized_sum +=
                                    integral_normalized_chunks.back() * power;
                                power <<= normalize4_chunk_size;
                            }

                            A2[index] = TYPE(integral_normalized_sum);
                            A2_sum[index] = TYPE(sum);
                            for (std::size_t j = 0; j < normalize4_num_chunks; ++j) {
                                A2_chunks[index][j] = TYPE(integral_chunks[j]);
                                A2_normalized_chunks[index][j] =
                                    TYPE(integral_normalized_chunks[j]);
                            }
                            A2_copy[index] = A2[index];
                        }

                        // rho/pi

                        B[0] = A2[0];
                        for (int index = 1; index < 25; ++index) {
                            int r = 3 * rho_offsets[index];
                            int minus_r = 192 - r;
                            integral_type integral_A = A2[perm[index - 1]].to_integral();
                            integral_type smaller_part = integral_A >> minus_r;
                            integral_type bigger_part =
                                integral_A & ((integral_type(1) << minus_r) - 1);
                            integral_type integral_A_rot = (bigger_part << r) + smaller_part;
                            B[perm[index]] = TYPE(integral_A_rot);
                            additional_rot_chunks.push_back(smaller_part);
                            additional_rot_chunks.push_back(bigger_part);
                            // integral_type bound_smaller = smaller_part - (integral_type(1) << r)
                            // + (integral_type(1) << 192); integral_type bound_bigger = bigger_part
                            // - (integral_type(1) << minus_r) + (integral_type(1) << 192);
                            integral_type bound_smaller =
                                smaller_part + big_rot_const - rot_consts[index + 4][0];
                            integral_type bound_bigger =
                                bigger_part + big_rot_const - rot_consts[index + 4][1];
                            auto copy_bound_smaller = bound_smaller;
                            auto copy_bound_bigger = bound_bigger;
                            std::vector<integral_type> integral_small_chunks;
                            std::vector<integral_type> integral_big_chunks;
                            integral_type mask = (integral_type(1) << rotate_chunk_size) - 1;
                            for (std::size_t j = 0; j < rotate_num_chunks; ++j) {
                                integral_small_chunks.push_back(bound_smaller & mask);
                                bound_smaller >>= rotate_chunk_size;
                                integral_big_chunks.push_back(bound_bigger & mask);
                                bound_bigger >>= rotate_chunk_size;
                            }

                            B_smaller_part[index - 1] = TYPE(smaller_part);
                            B_bigger_part[index - 1] = TYPE(bigger_part);
                            B_bound_smaller[index - 1] = TYPE(copy_bound_smaller);
                            B_bound_bigger[index - 1] = TYPE(copy_bound_bigger);
                            for (std::size_t j = 0; j < rotate_num_chunks; j++) {
                                B_small_chunks[index - 1][j] = TYPE(integral_small_chunks[j]);
                                B_big_chunks[index - 1][j] = TYPE(integral_big_chunks[j]);
                            }
                            B_rot_shift[index - 1] = TYPE(integral_type(1) << r);
                            B_rot_shift_minus[index - 1] = TYPE(integral_type(1) << minus_r);
                        }

                        // chi
                        for (int index = 0; index < 25; ++index) {
                            int x = index % 5;
                            int y = index / 5;
                            TYPE sum = TYPE(sparse_3) - 2 * B[x + 5 * y] + B[(x + 1) % 5 + 5 * y] -
                                       B[(x + 2) % 5 + 5 * y];
                            integral_type integral_sum = integral_type(sum.to_integral());
                            std::vector<integral_type> integral_chunks;
                            std::vector<integral_type> integral_chi_chunks;
                            integral_type mask = (integral_type(1) << chi_chunk_size) - 1;
                            integral_type power = 1;
                            integral_type integral_chi_sum = 0;
                            for (std::size_t j = 0; j < chi_num_chunks; ++j) {
                                integral_chunks.push_back(integral_sum & mask);
                                integral_sum >>= chi_chunk_size;
                                integral_chi_chunks.push_back(chi(integral_chunks.back()));
                                integral_chi_sum += integral_chi_chunks.back() * power;
                                power <<= chi_chunk_size;
                            }
                            A3[index] = TYPE(integral_chi_sum);
                            A3_sum[index] = sum;
                            B_extra[index][0] = B[index];
                            B_extra[index][1] = B[(x + 1) % 5 + 5 * y];
                            B_extra[index][2] = B[(x + 2) % 5 + 5 * y];
                            for (std::size_t j = 0; j < chi_num_chunks; ++j) {
                                A3_chunks[index][j] = TYPE(integral_chunks[j]);
                                A3_chi_chunks[index][j] = TYPE(integral_chi_chunks[j]);
                            }
                        }

                        // iota
                        {
                            TYPE sum = A3[0] + input.round_constant;
                            integral_type integral_sum = sum.to_integral();
                            std::vector<integral_type> integral_chunks;
                            std::vector<integral_type> integral_normalized_chunks;
                            integral_type mask = (integral_type(1) << normalize3_chunk_size) - 1;
                            integral_type power = 1;
                            integral_type integral_normalized_sum = 0;
                            for (std::size_t j = 0; j < normalize3_num_chunks; ++j) {
                                integral_chunks.push_back(integral_sum & mask);
                                integral_sum >>= normalize3_chunk_size;
                                integral_normalized_chunks.push_back(
                                    normalize(integral_chunks.back()));
                                integral_normalized_sum +=
                                    integral_normalized_chunks.back() * power;
                                power <<= normalize3_chunk_size;
                            }
                            A4 = TYPE(integral_normalized_sum);
                            for (std::size_t j = 0; j < normalize3_num_chunks; ++j) {
                                A4_chunks[j] = TYPE(integral_chunks[j]);
                                A4_normalized_chunks[j] = TYPE(integral_normalized_chunks[j]);
                            }
                            A3_0copy = A3[0];
                            A4_sum = TYPE(sum);
                            RC = input.round_constant;
                        }

                        // additional rots

                        for (std::size_t i = 0; i < 29; ++i) {
                            auto copy_bound_smaller = additional_rot_chunks[2 * i];
                            auto copy_bound_bigger = additional_rot_chunks[2 * i + 1];
                            std::vector<integral_type> integral_small_chunks;
                            std::vector<integral_type> integral_big_chunks;
                            integral_type mask = (integral_type(1) << rotate_chunk_size) - 1;
                            for (std::size_t j = 0; j < rotate_num_chunks; ++j) {
                                integral_small_chunks.push_back(copy_bound_smaller & mask);
                                copy_bound_smaller >>= rotate_chunk_size;
                                integral_big_chunks.push_back(copy_bound_bigger & mask);
                                copy_bound_bigger >>= rotate_chunk_size;
                            }
                            ROT_extra[i][0] = TYPE(additional_rot_chunks[2 * i]);
                            ROT_extra[i][1] = TYPE(additional_rot_chunks[2 * i + 1]);
                            for (std::size_t j = 0; j < rotate_num_chunks; ++j) {
                                ROT_extra_small_chunks[i][j] = TYPE(integral_small_chunks[j]);
                                ROT_extra_big_chunks[i][j] = TYPE(integral_big_chunks[j]);
                            }
                        }
                    }

                    std::size_t row_offset = 0;
                    if (xor_with_mes) {
                        for (int index = 0; index < 17; ++index) {
                            allocate(message[index], 0, row_offset + 2 * index);
                            allocate(state[index], 1, row_offset + 2 * index);
                            allocate(A0_sum[index], 2, row_offset + 2 * index);
                            allocate(A0[index], 0, row_offset + 2 * index + 1);
                            for (std::size_t j = 0; j < normalize3_num_chunks; j++) {
                                allocate(A0_chunks[index][j], 3 + j, row_offset + 2 * index);
                                allocate(A0_normalized_chunks[index][j], 1 + j,
                                         row_offset + 2 * index + 1);
                            }
                        }
                        row_offset += 2 * 17;
                    }

                    // theta allocations
                    for (int index = 0; index < 5; ++index) {
                        allocate(A1[index], 0, row_offset + 2 * index);
                        allocate(A1[index + 5], 1, row_offset + 2 * index);
                        allocate(A1[index + 10], 2, row_offset + 2 * index);
                        allocate(A1[index + 15], 3, row_offset + 2 * index);
                        allocate(A1[index + 20], 4, row_offset + 2 * index);
                        allocate(C_sum[index], 5, row_offset + 2 * index);
                        for (std::size_t j = 0; j < normalize6_num_chunks - 2; j++) {
                            allocate(C_chunks[index][j], 6 + j, row_offset + 2 * index);
                        }
                        allocate(C_chunks[index][9], 1, row_offset + 2 * index + 1);
                        allocate(C_chunks[index][10], 2, row_offset + 2 * index + 1);
                        allocate(C[index], 0, row_offset + 2 * index + 1);
                        for (std::size_t j = 0; j < normalize6_num_chunks; j++) {
                            allocate(C_chunks_normalized[index][j], 3 + j,
                                     row_offset + 2 * index + 1);
                        }
                    }
                    row_offset += 10;  // 2*5

                    for (int index = 0; index < 5; ++index) {
                        allocate(C_rot[index], 9, row_offset + 3 * index);
                        allocate(C_copy[index], 0, row_offset + 3 * index);
                        allocate(C_smaller_part[index], 12, row_offset + 3 * index);
                        allocate(C_bigger_part[index], 13, row_offset + 3 * index);
                        allocate(C_bound_smaller[index], 14, row_offset + 3 * index);
                        allocate(C_bound_bigger[index], 0, row_offset + 3 * index + 1);
                        allocate(big_rot_constant[index], 0, row_offset + 3 * index,
                                 column_type::constant);
                        allocate(rot_constants[index][0], 0, row_offset + 3 * index + 1,
                                 column_type::constant);
                        allocate(rot_constants[index][1], 0, row_offset + 3 * index + 2,
                                 column_type::constant);
                        for (std::size_t j = 0; j < rotate_num_chunks; j++) {
                            allocate(C_rot_small_chunks[index][j], 1 + j, row_offset + 3 * index);
                            allocate(C_rot_big_chunks[index][j], 1 + j, row_offset + 3 * index + 1);
                        }
                        allocate(C_rot_shift[index], 10, row_offset + 3 * index);
                        allocate(C_rot_shift_minus[index], 11, row_offset + 3 * index);
                    }
                    row_offset += 15;  // 3*5

                    for (int index = 0; index < 25; ++index) {
                        auto x = index % 5;
                        auto y = index / 5;
                        allocate(A1_copy[index], 0, row_offset + 2 * index);
                        allocate(C_rot_copy[(x + 1) % 5][y], 1, row_offset + 2 * index);
                        allocate(C_second_copy[(x + 4) % 5][y], 2, row_offset + 2 * index);
                        allocate(A2_sum[index], 3, row_offset + 2 * index);
                        allocate(A2[index], 0, row_offset + 2 * index + 1);
                        for (std::size_t j = 0; j < normalize4_num_chunks; ++j) {
                            allocate(A2_chunks[index][j], 4 + j, row_offset + 2 * index);
                            allocate(A2_normalized_chunks[index][j], 1 + j,
                                     row_offset + 2 * index + 1);
                        }
                    }
                    row_offset += 50;  // 2*25

                    // rho/pi allocations
                    for (int index = 0; index < 24; ++index) {
                        allocate(B[perm[index + 1]], 9, row_offset + 3 * index);
                        allocate(A2_copy[perm[index]], 0, row_offset + 3 * index);
                        allocate(B_smaller_part[index], 12, row_offset + 3 * index);
                        allocate(B_bigger_part[index], 13, row_offset + 3 * index);
                        allocate(B_bound_smaller[index], 14, row_offset + 3 * index);
                        allocate(B_bound_bigger[index], 0, row_offset + 3 * index + 1);
                        allocate(big_rot_constant[index + 5], 0, row_offset + 3 * index,
                                 column_type::constant);
                        allocate(rot_constants[index + 5][0], 0, row_offset + 3 * index + 1,
                                 column_type::constant);
                        allocate(rot_constants[index + 5][1], 0, row_offset + 3 * index + 2,
                                 column_type::constant);
                        for (std::size_t j = 0; j < rotate_num_chunks; j++) {
                            allocate(B_small_chunks[index][j], 1 + j, row_offset + 3 * index);
                            allocate(B_big_chunks[index][j], 1 + j, row_offset + 3 * index + 1);
                        }
                        allocate(B_rot_shift[index], 10, row_offset + 3 * index);
                        allocate(B_rot_shift_minus[index], 11, row_offset + 3 * index);
                    }
                    row_offset += 3 * 24;

                    // chi allocations
                    for (int index = 0; index < 25; ++index) {
                        auto x = index % 5;
                        auto y = index / 5;
                        allocate(A3_sum[index], 3, row_offset + 2 * index);
                        allocate(A3[index], 0, row_offset + 2 * index + 1);
                        allocate(B_extra[index][0], 0, row_offset + 2 * index);
                        allocate(B_extra[index][1], 1, row_offset + 2 * index);
                        allocate(B_extra[index][2], 2, row_offset + 2 * index);
                        for (std::size_t j = 0; j < chi_num_chunks; j++) {
                            allocate(A3_chunks[index][j], 4 + j, row_offset + 2 * index);
                            allocate(A3_chi_chunks[index][j], 1 + j, row_offset + 2 * index + 1);
                        }
                    }
                    row_offset += 50;

                    // iota allocations
                    allocate(A3_0copy, 0, row_offset);
                    allocate(RC, 1, row_offset);
                    allocate(A4_sum, 2, row_offset);
                    allocate(A4, 0, row_offset + 1);
                    for (std::size_t j = 0; j < normalize3_num_chunks; j++) {
                        allocate(A4_chunks[j], 3 + j, row_offset);
                        allocate(A4_normalized_chunks[j], 1 + j, row_offset + 1);
                    }
                    row_offset += 2;

                    // additional rots allocation
                    for (int index = 0; index < 29; ++index) {
                        allocate(ROT_extra[index][0], 0, row_offset + 2 * index);
                        allocate(ROT_extra[index][1], 0, row_offset + 2 * index + 1);
                        for (std::size_t j = 0; j < rotate_num_chunks; j++) {
                            allocate(ROT_extra_small_chunks[index][j], 1 + j,
                                     row_offset + 2 * index);
                            allocate(ROT_extra_big_chunks[index][j], 1 + j,
                                     row_offset + 2 * index + 1);
                        }
                    }
                    row_offset += 2 * 29;

                    if (make_links) {
                        if (xor_with_mes) {
                            for (std::size_t i = 0; i < 17; i++) {
                                copy_constrain(message[i], input.padded_message_chunk[i]);
                                copy_constrain(state[i], input.inner_state[i]);
                            }
                            for (std::size_t i = 17; i < 25; i++) {
                                copy_constrain(A1[i], input.inner_state[i]);
                            }
                        } else {
                            for (std::size_t i = 0; i < 25; i++) {
                                copy_constrain(A1[i], input.inner_state[i]);
                            }
                        }
                        copy_constrain(RC, input.round_constant);
                    }

                    if (xor_with_mes) {
                        for (int index = 0; index < 17; index++) {
                            copy_constrain(A0[index], A1[index]);
                            constrain(A0_sum[index] - message[index] - state[index]);
                            TYPE constraint_chunk = A0_sum[index];
                            TYPE constraint_normalized_chunk = A0[index];
                            for (std::size_t k = 0; k < normalize3_num_chunks; ++k) {
                                constraint_chunk -=
                                    A0_chunks[index][k] *
                                    (integral_type(1) << (k * normalize3_chunk_size));
                                constraint_normalized_chunk -=
                                    A0_normalized_chunks[index][k] *
                                    (integral_type(1) << (k * normalize3_chunk_size));
                                lookup({A0_chunks[index][k], A0_normalized_chunks[index][k]},
                                       "keccak_normalize3_table/full");
                            }
                            constrain(constraint_chunk);
                            constrain(constraint_normalized_chunk);
                        }
                    }

                    // theta constraints
                    for (int index = 0; index < 5; ++index) {
                        constrain(C_sum[index] - A1[index] - A1[index + 5] - A1[index + 10] -
                                  A1[index + 15] - A1[index + 20]);

                        TYPE constraint_chunk = C_sum[index];
                        TYPE constraint_normalized_chunk = C[index];
                        for (std::size_t k = 0; k < normalize6_num_chunks; ++k) {
                            constraint_chunk -= C_chunks[index][k] *
                                                (integral_type(1) << (k * normalize6_chunk_size));
                            constraint_normalized_chunk -=
                                C_chunks_normalized[index][k] *
                                (integral_type(1) << (k * normalize6_chunk_size));
                            lookup({C_chunks[index][k], C_chunks_normalized[index][k]},
                                   "keccak_normalize6_table/full");
                        }
                        constrain(constraint_chunk);
                        constrain(constraint_normalized_chunk);
                    }

                    for (int index = 0; index < 5; ++index) {
                        copy_constrain(C[index], C_copy[index]);
                        constrain(C_copy[index] - C_smaller_part[index] * C_rot_shift_minus[index] -
                                  C_bigger_part[index]);
                        constrain(C_rot[index] - C_bigger_part[index] * C_rot_shift[index] -
                                  C_smaller_part[index]);
                        constrain(C_rot_shift[index] * C_rot_shift_minus[index] -
                                  (integral_type(1) << 192));
                        constrain(C_bound_smaller[index] - C_smaller_part[index] +
                                  rot_constants[index][0] - big_rot_constant[index]);
                        constrain(C_bound_bigger[index] - C_bigger_part[index] +
                                  rot_constants[index][1] - big_rot_constant[index]);

                        TYPE constraint_small_chunks = C_bound_smaller[index];
                        TYPE constraint_big_chunks = C_bound_bigger[index];
                        for (std::size_t k = 0; k < rotate_num_chunks; k++) {
                            constraint_small_chunks -=
                                C_rot_small_chunks[index][k] *
                                (integral_type(1) << (k * rotate_chunk_size));
                            constraint_big_chunks -= C_rot_big_chunks[index][k] *
                                                     (integral_type(1) << (k * rotate_chunk_size));
                            lookup(C_rot_small_chunks[index][k],
                                   "keccak_pack_table/range_check_sparse");
                            lookup(C_rot_big_chunks[index][k],
                                   "keccak_pack_table/range_check_sparse");
                        }
                        constrain(constraint_small_chunks);
                        constrain(constraint_big_chunks);
                    }

                    for (int index = 0; index < 25; ++index) {
                        auto x = index % 5;
                        auto y = index / 5;
                        copy_constrain(C[x], C_second_copy[x][y]);
                        copy_constrain(C_rot[x], C_rot_copy[x][y]);
                        constrain(A2_sum[index] - A1_copy[index] - C_rot_copy[(x + 1) % 5][y] -
                                  C_second_copy[(x + 4) % 5][y]);
                        TYPE constrain_A2_chunks = A2_sum[index];
                        TYPE constrain_A2_normalized_chunks = A2[index];
                        for (std::size_t k = 0; k < normalize4_num_chunks; k++) {
                            constrain_A2_chunks -=
                                A2_chunks[index][k] *
                                (integral_type(1) << (k * normalize4_chunk_size));
                            constrain_A2_normalized_chunks -=
                                A2_normalized_chunks[index][k] *
                                (integral_type(1) << (k * normalize4_chunk_size));
                            lookup({A2_chunks[index][k], A2_normalized_chunks[index][k]},
                                   "keccak_normalize4_table/full");
                        }
                        constrain(constrain_A2_chunks);
                        constrain(constrain_A2_normalized_chunks);
                    }

                    // rho/pi constraints
                    for (int index = 0; index < 24; ++index) {
                        copy_constrain(A2[perm[index]], A2_copy[perm[index]]);
                        constrain(A2_copy[perm[index]] -
                                  B_smaller_part[index] * B_rot_shift_minus[index] -
                                  B_bigger_part[index]);
                        constrain(B[perm[index + 1]] - B_bigger_part[index] * B_rot_shift[index] -
                                  B_smaller_part[index]);
                        constrain(B_rot_shift[index] * B_rot_shift_minus[index] -
                                  (integral_type(1) << 192));
                        constrain(B_bound_smaller[index] - B_smaller_part[index] +
                                  rot_constants[index + 5][0] - big_rot_constant[index + 5]);
                        constrain(B_bound_bigger[index] - B_bigger_part[index] +
                                  rot_constants[index + 5][1] - big_rot_constant[index + 5]);

                        TYPE constraint_small_chunks = B_bound_smaller[index];
                        TYPE constraint_big_chunks = B_bound_bigger[index];
                        for (std::size_t k = 0; k < rotate_num_chunks; k++) {
                            constraint_small_chunks -=
                                B_small_chunks[index][k] *
                                (integral_type(1) << (k * rotate_chunk_size));
                            constraint_big_chunks -= B_big_chunks[index][k] *
                                                     (integral_type(1) << (k * rotate_chunk_size));
                            lookup(B_small_chunks[index][k],
                                   "keccak_pack_table/range_check_sparse");
                            lookup(B_big_chunks[index][k], "keccak_pack_table/range_check_sparse");
                        }
                        constrain(constraint_small_chunks);
                        constrain(constraint_big_chunks);
                    }

                    // chi constraints
                    for (int index = 0; index < 25; ++index) {
                        auto x = index % 5;
                        auto y = index / 5;

                        if (index == 0) {
                            copy_constrain(B_extra[index][0], A2[index]);
                        } else {
                            copy_constrain(B_extra[index][0], B[index]);
                        }
                        if ((x + 1) % 5 + 5 * y == 0) {
                            copy_constrain(B_extra[index][1], A2[0]);
                        } else {
                            copy_constrain(B_extra[index][1], B[(x + 1) % 5 + 5 * y]);
                        }
                        if ((x + 2) % 5 + 5 * y == 0) {
                            copy_constrain(B_extra[index][2], A2[0]);
                        } else {
                            copy_constrain(B_extra[index][2], B[(x + 2) % 5 + 5 * y]);
                        }

                        constrain(A3_sum[index] - sparse_3 + 2 * B_extra[index][0] -
                                  B_extra[index][1] + B_extra[index][2]);

                        TYPE constraint_chunks = A3_sum[index];
                        TYPE constraint_chi_chunks = A3[index];
                        for (std::size_t k = 0; k < chi_num_chunks; k++) {
                            constraint_chunks -=
                                A3_chunks[index][k] * (integral_type(1) << (k * chi_chunk_size));
                            constraint_chi_chunks -= A3_chi_chunks[index][k] *
                                                     (integral_type(1) << (k * chi_chunk_size));
                            lookup({A3_chunks[index][k], A3_chi_chunks[index][k]},
                                   "keccak_chi_table/full");
                        }
                        constrain(constraint_chunks);
                        constrain(constraint_chi_chunks);
                    }

                    // iota constraints
                    {
                        copy_constrain(A3_0copy, A3[0]);
                        constrain(A4_sum - A3_0copy - RC);
                        TYPE constraint_chunks = A4_sum;
                        TYPE constraint_normalized_chunks = A4;
                        for (std::size_t k = 0; k < normalize3_num_chunks; k++) {
                            constraint_chunks -=
                                A4_chunks[k] * (integral_type(1) << (k * normalize3_chunk_size));
                            constraint_normalized_chunks -=
                                A4_normalized_chunks[k] *
                                (integral_type(1) << (k * normalize3_chunk_size));
                            lookup({A4_chunks[k], A4_normalized_chunks[k]},
                                   "keccak_normalize3_table/full");
                        }
                        constrain(constraint_chunks);
                        constrain(constraint_normalized_chunks);
                    }

                    // additional rot range checks
                    for (int index = 0; index < 29; ++index) {
                        if (index < 5) {
                            copy_constrain(ROT_extra[index][0], C_smaller_part[index]);
                            copy_constrain(ROT_extra[index][1], C_bigger_part[index]);
                        } else {
                            copy_constrain(ROT_extra[index][0], B_smaller_part[index - 5]);
                            copy_constrain(ROT_extra[index][1], B_bigger_part[index - 5]);
                        }
                        TYPE constraint_small = ROT_extra[index][0];
                        TYPE constraint_big = ROT_extra[index][1];
                        for (std::size_t k = 0; k < rotate_num_chunks; k++) {
                            constraint_small -= ROT_extra_small_chunks[index][k] *
                                                (integral_type(1) << (k * rotate_chunk_size));
                            constraint_big -= ROT_extra_big_chunks[index][k] *
                                              (integral_type(1) << (k * rotate_chunk_size));
                            lookup(ROT_extra_small_chunks[index][k],
                                   "keccak_pack_table/range_check_sparse");
                            lookup(ROT_extra_big_chunks[index][k],
                                   "keccak_pack_table/range_check_sparse");
                        }
                        constrain(constraint_small);
                        constrain(constraint_big);
                    }

                    inner_state[0] = A4;
                    for (std::size_t index = 1; index < 25; ++index) {
                        inner_state[index] = A3[index];
                    }
                };
            };
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil
