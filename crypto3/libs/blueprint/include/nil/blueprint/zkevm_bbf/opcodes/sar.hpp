//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
// Copyright (c) 2024 Antoine Cyr <antoine.cyr@nil.foundation>
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

#include <algorithm>
#include <iostream>
#include <nil/blueprint/zkevm_bbf/types/opcode.hpp>
#include <numeric>

namespace nil {
    namespace blueprint {
        namespace bbf {
            template<typename FieldType>
            class opcode_abstract;

            template<typename FieldType, GenerationStage stage>
            class zkevm_sar_bbf : public generic_component<FieldType, stage> {
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;

                using value_type = typename FieldType::value_type;

                constexpr static const std::size_t chunk_amount = 16;
                constexpr static const std::size_t carry_amount = 16 / 3 + 1;
                constexpr static const value_type two_16 = 65536;
                constexpr static const value_type two_32 = 4294967296;
                constexpr static const value_type two_48 = 281474976710656;
                constexpr static const value_type two_64 = 0x10000000000000000_big_uint254;
                constexpr static const value_type two_128 =
                    0x100000000000000000000000000000000_big_uint254;
                constexpr static const value_type two_192 =
                    0x1000000000000000000000000000000000000000000000000_big_uint254;

              public:
                using typename generic_component<FieldType, stage>::TYPE;
                using typename generic_component<FieldType, stage>::context_type;

                template<typename T, typename V = T>
                T chunk_sum_64(const std::vector<V> &chunks, const unsigned char chunk_idx) const {
                    BOOST_ASSERT(chunk_idx < 4);
                    return chunks[4 * chunk_idx] + chunks[4 * chunk_idx + 1] * two_16 +
                           chunks[4 * chunk_idx + 2] * two_32 + chunks[4 * chunk_idx + 3] * two_48;
                }

                template<typename T>
                T first_carryless_construct(const std::vector<T> &a_64_chunks,
                                            const std::vector<T> &b_64_chunks,
                                            const std::vector<T> &r_64_chunks,
                                            const std::vector<T> &q_64_chunks) const {
                    return r_64_chunks[0] * b_64_chunks[0] + q_64_chunks[0] +
                           two_64 * (r_64_chunks[0] * b_64_chunks[1] +
                                     r_64_chunks[1] * b_64_chunks[0] + q_64_chunks[1]) -
                           a_64_chunks[0] - two_64 * a_64_chunks[1];
                }

                template<typename T>
                T second_carryless_construct(const std::vector<T> &a_64_chunks,
                                             const std::vector<T> &b_64_chunks,
                                             const std::vector<T> &r_64_chunks,
                                             const std::vector<T> &q_64_chunks) const {
                    return (r_64_chunks[0] * b_64_chunks[2] + r_64_chunks[1] * b_64_chunks[1] +
                            r_64_chunks[2] * b_64_chunks[0] + q_64_chunks[2] - a_64_chunks[2]) +
                           two_64 *
                               (r_64_chunks[0] * b_64_chunks[3] + r_64_chunks[1] * b_64_chunks[2] +
                                r_64_chunks[2] * b_64_chunks[1] + r_64_chunks[3] * b_64_chunks[0] +
                                q_64_chunks[3] - a_64_chunks[3]);
                }

                template<typename T>
                T third_carryless_construct(const std::vector<T> &b_64_chunks,
                                            const std::vector<T> &r_64_chunks) const {
                    return (r_64_chunks[1] * b_64_chunks[3] + r_64_chunks[2] * b_64_chunks[2] +
                            r_64_chunks[3] * b_64_chunks[1]) +
                           two_64 *
                               (r_64_chunks[2] * b_64_chunks[3] + r_64_chunks[3] * b_64_chunks[2]);
                }

                TYPE carry_on_addition_constraint(TYPE a_0, TYPE a_1, TYPE a_2, TYPE b_0, TYPE b_1,
                                                  TYPE b_2, TYPE r_0, TYPE r_1, TYPE r_2,
                                                  TYPE last_carry, TYPE result_carry,
                                                  bool first_constraint = false) {
                    TYPE res;
                    if (first_constraint) {
                        // no last carry for first constraint
                        res = (a_0 + b_0) + (a_1 + b_1) * two_16 + (a_2 + b_2) * two_32 - r_0 -
                              r_1 * two_16 - r_2 * two_32 - result_carry * two_48;
                    } else {
                        res = last_carry + (a_0 + b_0) + (a_1 + b_1) * two_16 +
                              (a_2 + b_2) * two_32 - r_0 - r_1 * two_16 - r_2 * two_32 -
                              result_carry * two_48;
                    }
                    return res;
                };
                TYPE last_carry_on_addition_constraint(TYPE a_0, TYPE b_0, TYPE r_0,
                                                       TYPE last_carry, TYPE result_carry) {
                    TYPE res = (last_carry + a_0 + b_0 - r_0 - result_carry * two_16);
                    return res;
                };

                std::vector<TYPE> res;

              public:
                zkevm_sar_bbf(context_type &context_object,
                              const opcode_input_type<FieldType, stage> &current_state)
                    : generic_component<FieldType, stage>(context_object, false),
                      res(chunk_amount) {
                    TYPE first_carryless;
                    TYPE second_carryless;
                    TYPE third_carryless;

                    TYPE b0p;
                    TYPE b0pp;
                    TYPE b0ppp;
                    TYPE b0p_range_check;
                    TYPE b0pp_range_check;
                    TYPE b0ppp_range_check;
                    TYPE I1;
                    TYPE I2;
                    TYPE z;
                    TYPE tp;
                    TYPE two_powers;
                    TYPE sum_part_b;
                    TYPE b_sum;
                    TYPE b_sum_inverse;
                    TYPE r_sum;
                    TYPE r_sum_inverse;
                    TYPE a_neg;
                    TYPE a_neg_2;

                    std::vector<TYPE> a_64_chunks(4);
                    std::vector<TYPE> b_64_chunks(4);
                    std::vector<TYPE> r_64_chunks(4);
                    std::vector<TYPE> q_64_chunks(4);

                    std::vector<TYPE> c_1_chunks(4);
                    std::vector<TYPE> c_3_chunks(4);
                    TYPE c_1;
                    TYPE c_2;
                    TYPE c_3;
                    TYPE c_4;

                    TYPE c_1_64;
                    TYPE c_3_64;

                    TYPE b_zero;

                    std::vector<TYPE> input_a_chunks(chunk_amount);
                    std::vector<TYPE> input_b_chunks(chunk_amount);
                    std::vector<TYPE> results_chunks(chunk_amount);
                    std::vector<TYPE> a_chunks(chunk_amount);
                    std::vector<TYPE> b_chunks(chunk_amount);
                    std::vector<TYPE> r_chunks(chunk_amount);
                    std::vector<TYPE> q_chunks(chunk_amount);
                    std::vector<TYPE> v_chunks(chunk_amount);

                    std::vector<TYPE> indic_1(chunk_amount);
                    std::vector<TYPE> indic_2(chunk_amount);

                    TYPE carry[3][carry_amount + 1];

                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        zkevm_word_type input_b = current_state.stack_top();
                        zkevm_word_type input_a = current_state.stack_top(1);

                        zkevm_word_type a = abs_word(input_a);

                        int shift = (input_b < 256) ? int(input_b) : 256;
                        zkevm_word_type r = a >> shift;

                        zkevm_word_type result =
                            is_negative(input_a) ? (r.is_zero() ? neg_one : negate_word(r)) : r;

                        zkevm_word_type b = zkevm_word_type(1) << shift;

                        zkevm_word_type q = b != 0u ? a % b : a;

                        zkevm_word_type v = wrapping_sub(q, b);
                        a_neg = is_negative(input_a);

                        input_a_chunks = zkevm_word_to_field_element<FieldType>(input_a);
                        input_b_chunks = zkevm_word_to_field_element<FieldType>(input_b);
                        results_chunks = zkevm_word_to_field_element<FieldType>(result);
                        a_chunks = zkevm_word_to_field_element<FieldType>(a);
                        b_chunks = zkevm_word_to_field_element<FieldType>(b);
                        r_chunks = zkevm_word_to_field_element<FieldType>(r);
                        q_chunks = zkevm_word_to_field_element<FieldType>(q);
                        v_chunks = zkevm_word_to_field_element<FieldType>(v);

                        zkevm_word_type two_15 = 32768;
                        auto biggest_input_a_chunk = zkevm_word_type(input_a) >> (256 - 16);

                        b0p = input_b % 16;
                        b0pp = (input_b / 16) % 16;
                        b0ppp = (input_b % 65536) / 256;
                        I1 = b0ppp.is_zero() ? 0 : b0ppp.inversed();

                        sum_part_b = 0;
                        b_sum = std::accumulate(b_chunks.begin(), b_chunks.end(), value_type(0));
                        for (std::size_t i = 1; i < chunk_amount; i++) {
                            sum_part_b += input_b_chunks[i];
                        }
                        I2 = sum_part_b.is_zero() ? 0 : sum_part_b.inversed();
                        z = (1 - b0ppp * I1) *
                            (1 -
                             sum_part_b * I2);  // z is zero if input_b >= 256, otherwise it is 1
                        tp = z * (static_cast<unsigned int>(1) << int(input_b % 16));
                        b_sum_inverse = b_sum.is_zero() ? 0 : b_sum.inversed();
                        b_zero = 1 - b_sum_inverse * b_sum;

                        two_powers = 0;
                        unsigned int pow = 1;
                        for (std::size_t i = 0; i < chunk_amount; i++) {
                            indic_1[i] = (b0p - i).is_zero() ? 0 : (b0p - i).inversed();
                            indic_2[i] = (b0pp - i).is_zero() ? 0 : (b0pp - i).inversed();
                            two_powers += (1 - (b0p - i) * indic_1[i]) * pow;
                            pow *= 2;
                        }

                        // note that we don't assign 64-chunks for a/b, as we can build them from
                        // 16-chunks with constraints under the same logic we only assign the 16 -
                        // bit

                        // chunks for carries
                        for (std::size_t i = 0; i < 4; i++) {
                            a_64_chunks.push_back(chunk_sum_64<value_type>(a_chunks, i));
                            b_64_chunks.push_back(chunk_sum_64<value_type>(b_chunks, i));
                            r_64_chunks.push_back(chunk_sum_64<value_type>(r_chunks, i));
                            q_64_chunks.push_back(chunk_sum_64<value_type>(q_chunks, i));
                        }
                    }

                    first_carryless = first_carryless_construct<TYPE>(a_64_chunks, b_64_chunks,
                                                                        r_64_chunks, q_64_chunks);
                    second_carryless = second_carryless_construct<TYPE>(
                            a_64_chunks, b_64_chunks, r_64_chunks, q_64_chunks);
                    third_carryless = third_carryless_construct<TYPE>(b_64_chunks, r_64_chunks);

                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        // caluclate first row carries
                        auto first_row_carries = first_carryless.data.base() >> 128;
                        c_1 = static_cast<value_type>(first_row_carries & (two_64 - 1).data.base());
                        c_2 = static_cast<value_type>(first_row_carries >> 64);
                        BOOST_ASSERT(first_carryless - c_1 * two_128 - c_2 * two_192 == 0);
                        c_1_chunks = chunk_64_to_16<FieldType>(c_1);
                        // no need for c_2 chunks as there is only a single chunk

                        c_1_64 = chunk_sum_64<TYPE>(c_1_chunks, 0);

                        // lookup constrain b0p < 16, b0pp < 16, b0ppp < 256
                        b0p_range_check = 4096 * b0p;
                        b0pp_range_check = 4096 * b0pp;
                        b0ppp_range_check = 256 * b0ppp;

                        carry[0][0] = 0;
                        // input_a + |input_a| = 2^256 carries
                        for (std::size_t i = 0; i < carry_amount - 1; i++) {
                            carry[0][i + 1] =
                                (carry[0][i] + input_a_chunks[3 * i] + a_chunks[3 * i] +
                                 (input_a_chunks[3 * i + 1] + a_chunks[3 * i + 1]) * two_16 +
                                 (input_a_chunks[3 * i + 2] + a_chunks[3 * i + 2]) * two_32) >=
                                two_48;
                        }
                        // The last carry, if input_a + |input_a| is ever needed, should be 1
                        // anyway, so we don't store it

                        r_sum = std::accumulate(r_chunks.begin(), r_chunks.end(), value_type(0));
                        r_sum_inverse = r_sum.is_zero() ? 0 : r_sum.inversed();

                        carry[1][0] = 0;
                        // result + r = 2^256 carries
                        for (std::size_t i = 0; i < carry_amount - 1; i++) {
                            carry[1][i + 1] =
                                (carry[1][i] + results_chunks[3 * i] + r_chunks[3 * i] +
                                 (results_chunks[3 * i + 1] + r_chunks[3 * i + 1]) * two_16 +
                                 (results_chunks[3 * i + 2] + r_chunks[3 * i + 2]) * two_32) >=
                                two_48;
                        }
                        // The last carry, if result + r is ever needed, should be 1 anyway, so we
                        // don't store it

                        carry[2][0] = 0;
                        for (std::size_t i = 0; i < carry_amount - 1; i++) {
                            carry[2][i + 1] =
                                (carry[2][i] + b_chunks[3 * i] + v_chunks[3 * i] +
                                 (b_chunks[3 * i + 1] + v_chunks[3 * i + 1]) * two_16 +
                                 (b_chunks[3 * i + 2] + v_chunks[3 * i + 2]) * two_32) >= two_48;
                        }
                        carry[2][carry_amount] =
                            (carry[2][carry_amount - 1] + b_chunks[3 * (carry_amount - 1)] +
                             v_chunks[3 * (carry_amount - 1)]) >= two_16;

                        b_zero = 1 - b_sum_inverse * b_sum;
                    }

                    allocate(b0p_range_check, 0, 4);
                    allocate(b0pp_range_check, 1, 4);
                    allocate(b0ppp_range_check, 2, 4);
                    allocate(b_zero, 39, 1);
                    for (std::size_t i = 0; i < 4; i++) {
                        allocate(c_1_chunks[i], 3 + i, 4);
                    }

                    for (std::size_t i = 0; i < chunk_amount; i++) {
                        allocate(input_a_chunks[i], i, 0);
                        allocate(a_chunks[i], i + chunk_amount, 0);
                        allocate(results_chunks[i], i, 1);
                        allocate(r_chunks[i], i + chunk_amount, 1);
                        allocate(q_chunks[i], i, 2);
                        allocate(v_chunks[i], i + chunk_amount, 2);
                        allocate(b_chunks[i], i, 3);
                        allocate(input_b_chunks[i], i + chunk_amount, 4);
                        res[i] = r_chunks[i];
                        constrain(b_zero * r_chunks[i]);
                    }

                    allocate(tp, 16, 3);
                    allocate(z, 17, 3);
                    allocate(I1, 39, 2);
                    allocate(I2, 40, 2);
                    allocate(two_powers, 41, 2);

                    allocate(b0p, 9, 4);
                    allocate(b0pp, 18, 3);
                    allocate(b0ppp, 19, 3);
                    allocate(sum_part_b, 42, 2);
                    allocate(b_sum, 40, 1);
                    allocate(b_sum_inverse, 41, 1);

                    constrain(tp - z * two_powers);
                    for (std::size_t i = 0; i < chunk_amount; i++) {
                        allocate(indic_1[i], i + 2 * chunk_amount, 4);
                        allocate(indic_2[i], i + 2 * chunk_amount, 3);
                        constrain((b0p - i) * (1 - (b0p - i) * indic_1[i]));
                        constrain((b0pp - i) * (1 - (b0pp - i) * indic_2[i]));
                        constrain(b_chunks[i] - tp * (1 - (b0pp - i) * indic_2[i]));
                    }

                    constrain(b_sum_inverse * (b_sum_inverse * b_sum - 1));
                    constrain(b_sum * (b_sum_inverse * b_sum - 1));
                    constrain(input_b_chunks[0] - b0p - 16 * b0pp - 256 * b0ppp);
                    constrain(b0ppp * (1 - b0ppp * I1));

                    TYPE op_sum_part_b_I2 = 1 - sum_part_b * I2;
                    allocate(op_sum_part_b_I2,44,2);
                    constrain(sum_part_b * op_sum_part_b_I2);
                    constrain(z - (1 - b0ppp * I1) * op_sum_part_b_I2);

                    allocate(first_carryless, 39, 0);
                    allocate(second_carryless, 40, 0);
                    allocate(third_carryless, 41, 0);
                    allocate(c_1_64, 42, 0);
                    allocate(c_2, 43, 0);

                    allocate(b_64_chunks[3], 7, 4);
                    allocate(r_64_chunks[3], 8, 4);

                    constrain(first_carryless - c_1_64 * two_128 - c_2 * two_192);
                    constrain(second_carryless + c_1_64 + c_2 * two_64);
                    constrain(c_2 * (c_2 - 1));
                    constrain(third_carryless);
                    constrain(b_64_chunks[3] * r_64_chunks[3]);

                    allocate(a_neg, 42, 1);
                    allocate(r_sum, 44, 0);
                    allocate(r_sum_inverse, 45, 0);
                    TYPE r_is_zero = 1 - r_sum * r_sum_inverse;
                    allocate(r_is_zero, 44, 1);
                    TYPE a_neg_r_sum = a_neg * r_sum;
                    allocate(a_neg_r_sum,43,1);

                    constrain(1 - b_sum_inverse * b_sum - b_zero);

                    allocate(carry[0][0], 32, 1);
                    for (std::size_t i = 0; i < carry_amount - 1; i++) {
                        allocate(carry[0][i + 1], 33 + i, 1);
                        constrain(a_neg * carry_on_addition_constraint(
                                              input_a_chunks[3 * i], input_a_chunks[3 * i + 1],
                                              input_a_chunks[3 * i + 2], a_chunks[3 * i],
                                              a_chunks[3 * i + 1], a_chunks[3 * i + 2], 0, 0, 0,
                                              carry[0][i], carry[0][i + 1], i == 0));
                        constrain(a_neg * carry[0][i + 1] * (1 - carry[0][i + 1]));
                    }
                    allocate(carry[0][carry_amount], 38, 1);
                    constrain(a_neg * last_carry_on_addition_constraint(
                                          input_a_chunks[3 * (carry_amount - 1)],
                                          a_chunks[3 * (carry_amount - 1)], 0,
                                          carry[0][carry_amount - 1], 1));
                    // ^^^ if ever input_a + |input_a| = 2^256 is used, the last carry should be 1

                    // since it is an overflow, if a_neg = 0, we should have input_a= a
                    for (std::size_t i = 0; i < chunk_amount; i++) {
                        constrain((1 - a_neg) *(input_a_chunks[i] - a_chunks[i]) );
                    }

                    //constrain(r_sum * (1 - r_sum_inverse * r_sum));
                    constrain(r_sum * r_is_zero);

                    allocate(carry[1][0], 32, 0);
                    for (std::size_t i = 0; i < carry_amount - 1; i++) {
                        allocate(carry[1][i + 1], 33 + i, 0);
                        constrain(a_neg_r_sum *
                                  carry_on_addition_constraint(
                                      results_chunks[3 * i], results_chunks[3 * i + 1],
                                      results_chunks[3 * i + 2], r_chunks[3 * i],
                                      r_chunks[3 * i + 1], r_chunks[3 * i + 2], 0, 0, 0,
                                      carry[1][i], carry[1][i + 1], i == 0));
                        constrain(a_neg_r_sum * carry[1][i + 1] * (1 - carry[1][i + 1]));
                    }
                    allocate(carry[1][carry_amount], 38, 0);
                    constrain(
                        a_neg_r_sum *
                        last_carry_on_addition_constraint(results_chunks[3 * (carry_amount - 1)],
                                                          r_chunks[3 * (carry_amount - 1)], 0,
                                                          carry[1][carry_amount - 1], 1));
                    // ^^^ if ever result + r = 2^256 is used, the last carry should be 1 since is
                    // actually an overflow

                    // if a_neg = 0 we should have r = result
                    // if a_neg = 1 and r_sum_0 = 0 we should have result = 2^257 - 1,
                    // i.e. every chunk of result should be 2^16 - 1
                    a_neg_2 = a_neg;
                    allocate(a_neg_2, 43, 2);
                    for (std::size_t i = 0; i < chunk_amount; i++) {
                       // constrain((1 - a_neg_2) * (results_chunks[i] - r_chunks[i]) + a_neg_2 * (1 - r_sum * r_sum_inverse) *(two_16 - 1 -results_chunks[i]));
                       constrain((1 - a_neg_2) * (results_chunks[i] - r_chunks[i]) + a_neg_2 * r_is_zero *(two_16 - 1 -results_chunks[i]));
                    }

                    allocate(carry[2][0], 32, 2);
                    for (std::size_t i = 0; i < carry_amount - 1; i++) {
                        allocate(carry[2][i + 1], 33 + i, 2);
                        constrain(carry_on_addition_constraint(
                            b_chunks[3 * i], b_chunks[3 * i + 1], b_chunks[3 * i + 2],
                            v_chunks[3 * i], v_chunks[3 * i + 1], v_chunks[3 * i + 2],
                            q_chunks[3 * i], q_chunks[3 * i + 1], q_chunks[3 * i + 2],
                            carry[2][i], carry[2][i + 1], i == 0));
                        constrain(carry[2][i + 1] * (1 - carry[2][i + 1]));
                    }
                    allocate(carry[2][carry_amount], 38, 2);
                    constrain(last_carry_on_addition_constraint(
                        b_chunks[3 * (carry_amount - 1)], v_chunks[3 * (carry_amount - 1)],
                        q_chunks[3 * (carry_amount - 1)], carry[2][carry_amount - 1],
                        carry[2][carry_amount]));

                    // last carry is 0 or 1, but should be 1 if z = 1
                    constrain((z + (1 - z) * carry[2][carry_amount]) *
                              (1 - carry[2][carry_amount]));

                    auto A_128 = chunks16_to_chunks128_reversed<TYPE>(input_a_chunks);
                    auto B_128 = chunks16_to_chunks128_reversed<TYPE>(input_b_chunks);
                    auto Res_128 = chunks16_to_chunks128_reversed<TYPE>(res);

                    TYPE A0, A1, B0, B1, Res0, Res1;

                    A0 = A_128.first;
                    A1 = A_128.second;
                    B0 = B_128.first;
                    B1 = B_128.second;
                    Res0 = Res_128.first;
                    Res1 = Res_128.second;
                    allocate(A0, 46, 0);
                    allocate(A1, 47, 0);
                    allocate(B0, 46, 2);
                    allocate(B1, 47, 2);
                    allocate(Res0, 46, 1);
                    allocate(Res1, 47, 1);

                    if constexpr (stage == GenerationStage::CONSTRAINTS) {
                        constrain(current_state.pc_next() - current_state.pc(4) -
                                  1);  // PC transition
                        constrain(current_state.gas(4) - current_state.gas_next() -
                                  3);  // GAS transition
                        constrain(current_state.stack_size(4) - current_state.stack_size_next() -
                                  1);  // stack_size transition
                        constrain(current_state.memory_size(4) -
                                  current_state.memory_size_next());  // memory_size transition
                        constrain(current_state.rw_counter_next() - current_state.rw_counter(4) -
                                  3);  // rw_counter transition
                        std::vector<TYPE> tmp;
                        tmp = rw_table<FieldType, stage>::stack_lookup(
                            current_state.call_id(2),
                            current_state.stack_size(2) - 1,
                            current_state.rw_counter(2),
                            TYPE(0),  // is_write
                            B0,
                            B1
                        );
                        lookup(tmp, "zkevm_rw");
                        tmp = rw_table<FieldType, stage>::stack_lookup(
                            current_state.call_id(0),
                            current_state.stack_size(0) - 2,
                            current_state.rw_counter(0) + 1,
                            TYPE(0),  // is_write
                            A0,
                            A1
                        );
                        lookup(tmp, "zkevm_rw");
                        tmp = rw_table<FieldType, stage>::stack_lookup(
                            current_state.call_id(1),
                            current_state.stack_size(1) - 2,
                            current_state.rw_counter(1) + 2,
                            TYPE(1),  // is_write
                            Res0,
                            Res1
                        );
                        lookup(tmp, "zkevm_rw");
                    }
                };
            };

            template<typename FieldType>
            class zkevm_sar_operation : public opcode_abstract<FieldType> {
              public:
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type
                        &context,
                    const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT>
                        &current_state) override  {
                    zkevm_sar_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context,
                                                                                  current_state);
                }
                virtual void fill_context(
                    typename generic_component<FieldType,
                                               GenerationStage::CONSTRAINTS>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS>
                        &current_state) override  {
                    zkevm_sar_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context,
                                                                                   current_state);
                }
                virtual std::size_t rows_amount() override { return 5; }
            };
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil
