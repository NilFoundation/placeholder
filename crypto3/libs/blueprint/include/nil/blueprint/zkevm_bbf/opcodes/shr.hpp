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
#include <nil/blueprint/zkevm/zkevm_word.hpp>
#include <nil/blueprint/zkevm_bbf/types/opcode.hpp>
#include <numeric>

namespace nil {
    namespace blueprint {
        namespace bbf {
            template<typename FieldType>
            class opcode_abstract;

            template<typename FieldType, GenerationStage stage>
            class zkevm_shr_bbf : public generic_component<FieldType, stage> {
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
                constexpr static const value_type two_64 = 0x10000000000000000_cppui_modular254;
                constexpr static const value_type two_128 =
                    0x100000000000000000000000000000000_cppui_modular254;
                constexpr static const value_type two_192 =
                    0x1000000000000000000000000000000000000000000000000_cppui_modular254;

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
                zkevm_shr_bbf(context_type &context_object,
                              const opcode_input_type<FieldType, stage> &current_state)
                    : generic_component<FieldType, stage>(context_object, false),
                      res(chunk_amount) {
                    return;
                    using integral_type = boost::multiprecision::number<
                        boost::multiprecision::backends::cpp_int_modular_backend<257>>;

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
                    TYPE b_zero;

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

                    std::vector<TYPE> input_b_chunks(chunk_amount);
                    std::vector<TYPE> a_chunks(chunk_amount);
                    std::vector<TYPE> b_chunks(chunk_amount);
                    std::vector<TYPE> r_chunks(chunk_amount);
                    std::vector<TYPE> q_chunks(chunk_amount);
                    std::vector<TYPE> v_chunks(chunk_amount);

                    TYPE carry[carry_amount + 1];

                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        zkevm_word_type a = current_state.stack_top(1);
                        zkevm_word_type input_b = current_state.stack_top();

                        int shift =
                            (integral_type(input_b) < 256) ? int(integral_type(input_b)) : 256;
                        integral_type r_integral = integral_type(a) >> shift;

                        zkevm_word_type b = zkevm_word_type(integral_type(1) << shift);

                        zkevm_word_type result =
                            zkevm_word_type::backend_type(r_integral.backend());
                        zkevm_word_type q = b != 0u ? a % b : a;

                        bool t_last = integral_type(q) < integral_type(b);
                        zkevm_word_type v = zkevm_word_type(integral_type(q) +
                                                            integral_type(t_last) * zkevm_modulus -
                                                            integral_type(b));

                        input_b_chunks = zkevm_word_to_field_element<FieldType>(input_b);
                        a_chunks = zkevm_word_to_field_element<FieldType>(a);
                        b_chunks = zkevm_word_to_field_element<FieldType>(b);
                        r_chunks = zkevm_word_to_field_element<FieldType>(result);
                        q_chunks = zkevm_word_to_field_element<FieldType>(q);
                        v_chunks = zkevm_word_to_field_element<FieldType>(v);

                        b0p = integral_type(input_b) % 16;
                        b0pp = (integral_type(input_b) / 16) % 16;
                        b0ppp = (integral_type(input_b) % 65536) / 256;
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
                        two_powers =
                            (static_cast<unsigned int>(1) << int(integral_type(input_b) % 16));
                        tp = z * two_powers;
                        b_zero = 1 - b_sum_inverse * b_sum;
                        b_sum_inverse = b_sum.is_zero() ? 0 : b_sum.inversed();

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
                        // caluclate first row carries
                        first_carryless = first_carryless_construct<TYPE>(a_64_chunks, b_64_chunks,
                                                                          r_64_chunks, q_64_chunks);
                        auto first_row_carries = first_carryless.data >> 128;

                        c_1 = value_type(first_row_carries & (two_64 - 1).data);
                        c_2 = value_type(first_row_carries >> 64);
                        BOOST_ASSERT(first_carryless - c_1 * two_128 - c_2 * two_192 == 0);
                        c_1_chunks = chunk_64_to_16<FieldType>(c_1);
                        // no need for c_2 chunks as there is only a single chunk
                        second_carryless = second_carryless_construct<TYPE>(
                            a_64_chunks, b_64_chunks, r_64_chunks, q_64_chunks);
                        c_1_64 = chunk_sum_64<TYPE>(c_1_chunks, 0);

                        third_carryless = third_carryless_construct<TYPE>(b_64_chunks, r_64_chunks);

                        // lookup constrain b0p < 16, b0pp < 16, b0ppp < 256
                        b0p_range_check = 4096 * b0p;
                        b0pp_range_check = 4096 * b0pp;
                        b0ppp_range_check = 256 * b0ppp;

                        carry[0] = 0;
                        for (std::size_t i = 0; i < carry_amount - 1; i++) {
                            carry[i + 1] =
                                (carry[i] + b_chunks[3 * i] + v_chunks[3 * i] +
                                 (b_chunks[3 * i + 1] + v_chunks[3 * i + 1]) * two_16 +
                                 (b_chunks[3 * i + 2] + v_chunks[3 * i + 2]) * two_32) >= two_48;
                        }
                        carry[carry_amount] =
                            (carry[carry_amount - 1] + b_chunks[3 * (carry_amount - 1)] +
                             v_chunks[3 * (carry_amount - 1)]) >= two_16;
                    }

                    allocate(b0p_range_check, 0, 3);
                    allocate(b0pp_range_check, 1, 3);
                    allocate(b0ppp_range_check, 2, 3);
                    allocate(b_zero, 37, 1);
                    for (std::size_t i = 0; i < 4; i++) {
                        allocate(c_1_chunks[i], 3 + i, 3);
                    }

                    for (std::size_t i = 0; i < chunk_amount; i++) {
                        allocate(input_b_chunks[i], i, 0);
                        allocate(r_chunks[i], i + chunk_amount, 0);
                        allocate(a_chunks[i], i, 1);
                        allocate(b_chunks[i], i + chunk_amount, 1);
                        allocate(q_chunks[i], i, 2);
                        allocate(v_chunks[i], i + chunk_amount, 2);
                        res[i] = r_chunks[i];
                        constrain(b_zero * r_chunks[i]);
                    }

                    allocate(tp, 32, 1);
                    allocate(z, 33, 1);
                    allocate(I1, 34, 1);
                    allocate(I2, 35, 1);
                    allocate(two_powers, 36, 1);

                    constrain(tp - z * two_powers);

                    allocate(b0p, 32, 0);
                    allocate(b0pp, 33, 0);
                    allocate(b0ppp, 34, 0);
                    allocate(sum_part_b, 35, 0);
                    allocate(b_sum, 36, 0);
                    allocate(b_sum_inverse, 37, 0);

                    constrain(b_sum_inverse * (b_sum_inverse * b_sum - 1));
                    constrain(b_sum * (b_sum_inverse * b_sum - 1));
                    constrain(input_b_chunks[0] - b0p - 16 * b0pp - 256 * b0ppp);
                    constrain(b0ppp * (1 - b0ppp * I1));

                    constrain(sum_part_b * (1 - sum_part_b * I2));
                    constrain((z - (1 - b0ppp * I1) * (1 - sum_part_b * I2)));

                    allocate(first_carryless, 32, 2);
                    allocate(second_carryless, 33, 2);
                    allocate(third_carryless, 34, 2);
                    allocate(c_1_64, 35, 2);
                    allocate(c_2, 36, 2);

                    allocate(b_64_chunks[3], 7, 3);
                    allocate(r_64_chunks[3], 8, 3);

                    constrain(first_carryless - c_1_64 * two_128 - c_2 * two_192);
                    constrain(second_carryless + c_1_64 + c_2 * two_64);
                    constrain(c_2 * (c_2 - 1));
                    constrain(third_carryless);
                    constrain(b_64_chunks[3] * r_64_chunks[3]);

                    allocate(carry[0], 37, 2);
                    for (std::size_t i = 0; i < carry_amount - 1; i++) {
                        allocate(carry[i + 1], 38 + i, 2);
                        constrain(carry_on_addition_constraint(
                            b_chunks[3 * i], b_chunks[3 * i + 1], b_chunks[3 * i + 2],
                            v_chunks[3 * i], v_chunks[3 * i + 1], v_chunks[3 * i + 2],
                            q_chunks[3 * i], q_chunks[3 * i + 1], q_chunks[3 * i + 2], carry[i],
                            carry[i + 1], i == 0));
                        constrain(carry[i + 1] * (1 - carry[i + 1]));
                    }
                    allocate(carry[carry_amount], 43, 2);
                    constrain(last_carry_on_addition_constraint(
                        b_chunks[3 * (carry_amount - 1)], v_chunks[3 * (carry_amount - 1)],
                        q_chunks[3 * (carry_amount - 1)], carry[carry_amount - 1],
                        carry[carry_amount]));
                    // carry[carry_amount] is 0 or 1, but should be 1 if z = 1
                    constrain((z + (1 - z) * carry[carry_amount]) * (1 - carry[carry_amount]));

                    auto A_128 = chunks16_to_chunks128_reversed<TYPE>(a_chunks);
                    auto B_128 = chunks16_to_chunks128_reversed<TYPE>(input_b_chunks);
                    auto Res_128 = chunks16_to_chunks128_reversed<TYPE>(res);

                    TYPE A0, A1, B0, B1, Res0, Res1;
                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        A0 = A_128.first;
                        A1 = A_128.second;
                        B0 = B_128.first;
                        B1 = B_128.second;
                        Res0 = Res_128.first;
                        Res1 = Res_128.second;
                    }
                    allocate(A0, 38, 0);
                    allocate(A1, 38, 1);
                    allocate(B0, 39, 0);
                    allocate(B1, 39, 1);
                    allocate(Res0, 40, 0);
                    allocate(Res1, 40, 1);

                    constrain(A0 - A_128.first);
                    constrain(A1 - A_128.second);
                    constrain(B0 - B_128.first);
                    constrain(B1 - B_128.second);
                    constrain(Res0 - Res_128.first);
                    constrain(Res1 - Res_128.second);

                    if constexpr (stage == GenerationStage::CONSTRAINTS) {
                        constrain(current_state.pc_next() - current_state.pc(3) -
                                  1);  // PC transition
                        constrain(current_state.gas(3) - current_state.gas_next() -
                                  3);  // GAS transition
                        constrain(current_state.stack_size(3) - current_state.stack_size_next() -
                                  1);  // stack_size transition
                        constrain(current_state.memory_size(3) -
                                  current_state.memory_size_next());  // memory_size transition
                        constrain(current_state.rw_counter_next() - current_state.rw_counter(3) -
                                  3);  // rw_counter transition
                        std::vector<TYPE> tmp;
                        tmp = {TYPE(rw_op_to_num(rw_operation_type::stack)),
                               current_state.call_id(1),
                               current_state.stack_size(1) - 1,
                               TYPE(0),  // storage_key_hi
                               TYPE(0),  // storage_key_lo
                               TYPE(0),  // field
                               current_state.rw_counter(1) + 1,
                               TYPE(0),  // is_write
                               A0,
                               A1};
                        lookup(tmp, "zkevm_rw");
                        tmp = {TYPE(rw_op_to_num(rw_operation_type::stack)),
                               current_state.call_id(1),
                               current_state.stack_size(1) - 2,
                               TYPE(0),  // storage_key_hi
                               TYPE(0),  // storage_key_lo
                               TYPE(0),  // field
                               current_state.rw_counter(1),
                               TYPE(0),  // is_write
                               B0,
                               B1};
                        lookup(tmp, "zkevm_rw");
                        tmp = {TYPE(rw_op_to_num(rw_operation_type::stack)),
                               current_state.call_id(1),
                               current_state.stack_size(1) - 2,
                               TYPE(0),  // storage_key_hi
                               TYPE(0),  // storage_key_lo
                               TYPE(0),  // field
                               current_state.rw_counter(1) + 2,
                               TYPE(1),  // is_write
                               Res0,
                               Res1};
                        lookup(tmp, "zkevm_rw");
                    }
                }
            };

            template<typename FieldType>
            class zkevm_shr_operation : public opcode_abstract<FieldType> {
            public:
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type
                        &context,
                    const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT>
                        &current_state) {
                   zkevm_shr_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context,
                                                                                 current_state);
                }
                virtual void fill_context(
                    typename generic_component<FieldType,
                                               GenerationStage::CONSTRAINTS>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS>
                        &current_state) {
                   zkevm_shr_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context,
                                                                                  current_state);
                }
                virtual std::size_t rows_amount() override { return 4; }
            };
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil