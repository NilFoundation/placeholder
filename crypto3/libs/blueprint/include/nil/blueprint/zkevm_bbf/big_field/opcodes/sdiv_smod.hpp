//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
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
#include <nil/blueprint/zkevm_bbf/big_field/opcodes/abstract_opcode.hpp>
#include <numeric>

namespace nil::blueprint::bbf::zkevm_big_field{
    template<typename FieldType, GenerationStage stage>
    class zkevm_sdiv_smod_bbf : generic_component<FieldType, stage> {
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;
        using value_type = typename FieldType::value_type;

        constexpr static const std::size_t chunk_amount = 16;
        constexpr static const std::size_t carry_amount = 16 / 3 + 1;
        constexpr static const value_type two_15 = 32768;
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

        // The central relation is a = br + q. We also require that sgn(q) = sgn(a) and
        // that |q| < |b| if b != 0.
        // For b = 0 we must assure r = 0. For the SMOD operation we should
        // have q = 0 if b = 0, so we use a special q_out value.

        public:
        zkevm_sdiv_smod_bbf(context_type &context_object,
                            const opcode_input_type<FieldType, stage> &current_state,
                            bool is_div)
            : generic_component<FieldType, stage>(context_object, false),
                res(chunk_amount) {
            std::vector<TYPE> c_1_chunks(4);
            TYPE c_2;
            TYPE carry[3][carry_amount + 1];
            TYPE c_1_64;
            TYPE first_carryless;
            TYPE second_carryless;
            TYPE third_carryless;
            TYPE b_sum;
            TYPE b2;
            TYPE b_zero;
            TYPE b_sum_inverse;
            TYPE b2_inverse;
            TYPE b_nonzero;
            TYPE a_sum;
            TYPE a_sum_inverse;
            TYPE b_input_sum;
            TYPE b_lower_sum;
            TYPE b_lower_sum_inverse;
            TYPE q_sum;

            TYPE biggest_a_chunk;
            TYPE biggest_b_chunk;
            TYPE biggest_q_chunk;

            TYPE a_top;
            TYPE b_top;
            TYPE q_top;
            TYPE a_aux;
            TYPE b_aux;
            TYPE q_aux;
            TYPE a_neg;
            TYPE b_neg;
            TYPE q_neg;
            TYPE q_neg_2;
            TYPE a_ind;
            TYPE b_ind;
            TYPE b2_ind;

            TYPE is_overflow;

            std::vector<TYPE> a_64_chunks(4);
            std::vector<TYPE> b_64_chunks(4);
            std::vector<TYPE> r_64_chunks(4);
            std::vector<TYPE> q_64_chunks(4);

            std::vector<TYPE> a_chunks(chunk_amount);
            std::vector<TYPE> b_input_chunks(chunk_amount);
            std::vector<TYPE> b_chunks(chunk_amount);
            std::vector<TYPE> r_chunks(chunk_amount);
            std::vector<TYPE> q_chunks(chunk_amount);
            std::vector<TYPE> v_chunks(chunk_amount);
            std::vector<TYPE> b_abs_chunks(chunk_amount);
            std::vector<TYPE> q_abs_chunks(chunk_amount);
            std::vector<TYPE> q_out_chunks(chunk_amount);
            zkevm_word_type a,b,q;

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                a = current_state.stack_top();
                zkevm_word_type b_input = current_state.stack_top(1);

                bool overflow = (a == neg_one) && (b_input == min_neg);
                b = overflow ? 1 : b_input;
                is_overflow = overflow;

                zkevm_word_type a_abs = abs_word(a), b_abs = abs_word(b);

                zkevm_word_type r_abs = b != 0u ? a_abs / b_abs : 0u;
                zkevm_word_type q_abs = b != 0u ? a_abs % b_abs : a_abs,
                                r = (is_negative(a) == is_negative(b)) ? r_abs
                                                                        : negate_word(r_abs);
                q = is_negative(a) ? negate_word(q_abs) : q_abs;

                zkevm_word_type q_out =
                    b != 0u ? q : 0u;  // according to EVM spec a % 0 = 0
                zkevm_word_type v = wrapping_sub(q_abs, b_abs);
                zkevm_word_type result = is_div ? r : q_out;

                a_chunks = zkevm_word_to_field_element<FieldType>(a);
                b_input_chunks = zkevm_word_to_field_element<FieldType>(b_input);
                b_chunks = zkevm_word_to_field_element<FieldType>(b);
                r_chunks = zkevm_word_to_field_element<FieldType>(r);
                q_chunks = zkevm_word_to_field_element<FieldType>(q);
                v_chunks = zkevm_word_to_field_element<FieldType>(v);
                b_abs_chunks = zkevm_word_to_field_element<FieldType>(b_abs);
                q_abs_chunks = zkevm_word_to_field_element<FieldType>(q_abs);
                q_out_chunks = zkevm_word_to_field_element<FieldType>(q_out);

                // note that we don't assign 64-chunks for s/N, as we can build them
                // from 16-chunks with constraints under the same logic we only assign
                // the 16-bit chunks for carries
                for (std::size_t i = 0; i < 4; i++) {
                    a_64_chunks.push_back(chunk_sum_64<value_type>(a_chunks, i));
                    b_64_chunks.push_back(chunk_sum_64<value_type>(b_chunks, i));
                    r_64_chunks.push_back(chunk_sum_64<value_type>(r_chunks, i));
                    q_64_chunks.push_back(chunk_sum_64<value_type>(q_chunks, i));
                }
            }

            first_carryless = first_carryless_construct<TYPE>(a_64_chunks, b_64_chunks,
                                                                r_64_chunks, q_64_chunks);
            second_carryless = second_carryless_construct<TYPE>(a_64_chunks, b_64_chunks,
                                                                r_64_chunks, q_64_chunks);
            third_carryless = third_carryless_construct<TYPE>(b_64_chunks, r_64_chunks);

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                    // caluclate first row carries
                auto first_row_carries = first_carryless.to_integral() >> 128;
                value_type c_1 =
                    static_cast<value_type>(first_row_carries & (two_64 - 1).to_integral());
                c_2 = static_cast<value_type>(first_row_carries >> 64);
                c_1_chunks = chunk_64_to_16<FieldType>(c_1);
                // no need for c_2 chunks as there is only a single chunk
                auto second_row_carries =
                    (second_carryless + c_1 + c_2 * two_64).to_integral() >> 128;

                // value_type
                c_1_64 = chunk_sum_64<TYPE>(c_1_chunks, 0);

                auto third_row_carries = third_carryless.to_integral() >> 128;

                b_sum = std::accumulate(b_chunks.begin(), b_chunks.end(), value_type(0));
                a_sum = std::accumulate(a_chunks.begin(), a_chunks.end(), value_type(0)) -
                        16 * 65535;
                q_sum = std::accumulate(q_chunks.begin(), q_chunks.end(), value_type(0));
                b_input_sum = std::accumulate(b_input_chunks.begin(), b_input_chunks.end(),
                                                value_type(0));
                b_lower_sum =
                    b_input_sum -
                    b_input_chunks[chunk_amount - 1];  // all chunks except the last
                b2 = b_input_chunks[chunk_amount - 1] - two_15;

                bool a_indicator = a_sum == 0;
                bool b_indicator = b_lower_sum == 0;
                bool b2_indicator = b2 == 0;
                // a_ind and b_ind needs to be 1 when overflow is 1
                a_ind = a_indicator;
                b_ind = b_indicator;
                b2_ind = b2_indicator;
                b_lower_sum_inverse = b_indicator ? 0 : b_lower_sum.inversed();
                b_sum_inverse = b_sum == 0 ? 0 : b_sum.inversed();
                b2_inverse = b2 == 0 ? 0 : b2.inversed();
                a_sum_inverse = a_indicator ? 0 : a_sum.inversed();

                b_zero = 1 - b_sum_inverse * b_sum;
                b_nonzero = b_sum_inverse * b_sum;

                // compute signs of a,b and q
                // x + 2^15 = x_aux + 2^16*x_neg
                biggest_a_chunk = a >> (256 - 16);
                biggest_b_chunk = b >> (256 - 16);
                biggest_q_chunk = q >> (256 - 16);

                a_aux = (biggest_a_chunk > two_15 - 1) ? (biggest_a_chunk - two_15)
                                                        : biggest_a_chunk + two_15;
                a_neg = (biggest_a_chunk > two_15 - 1);
                a_top = a_aux + two_16 * a_neg - two_15;

                b_aux = (biggest_b_chunk > two_15 - 1) ? (biggest_b_chunk - two_15)
                                                        : biggest_b_chunk + two_15;
                b_neg = (biggest_b_chunk > two_15 - 1);
                b_top = b_aux + two_16 * b_neg - two_15;

                q_aux = (biggest_q_chunk > two_15 - 1) ? (biggest_q_chunk - two_15)
                                                        : biggest_q_chunk + two_15;
                q_neg = (biggest_q_chunk > two_15 - 1);
                q_top = q_aux + two_16 * q_neg - two_15;

                carry[0][0] = 0;
                carry[1][0] = 0;
                carry[2][0] = 0;
                // b + |b| = 2^256 carries
                for (std::size_t i = 0; i < carry_amount - 1; i++) {
                    carry[0][i + 1] =
                        (carry[0][i] + b_chunks[3 * i] + b_abs_chunks[3 * i] +
                            (b_chunks[3 * i + 1] + b_abs_chunks[3 * i + 1]) * two_16 +
                            (b_chunks[3 * i + 2] + b_abs_chunks[3 * i + 2]) * two_32) >=
                        two_48;
                }
                // The last carry, if b + |b| is ever needed, should be 1 anyway, so we
                // don't store it

                // q + |q| = 2^256 carries
                for (std::size_t i = 0; i < carry_amount - 1; i++) {
                    carry[1][i + 1] =
                        (carry[1][i] + q_chunks[3 * i] + q_abs_chunks[3 * i] +
                            (q_chunks[3 * i + 1] + q_abs_chunks[3 * i + 1]) * two_16 +
                            (q_chunks[3 * i + 2] + q_abs_chunks[3 * i + 2]) * two_32) >=
                        two_48;
                }
                // The last carry, if q + |q| is ever needed, should be 1 anyway, so we
                // don't store it

                // |q| < |b| <=> |b| + v = |q| + 2^T, i.e. the last carry is 1.
                // We use t to store the addition carries and enforce the above constraint
                // if b != 0
                // |b| + v carries
                for (std::size_t i = 0; i < carry_amount - 1; i++) {
                    carry[2][i + 1] =
                        (carry[2][i] + b_abs_chunks[3 * i] + v_chunks[3 * i] +
                            (b_abs_chunks[3 * i + 1] + v_chunks[3 * i + 1]) * two_16 +
                            (b_abs_chunks[3 * i + 2] + v_chunks[3 * i + 2]) * two_32) >=
                        two_48;
                }
                carry[2][carry_amount] =
                    (carry[2][carry_amount - 1] + b_abs_chunks[3 * (carry_amount - 1)] +
                        v_chunks[3 * (carry_amount - 1)]) >= two_16;
            }

            allocate(b_zero, 39, 2);
            allocate(b_nonzero, 39, 3);
            allocate(b_neg, 39, 1);
            allocate(is_overflow, 32, 0);
            allocate(q_neg, 39, 4);

            for (std::size_t i = 0; i < chunk_amount; i++) {
                allocate(a_chunks[i], i, 0);
                allocate(b_input_chunks[i], i + chunk_amount, 0);
                allocate(b_chunks[i], i, 1);
                allocate(b_abs_chunks[i], i + chunk_amount, 1);
                allocate(r_chunks[i], i, 2);
                allocate(v_chunks[i], i + chunk_amount, 2);
                allocate(q_chunks[i], i, 3);
                allocate(q_abs_chunks[i], i + chunk_amount, 3);
                constrain(b_zero * r_chunks[i]);

                if (i == 0) {
                    constrain(b_chunks[0] - is_overflow * (1 - b_input_chunks[0]) -
                                b_input_chunks[0]);
                } else {
                    constrain(b_chunks[i] - (1 - is_overflow) * b_input_chunks[i]);
                };

                // if b_neg = 0, we should have b = |b|
                constrain((1 - b_neg) * (b_chunks[i] - b_abs_chunks[i]));
                // if q_neg = 0, we should have q = |q|
                constrain((1 - q_neg) * (q_chunks[i] - q_abs_chunks[i]));

                if (!is_div) {
                    allocate(q_out_chunks[i], i, 4);
                    constrain(b_nonzero * (q_chunks[i] - q_out_chunks[i]) +
                                (1 - b_nonzero) * q_out_chunks[i]);
                    constrain(b_nonzero * (q_chunks[i] - q_out_chunks[i]) +
                                (1 - b_nonzero) * q_out_chunks[i]);
                    res[i] = q_out_chunks[i];
                } else {
                    res[i] = r_chunks[i];
                }
            }


            allocate(carry[0][0], 32, 1);
            for (std::size_t i = 0; i < carry_amount - 1; i++) {
                allocate(carry[0][i + 1], 33 + i, 1);
                constrain(b_neg * carry_on_addition_constraint(
                                        b_chunks[3 * i], b_chunks[3 * i + 1],
                                        b_chunks[3 * i + 2], b_abs_chunks[3 * i],
                                        b_abs_chunks[3 * i + 1], b_abs_chunks[3 * i + 2],
                                        0, 0, 0, carry[0][i], carry[0][i + 1],
                                        i == 0));
                constrain(b_neg * carry[0][i + 1] * (1 - carry[0][i + 1]));
            }
            constrain(b_neg * last_carry_on_addition_constraint(
                                    b_chunks[3 * (carry_amount - 1)],
                                    b_abs_chunks[3 * (carry_amount - 1)], 0,
                                    carry[0][carry_amount - 1], 1));

            allocate(carry[1][0], 32, 4);
            for (std::size_t i = 0; i < carry_amount - 1; i++) {
                allocate(carry[1][i + 1], 33 + i, 4);
                constrain(q_neg * carry_on_addition_constraint(
                                        q_chunks[3 * i], q_chunks[3 * i + 1],
                                        q_chunks[3 * i + 2], q_abs_chunks[3 * i],
                                        q_abs_chunks[3 * i + 1], q_abs_chunks[3 * i + 2],
                                        0, 0, 0, carry[1][i], carry[1][i + 1],
                                        i == 0));
                constrain(q_neg * carry[1][i + 1] * (1 - carry[1][i + 1]));
            }
            constrain(q_neg * last_carry_on_addition_constraint(
                                    q_chunks[3 * (carry_amount - 1)],
                                    q_abs_chunks[3 * (carry_amount - 1)], 0,
                                    carry[1][carry_amount - 1], 1));

            allocate(carry[2][0], 32, 3);
            for (std::size_t i = 0; i < carry_amount - 1; i++) {
                allocate(carry[2][i + 1], 33 + i, 2);
                constrain(carry_on_addition_constraint(
                    b_abs_chunks[3 * i], b_abs_chunks[3 * i + 1], b_abs_chunks[3 * i + 2],
                    v_chunks[3 * i], v_chunks[3 * i + 1], v_chunks[3 * i + 2],
                    q_abs_chunks[3 * i], q_abs_chunks[3 * i + 1], q_abs_chunks[3 * i + 2],
                    carry[2][i], carry[2][i + 1], i == 0));
                constrain(carry[2][i + 1] * (1 - carry[2][i + 1]));
            }

            allocate(carry[2][carry_amount], 38, 2);
            constrain(last_carry_on_addition_constraint(
                b_abs_chunks[3 * (carry_amount - 1)], v_chunks[3 * (carry_amount - 1)],
                q_abs_chunks[3 * (carry_amount - 1)], carry[2][carry_amount - 1],
                carry[2][carry_amount]));
            // last carry is 0 or 1, but should be 1 if b_nonzero = 1
            constrain((b_nonzero + (1 - b_nonzero) * carry[2][carry_amount]) *
                        (1 - carry[2][carry_amount]));

            allocate(first_carryless, 40, 4);
            allocate(c_1_64, 41, 4);
            allocate(c_2, 42, 4);
            constrain(c_2 * (c_2 - 1));
            constrain(first_carryless - c_1_64 * two_128 - c_2 * two_192);
            allocate(second_carryless, 43, 4);
            constrain(second_carryless + c_1_64 + c_2 * two_64);
            allocate(third_carryless, 44, 4);
            constrain(third_carryless);
            allocate(b_sum, 33, 0);
            allocate(b_sum_inverse, 34, 0);
            allocate(b_lower_sum, 35, 0);
            allocate(b_lower_sum_inverse, 36, 0);
            constrain(b_sum_inverse * (b_sum_inverse * b_sum - 1));
            constrain(b_sum * (b_sum_inverse * b_sum - 1));
            constrain(b_lower_sum_inverse * (b_lower_sum_inverse * b_lower_sum - 1));
            constrain(b_lower_sum * (b_lower_sum_inverse * b_lower_sum - 1));

            allocate(b_64_chunks[3], 16, 4);
            allocate(r_64_chunks[3], 17, 4);
            constrain(b_64_chunks[3] * r_64_chunks[3]);


            allocate(a_neg, 40, 1);
            allocate(a_top, 41, 1);
            allocate(a_aux, 42, 1);
            constrain(a_neg * (1 - a_neg));
            constrain(a_top + two_15 - two_16 * a_neg - a_aux);

            allocate(b_top, 43, 1);
            allocate(b_aux, 44, 1);
            // b_top + 2^15 = b_aux + 2^16 * b_neg
            constrain(b_neg * (1 - b_neg));
            constrain(b_top + two_15 - two_16 * b_neg - b_aux);

            allocate(q_top, 45, 1);
            allocate(q_aux, 46, 1);

            //q_top + 2^15 = q_aux + 2^16 * q_neg
            constrain(q_neg * (1 - q_neg));
            q_neg_2 = q_neg;
            allocate(q_neg_2, 40,2);
            constrain(q_top + two_15 - two_16 * q_neg_2 - q_aux);

            allocate(q_sum, 47, 1);
            constrain(q_sum * (a_neg - q_neg_2));

            allocate(a_sum, 37, 0);
            allocate(a_sum_inverse, 38, 0);
            constrain(a_sum * (1 - a_sum * a_sum_inverse));

            allocate(a_ind, 39, 0);
            allocate(b_ind, 40, 0);
            allocate(b2_ind, 41, 0);
            allocate(b2_inverse, 42, 0);

            constrain((b_input_chunks[chunk_amount - 1] - two_15) *
                        (1 - (b_input_chunks[chunk_amount - 1] - two_15) * b2_inverse));

            constrain(a_ind - (1 - a_sum * a_sum_inverse));
            constrain(b_ind - (1 - b_lower_sum * b_lower_sum_inverse));
            constrain(b2_ind -
                        (1 - (b_input_chunks[chunk_amount - 1] - two_15) * b2_inverse));
            constrain(is_overflow - a_ind * b_ind * b2_ind);

            auto A_128 = chunks16_to_chunks128_reversed<TYPE>(a_chunks);
            auto B_128 = chunks16_to_chunks128_reversed<TYPE>(b_input_chunks);
            auto Res_128 = chunks16_to_chunks128_reversed<TYPE>(res);

            TYPE A0, A1, B0, B1, Res0, Res1;

            A0 = A_128.first;
            A1 = A_128.second;
            B0 = B_128.first;
            B1 = B_128.second;
            Res0 = Res_128.first;
            Res1 = Res_128.second;
            allocate(A0, 44, 0);
            allocate(A1, 45, 0);
            allocate(B0, 46, 0);
            allocate(B1, 47, 0);
            if (is_div){
                allocate(Res0, 46, 2);
                allocate(Res1, 47, 2);
            }
            else{
                allocate(Res0, 46, 4);
                allocate(Res1, 47, 4);
            }

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                constrain(current_state.pc_next() - current_state.pc(4) -
                            1);  // PC transition
                constrain(current_state.gas(4) - current_state.gas_next() -
                            5);  // GAS transition
                constrain(current_state.stack_size(4) - current_state.stack_size_next() -
                            1);  // stack_size transition
                constrain(current_state.memory_size(4) -
                            current_state.memory_size_next());  // memory_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(4) -
                            3);  // rw_counter transition
                std::vector<TYPE> tmp;

                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(1),
                    current_state.stack_size(1) - 1,
                    current_state.rw_counter(1),
                    TYPE(0),  // is_write
                    A0,
                    A1
                );
                lookup(tmp, "zkevm_rw");

                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(2),
                    current_state.stack_size(2) - 2,
                    current_state.rw_counter(2) + 1,
                    TYPE(0),  // is_write
                    B0,
                    B1
                );

                lookup(tmp, "zkevm_rw");
                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(3),
                    current_state.stack_size(3) - 2,
                    current_state.rw_counter(3) + 2,
                    TYPE(1),  // is_write
                    Res0,
                    Res1
                );
                lookup(tmp, "zkevm_rw");
            }
        }
    };

    template<typename FieldType>
    class zkevm_sdiv_smod_operation : public opcode_abstract<FieldType> {
        public:
        zkevm_sdiv_smod_operation(bool _is_div) : is_div(_is_div) {}
        virtual std::size_t rows_amount() override { return 5; }
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type
                &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT>
                &current_state) override {
            zkevm_sdiv_smod_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(
                context, current_state, is_div);
        }
        virtual void fill_context(
            typename generic_component<FieldType,
                                        GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS>
                &current_state) override {
            zkevm_sdiv_smod_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(
                context, current_state, is_div);
        }

        protected:
        bool is_div;
    };
}