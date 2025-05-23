//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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

namespace nil {
    namespace blueprint {
        namespace bbf {
            namespace zkevm_big_field {
                template<typename FieldType, GenerationStage stage>
                class zkevm_addmod_bbf : public generic_component<FieldType, stage> {
                    using generic_component<FieldType, stage>::allocate;
                    using generic_component<FieldType, stage>::copy_constrain;
                    using generic_component<FieldType, stage>::constrain;
                    using generic_component<FieldType, stage>::lookup;
                    using generic_component<FieldType, stage>::lookup_table;

                    using value_type = typename FieldType::value_type;
                    using var = crypto3::zk::snark::plonk_variable<typename FieldType::value_type>;

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
                    zkevm_addmod_bbf(context_type &context_object,
                                    const opcode_input_type<FieldType, stage> &current_state,
                                    bool make_links = true)
                        : generic_component<FieldType, stage>(context_object, false), res(chunk_amount) {
                        std::vector<TYPE> c_1_chunks(4);
                        TYPE c_2;
                        TYPE c_3;
                        TYPE carry[2][carry_amount + 1];
                        TYPE N_sum_inverse;
                        TYPE r_overflow;
                        TYPE s_overflow;
                        TYPE N_nonzero;
                        TYPE N_sum;
                        TYPE c_1_64;
                        TYPE first_carryless;
                        TYPE second_carryless;
                        TYPE third_carryless;
                        TYPE two_192_cell;
                        TYPE two_128_cell;
                        TYPE two_64_cell;
                        std::vector<TYPE> N_64_chunks(4);
                        std::vector<TYPE> r_64_chunks(4);
                        std::vector<TYPE> s_64_chunks(4);
                        std::vector<TYPE> q_64_chunks(4);

                        std::vector<TYPE> a_chunks(chunk_amount);
                        std::vector<TYPE> b_chunks(chunk_amount);
                        std::vector<TYPE> N_chunks(chunk_amount);
                        std::vector<TYPE> s_chunks(chunk_amount);
                        std::vector<TYPE> r_chunks(chunk_amount);
                        std::vector<TYPE> q_chunks(chunk_amount);
                        std::vector<TYPE> v_chunks(chunk_amount);
                        std::vector<TYPE> q_out_chunks(chunk_amount);

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            zkevm_word_type a = current_state.stack_top();
                            zkevm_word_type b = current_state.stack_top(1);
                            zkevm_word_type N = current_state.stack_top(2);

                            auto s_full = nil::crypto3::multiprecision::big_uint<257>(a) + b;
                            zkevm_word_type s = s_full.truncate<256>();
                            s_overflow = s_full.bit_test(256);
                            auto r_full = N != 0u ? s_full / N : 0u;
                            r_overflow = r_full.bit_test(256);
                            zkevm_word_type r = r_full.truncate<256>();
                            // word_type q = N != 0u ? s % N : s;
                            zkevm_word_type q = wrapping_sub(s_full, wrapping_mul(r_full, N)).truncate<256>();
                            zkevm_word_type q_out =
                                N != 0u ? q : 0u;  // according to EVM spec s % 0 = 0
                            zkevm_word_type v = wrapping_sub(q, N);

                            a_chunks = zkevm_word_to_field_element<FieldType>(a);
                            b_chunks = zkevm_word_to_field_element<FieldType>(b);
                            N_chunks = zkevm_word_to_field_element<FieldType>(N);
                            s_chunks = zkevm_word_to_field_element<FieldType>(s);
                            r_chunks = zkevm_word_to_field_element<FieldType>(r);
                            q_chunks = zkevm_word_to_field_element<FieldType>(q);
                            v_chunks = zkevm_word_to_field_element<FieldType>(v);
                            q_out_chunks = zkevm_word_to_field_element<FieldType>(q_out);
                            // note that we don't assign 64-chunks for s/N, as we can build them
                            // from 16-chunks with constraints under the same logic we only assign
                            // the 16-bit chunks for carries
                            for (std::size_t i = 0; i < 4; i++) {
                                s_64_chunks.push_back(chunk_sum_64<value_type>(s_chunks, i));
                                N_64_chunks.push_back(chunk_sum_64<value_type>(N_chunks, i));
                                r_64_chunks.push_back(chunk_sum_64<value_type>(r_chunks, i));
                                q_64_chunks.push_back(chunk_sum_64<value_type>(q_chunks, i));
                            }
                        }
                        first_carryless = first_carryless_construct<TYPE>(s_64_chunks, N_64_chunks,
                                                                            r_64_chunks, q_64_chunks);
                        second_carryless = second_carryless_construct<TYPE>(s_64_chunks, N_64_chunks,
                                                                            r_64_chunks, q_64_chunks);
                        third_carryless = third_carryless_construct<TYPE>(N_64_chunks, r_64_chunks);

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            // caluclate first row carries
                            auto first_row_carries =first_carryless.to_integral()>>128;
                            value_type c_1 =
                                static_cast<value_type>(first_row_carries & (two_64 - 1).to_integral());
                            c_2 = static_cast<value_type>(first_row_carries >> 64);
                            c_1_chunks = chunk_64_to_16<FieldType>(c_1);
                            // no need for c_2 chunks as there is only a single chunk
                            auto second_row_carries =
                                (second_carryless + c_1 + c_2 * two_64).to_integral() >> 128;
                            c_3 = static_cast<value_type>(second_row_carries);
                            std::vector<value_type> c_3_chunks = chunk_64_to_16<FieldType>(c_3);
                            value_type N_sum =
                                std::accumulate(N_chunks.begin(), N_chunks.end(), value_type(0));
                            N_sum_inverse = N_sum == 0 ? 0 : N_sum.inversed();
                            N_nonzero = N_sum_inverse * N_sum;
                            // value_type
                            c_1_64 = chunk_sum_64<TYPE>(c_1_chunks, 0);

                            auto third_row_carries = third_carryless.to_integral() >> 128;

                            carry[0][0] = 0;
                            carry[1][0] = 0;
                            two_192_cell = two_192;
                            two_128_cell = two_128;
                            two_64_cell = two_64;
                        }

                        // TODO: replace with memory access, which would also do range checks!
                        // also we can pack slightly more effectively
                        for (std::size_t i = 0; i < carry_amount - 1; i++) {
                            allocate(a_chunks[3 * i], 0, i);
                            allocate(b_chunks[3 * i], 1, i);
                            allocate(s_chunks[3 * i], 2, i);

                            allocate(a_chunks[3 * i + 1], 3, i);
                            allocate(b_chunks[3 * i + 1], 4, i);
                            allocate(s_chunks[3 * i + 1], 5, i);

                            allocate(a_chunks[3 * i + 2], 6, i);
                            allocate(b_chunks[3 * i + 2], 7, i);
                            allocate(s_chunks[3 * i + 2], 8, i);
                        }
                        allocate(a_chunks[chunk_amount - 1], 26, 3);
                        allocate(b_chunks[chunk_amount - 1], 27, 3);
                        allocate(s_chunks[chunk_amount - 1], 28, 3);

                        for (std::size_t i = 0; i < carry_amount - 1; i++) {
                            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                                carry[0][i + 1] =
                                    (carry[0][i] + a_chunks[3 * i] + b_chunks[3 * i] +
                                    (a_chunks[3 * i + 1] + b_chunks[3 * i + 1]) * two_16 +
                                    (a_chunks[3 * i + 2] + b_chunks[3 * i + 2]) * two_32) >= two_48;
                            }
                            allocate(carry[0][i], 9, i);
                            allocate(carry[0][i + 1], 10, i);
                            constrain(carry_on_addition_constraint(
                                a_chunks[3 * i], a_chunks[3 * i + 1], a_chunks[3 * i + 2],
                                b_chunks[3 * i], b_chunks[3 * i + 1], b_chunks[3 * i + 2],
                                s_chunks[3 * i], s_chunks[3 * i + 1], s_chunks[3 * i + 2], carry[0][i],
                                carry[0][i + 1], i == 0));
                            constrain(carry[0][i + 1] * (1 - carry[0][i + 1]));
                        }

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            carry[0][carry_amount] =
                                (carry[0][carry_amount - 1] + a_chunks[3 * (carry_amount - 1)] +
                                b_chunks[3 * (carry_amount - 1)]) >= two_16;
                        }
                        allocate(carry[0][carry_amount - 1], 29, 3);
                        allocate(carry[0][carry_amount], 30, 3);

                        constrain(last_carry_on_addition_constraint(
                            a_chunks[3 * (carry_amount - 1)], b_chunks[3 * (carry_amount - 1)],
                            s_chunks[3 * (carry_amount - 1)], carry[0][carry_amount - 1],
                            carry[0][carry_amount]));
                        constrain(carry[0][carry_amount] * (1 - carry[0][carry_amount]));

                        for (std::size_t i = 0; i < carry_amount - 1; i++) {
                            allocate(N_chunks[3 * i], 11, i);
                            allocate(q_chunks[3 * i], 12, i);
                            allocate(v_chunks[3 * i], 13, i);

                            allocate(N_chunks[3 * i + 1], 14, i);
                            allocate(q_chunks[3 * i + 1], 15, i);
                            allocate(v_chunks[3 * i + 1], 16, i);

                            allocate(N_chunks[3 * i + 2], 17, i);
                            allocate(q_chunks[3 * i + 2], 18, i);
                            allocate(v_chunks[3 * i + 2], 19, i);
                        }
                        allocate(N_chunks[chunk_amount - 1], 26, 4);
                        allocate(q_chunks[chunk_amount - 1], 27, 4);
                        allocate(v_chunks[chunk_amount - 1], 28, 4);

                        for (std::size_t i = 0; i < carry_amount - 1; i++) {
                            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                                carry[1][i + 1] =
                                    (carry[1][i] + N_chunks[3 * i] + v_chunks[3 * i] +
                                    (N_chunks[3 * i + 1] + v_chunks[3 * i + 1]) * two_16 +
                                    (N_chunks[3 * i + 2] + v_chunks[3 * i + 2]) * two_32) >= two_48;
                            }
                            allocate(carry[1][i], 20, i);
                            allocate(carry[1][i + 1], 21, i);
                            constrain(carry_on_addition_constraint(
                                N_chunks[3 * i], N_chunks[3 * i + 1], N_chunks[3 * i + 2],
                                v_chunks[3 * i], v_chunks[3 * i + 1], v_chunks[3 * i + 2],
                                q_chunks[3 * i], q_chunks[3 * i + 1], q_chunks[3 * i + 2], carry[1][i],
                                carry[1][i + 1], i == 0));
                            constrain(carry[1][i + 1] * (1 - carry[1][i + 1]));
                        }

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            carry[1][carry_amount] =
                                (carry[1][carry_amount - 1] + N_chunks[3 * (carry_amount - 1)] +
                                v_chunks[3 * (carry_amount - 1)]) >= two_16;
                        }
                        allocate(carry[1][carry_amount - 1], 29, 4);
                        allocate(carry[1][carry_amount], 30, 4);
                        constrain(last_carry_on_addition_constraint(
                            N_chunks[3 * (carry_amount - 1)], v_chunks[3 * (carry_amount - 1)],
                            q_chunks[3 * (carry_amount - 1)], carry[1][carry_amount - 1],
                            carry[1][carry_amount]));

                        // // carry[1][carry_amount] is 0 or 1, but should be 1 if N_nonzero = 1

                        constrain((N_nonzero + (1 - N_nonzero) * carry[1][carry_amount]) *
                                (1 - carry[1][carry_amount]));

                        for (std::size_t i = 0; i < carry_amount - 1; i++) {
                            allocate(q_out_chunks[3 * i], 22, i);
                            allocate(q_out_chunks[3 * i + 1], 23, i);
                            allocate(q_out_chunks[3 * i + 2], 24, i);
                        }
                        allocate(q_out_chunks[chunk_amount - 1], 31, 4);

                        for (std::size_t i = 0; i < chunk_amount; i++) {
                            if (i % 3 == 0) {
                                allocate(N_nonzero, 25, i / 3);
                            }
                            constrain((N_nonzero * (q_chunks[i] - q_out_chunks[i]) +
                                    (1 - N_nonzero) * q_out_chunks[i]));
                            res[i] = q_out_chunks[i];
                        }

                        allocate(first_carryless, 32, 0);
                        allocate(c_1_64, 33, 0);
                        allocate(c_2, 34, 0);
                        constrain(first_carryless - c_1_64 * two_128 - c_2 * two_192);

                        allocate(second_carryless, 32, 1);
                        allocate(c_3, 33, 1);
                        constrain(second_carryless + c_1_64 + c_2 * two_64 - c_3 * two_128);

                        allocate(N_64_chunks[0], 31, 2);
                        allocate(third_carryless, 32, 2);
                        allocate(r_overflow, 33, 2);
                        allocate(s_overflow, 34, 2);
                        allocate(N_sum, 35, 2);
                        allocate(N_sum_inverse, 36, 2);
                        constrain(third_carryless + r_overflow * N_64_chunks[0] + c_3 -
                                s_overflow * N_sum * N_sum_inverse);

                        allocate(N_64_chunks[3], 30, 1);
                        allocate(r_64_chunks[3], 31, 1);
                        constrain(N_64_chunks[3] * r_64_chunks[3]);

                        constrain(c_2 * (c_2 - 1));
                        constrain(c_3 * (c_3 - 1));
                        constrain(r_overflow * (1 - r_overflow));

                        auto A_128 = chunks16_to_chunks128_reversed<TYPE>(a_chunks);
                        auto B_128 = chunks16_to_chunks128_reversed<TYPE>(b_chunks);
                        auto N_128 = chunks16_to_chunks128_reversed<TYPE>(N_chunks);
                        auto Res_128 = chunks16_to_chunks128_reversed<TYPE>(res);

                        TYPE A0, A1, B0, B1, N0, N1, Res0, Res1;
                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            A0 = A_128.first;
                            A1 = A_128.second;
                            B0 = B_128.first;
                            B1 = B_128.second;
                            N0 = N_128.first;
                            N1 = N_128.second;
                            Res0 = Res_128.first;
                            Res1 = Res_128.second;
                        }
                        allocate(A0, 34, 3); allocate(A1, 34, 1);
                        allocate(B0, 35, 3); allocate(B1, 35, 1);
                        allocate(N0, 36, 3); allocate(N1, 36, 1);
                        allocate(Res0, 37, 3); allocate(Res1, 37, 1);

                        constrain(A0 - A_128.first); constrain(A1 - A_128.second);
                        constrain(B0 - B_128.first); constrain(B1 - B_128.second);
                        constrain(N0 - N_128.first); constrain(N1 - N_128.second);
                        constrain(Res0 - Res_128.first); constrain(Res1 - Res_128.second);
                        if constexpr (stage == GenerationStage::CONSTRAINTS) {
                            constrain(current_state.pc_next() - current_state.pc(4) - 1);  // PC transition
                            constrain(current_state.gas(4) - current_state.gas_next() - 8);  // GAS transition
                            constrain(current_state.stack_size(4) - current_state.stack_size_next() - 2);  // stack_size transition
                            constrain(current_state.memory_size(4) - current_state.memory_size_next());  // memory_size transition
                            constrain(current_state.rw_counter_next() - current_state.rw_counter(4) - 4);  // rw_counter transition
                            std::vector<TYPE> tmp;
                            tmp = rw_table<FieldType, stage>::stack_lookup(
                                current_state.call_id(2),
                                current_state.stack_size(2) - 1,
                                current_state.rw_counter(2),
                                TYPE(0),  // is_write
                                A0,
                                A1
                            );
                            lookup(tmp, "zkevm_rw");
                            tmp = rw_table<FieldType, stage>::stack_lookup(
                                current_state.call_id(1),
                                current_state.stack_size(1) - 2,
                                current_state.rw_counter(1) + 1,
                                TYPE(0),  // is_write
                                B0,
                                B1
                            );
                            lookup(tmp, "zkevm_rw");
                            tmp = rw_table<FieldType, stage>::stack_lookup(
                                current_state.call_id(2),
                                current_state.stack_size(2) - 3,
                                current_state.rw_counter(2) + 2,
                                TYPE(0),  // is_write
                                N0,
                                N1
                            );
                            lookup(tmp, "zkevm_rw");
                            tmp = rw_table<FieldType, stage>::stack_lookup(
                                current_state.call_id(2),
                                current_state.stack_size(2) - 3,
                                current_state.rw_counter(2) + 3,
                                TYPE(1),  // is_write
                                Res0,
                                Res1
                            );
                            lookup(tmp, "zkevm_rw");
                        }
                    }
                };

                template<typename FieldType>
                class zkevm_addmod_operation : public opcode_abstract<FieldType> {
                public:
                    virtual void fill_context(
                        typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type
                            &context,
                        const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT>
                            &current_state
                    ) override  {
                        zkevm_addmod_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context,
                                                                                        current_state);
                    }
                    virtual void fill_context(
                        typename generic_component<FieldType,
                                                GenerationStage::CONSTRAINTS>::context_type &context,
                        const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS>
                            &current_state
                    ) override  {
                        zkevm_addmod_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(
                            context, current_state);
                    }
                    virtual std::size_t rows_amount() override { return 5; }
                };
            }
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil
