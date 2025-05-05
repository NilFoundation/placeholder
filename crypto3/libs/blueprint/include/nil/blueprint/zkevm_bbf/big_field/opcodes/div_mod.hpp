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
    class zkevm_div_mod_bbf : generic_component<FieldType, stage> {
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
        zkevm_div_mod_bbf(context_type &context_object,
                            const opcode_input_type<FieldType, stage> &current_state,
                            bool is_div)
            : generic_component<FieldType, stage>(context_object, false),res(chunk_amount) {
            std::vector<TYPE> c_1_chunks(4);
            TYPE c_2;
            TYPE carry[carry_amount + 1];
            TYPE c_1_64;
            TYPE first_carryless;
            TYPE second_carryless;
            TYPE third_carryless;
            TYPE b_sum;
            TYPE b_zero;
            TYPE b_sum_inverse;
            TYPE b_nonzero;

            std::vector<TYPE> a_64_chunks(4);
            std::vector<TYPE> b_64_chunks(4);
            std::vector<TYPE> r_64_chunks(4);
            std::vector<TYPE> q_64_chunks(4);

            std::vector<TYPE> a_chunks(chunk_amount);
            std::vector<TYPE> b_chunks(chunk_amount);
            std::vector<TYPE> r_chunks(chunk_amount);
            std::vector<TYPE> q_chunks(chunk_amount);
            std::vector<TYPE> v_chunks(chunk_amount);
            std::vector<TYPE> q_out_chunks(chunk_amount);

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                zkevm_word_type a = current_state.stack_top();
                zkevm_word_type b = current_state.stack_top(1);

                zkevm_word_type r = b != 0u ? a / b : 0u;
                zkevm_word_type q = b != 0u ? a % b : a;
                zkevm_word_type q_out =
                    b != 0u ? q : 0u;  // according to EVM spec a % 0 = 0

                zkevm_word_type v = wrapping_sub(q, b);

                zkevm_word_type result = is_div ? r : q_out;

                a_chunks = zkevm_word_to_field_element<FieldType>(a);
                b_chunks = zkevm_word_to_field_element<FieldType>(b);
                r_chunks = zkevm_word_to_field_element<FieldType>(r);
                q_chunks = zkevm_word_to_field_element<FieldType>(q);
                v_chunks = zkevm_word_to_field_element<FieldType>(v);
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
            third_carryless = third_carryless_construct<TYPE>(a_64_chunks, b_64_chunks);

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                // caluclate first row carries
                auto first_row_carries = first_carryless.to_integral() >> 128;
                value_type c_1 = static_cast<value_type>(first_row_carries & (two_64 - 1).to_integral());
                c_2 = static_cast<value_type>(first_row_carries >> 64);
                c_1_chunks = chunk_64_to_16<FieldType>(c_1);
                // no need for c_2 chunks as there is only a single chunk
                auto second_row_carries =
                    (second_carryless +c_1 + c_2 * two_64).to_integral() >>128;

                // value_type
                c_1_64 = chunk_sum_64<TYPE>(c_1_chunks, 0);

                auto third_row_carries = third_carryless.to_integral() >> 128;

                b_sum = std::accumulate(b_chunks.begin(), b_chunks.end(), value_type(0));
                b_sum_inverse = b_sum == 0 ? 0 : b_sum.inversed();
                b_zero = 1 - b_sum_inverse * b_sum;
                b_nonzero = b_sum_inverse * b_sum;

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

            allocate(b_zero,32,2);
            allocate(b_nonzero,33,2);

            for (std::size_t i = 0; i < chunk_amount; i++) {
                allocate(a_chunks[i], i, 0);
                allocate(b_chunks[i], i + chunk_amount, 0);
                allocate(v_chunks[i], i, 1);
                allocate(q_chunks[i], chunk_amount + i, 1);
                allocate(r_chunks[i], i, 2);
                constrain(b_zero * r_chunks[i]);

                if (!is_div) {
                    allocate(q_out_chunks[i], chunk_amount+ i, 2);
                    constrain(b_nonzero * (q_chunks[i] - q_out_chunks[i]) +
                                (1 - b_nonzero) * q_out_chunks[i]);
                    res[i] = q_out_chunks[i];
                } else {
                    res[i] = r_chunks[i];
                }
            }

            allocate(carry[0], 32, 0);
            for (std::size_t i = 0; i < carry_amount - 1; i++) {
                allocate(carry[i + 1], 33 + i, 0);
                constrain(carry_on_addition_constraint(
                    b_chunks[3 * i], b_chunks[3 * i + 1], b_chunks[3 * i + 2],
                    v_chunks[3 * i], v_chunks[3 * i + 1], v_chunks[3 * i + 2],
                    q_chunks[3 * i], q_chunks[3 * i + 1], q_chunks[3 * i + 2], carry[i],
                    carry[i + 1], i == 0));
                constrain(carry[i + 1] * (1 - carry[i + 1]));
            }
            allocate(carry[carry_amount], 38, 0);
            constrain(last_carry_on_addition_constraint(
                b_chunks[3 * (carry_amount - 1)], v_chunks[3 * (carry_amount - 1)],
                q_chunks[3 * (carry_amount - 1)], carry[carry_amount - 1],
                carry[carry_amount]));

            // last carry is 0 or 1, but should be 1 if b_nonzero = 1
            constrain((b_nonzero +
                        (1 - b_nonzero) * carry[carry_amount]) * (1 - carry[carry_amount]));

            allocate(first_carryless, 32, 1);
            allocate(c_1_64, 33, 1);
            allocate(c_2, 34, 1);

            constrain(first_carryless - c_1_64 * two_128 - c_2 * two_192);

            allocate(second_carryless, 35, 1);
            constrain(third_carryless + c_1_64 + c_2 * two_64);

            allocate(third_carryless, 33, 3);
            constrain(third_carryless);
            allocate(b_sum, 34, 2);
            allocate(b_sum_inverse, 35, 2);
            constrain(b_sum_inverse * (b_sum_inverse * b_sum - 1));
            constrain(b_sum * (b_sum_inverse * b_sum - 1));

            allocate(b_64_chunks[3], 0, 3);
            allocate(r_64_chunks[3], 1, 3);
            constrain(b_64_chunks[3] * r_64_chunks[3]);

            constrain(c_2 * (c_2 - 1));

            auto A_128 = chunks16_to_chunks128_reversed<TYPE>(a_chunks);
            auto B_128 = chunks16_to_chunks128_reversed<TYPE>(b_chunks);
            auto Res_128 = chunks16_to_chunks128_reversed<TYPE>(res);

            TYPE A0, A1, B0, B1, Res0, Res1;

            A0 = A_128.first;
            A1 = A_128.second;
            B0 = B_128.first;
            B1 = B_128.second;
            Res0 = Res_128.first;
            Res1 = Res_128.second;
            allocate(A0, 39, 0);
            allocate(A1, 40, 0);
            allocate(B0, 41, 0);
            allocate(B1, 42, 0);
            allocate(Res0, 39, 2);
            allocate(Res1, 40, 2);

            if constexpr (stage == GenerationStage::CONSTRAINTS) {

                constrain(current_state.pc_next() - current_state.pc(3) - 1);  // PC transition
                constrain(current_state.gas(3) - current_state.gas_next() - 5);  // GAS transition
                constrain(current_state.stack_size(3) - current_state.stack_size_next() - 1);  // stack_size transition
                constrain(current_state.memory_size(3) - current_state.memory_size_next());  // memory_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(3) - 3);  // rw_counter transition
                std::vector<TYPE> tmp;

                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 1,
                    current_state.rw_counter(0),
                    TYPE(0),  // is_write
                    A0,
                    A1
                );
                lookup(tmp, "zkevm_rw");
                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 2,
                    current_state.rw_counter(0) + 1,
                    TYPE(0),  // is_write
                    B0,
                    B1
                );
                lookup(tmp, "zkevm_rw");

                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(2),
                    current_state.stack_size(2) - 2,
                    current_state.rw_counter(2) + 2,
                    TYPE(1),  // is_write
                    Res0,
                    Res1
                );
                lookup(tmp, "zkevm_rw");
            }

        }
    };

    template<typename FieldType>
    class zkevm_div_mod_operation : public opcode_abstract<FieldType> {
        public:
        zkevm_div_mod_operation(bool _is_div) : is_div(_is_div) {}
        virtual std::size_t rows_amount() override { return 4; }
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type
                &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT>
                &current_state)  override  {
            zkevm_div_mod_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state, is_div);
        }
        virtual void fill_context(
            typename generic_component<FieldType,
                                        GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS>
                &current_state) override  {
            zkevm_div_mod_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state, is_div);
        }

        protected:
        bool is_div;
    };
}
