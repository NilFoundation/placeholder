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
#include <nil/blueprint/zkevm_bbf/big_field/opcodes/abstract_opcode.hpp>
#include <numeric>

namespace nil::blueprint::bbf::zkevm_big_field{
    template<typename FieldType, GenerationStage stage>
    class zkevm_shl_bbf : public generic_component<FieldType, stage> {
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

        using value_type = typename FieldType::value_type;

        constexpr static const std::size_t chunk_amount = 16;
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
                                        const std::vector<T> &r_64_chunks) const {
            return a_64_chunks[0] * b_64_chunks[0] +
                    two_64 *
                        (a_64_chunks[0] * b_64_chunks[1] + a_64_chunks[1] * b_64_chunks[0]) -
                    r_64_chunks[0] - two_64 * r_64_chunks[1];
        }

        template<typename T>
        T second_carryless_construct(const std::vector<T> &a_64_chunks,
                                        const std::vector<T> &b_64_chunks,
                                        const std::vector<T> &r_64_chunks) {
            return (a_64_chunks[0] * b_64_chunks[2] + a_64_chunks[1] * b_64_chunks[1] +
                    a_64_chunks[2] * b_64_chunks[0] - r_64_chunks[2]) +
                    two_64 *
                        (a_64_chunks[0] * b_64_chunks[3] + a_64_chunks[1] * b_64_chunks[2] +
                        a_64_chunks[2] * b_64_chunks[1] + a_64_chunks[3] * b_64_chunks[0] -
                        r_64_chunks[3]);
        }

        std::vector<TYPE> res;

        public:
        zkevm_shl_bbf(context_type &context_object,
                        const opcode_input_type<FieldType, stage> &current_state)
            : generic_component<FieldType, stage>(context_object, false),
                res(chunk_amount) {
            TYPE first_carryless;
            TYPE second_carryless;

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
            TYPE sum_b;

            std::vector<TYPE> a_64_chunks(4);
            std::vector<TYPE> b_64_chunks(4);
            std::vector<TYPE> r_64_chunks(4);

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

            std::vector<TYPE> indic_1(chunk_amount);
            std::vector<TYPE> indic_2(chunk_amount);

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                zkevm_word_type input_b = current_state.stack_top();
                zkevm_word_type a = current_state.stack_top(1);

                int shift = (input_b < 256) ? int(input_b) : 256;

                zkevm_word_type result = a << shift;

                zkevm_word_type b = zkevm_word_type(1) << shift;

                input_b_chunks = zkevm_word_to_field_element<FieldType>(input_b);
                a_chunks = zkevm_word_to_field_element<FieldType>(a);
                b_chunks = zkevm_word_to_field_element<FieldType>(b);
                r_chunks = zkevm_word_to_field_element<FieldType>(result);

                b0p = input_b % 16;
                b0pp = (input_b / 16) % 16;
                b0ppp = (input_b % 65536) / 256;
                I1 = b0ppp.is_zero() ? 0 : b0ppp.inversed();

                sum_b = 0;
                for (std::size_t i = 1; i < chunk_amount; i++) {
                    sum_b += input_b_chunks[i];
                }
                I2 = sum_b.is_zero() ? 0 : sum_b.inversed();
                z = (1 - b0ppp * I1) *
                    (1 - sum_b * I2);  // z is zero if input_b >= 256, otherwise it is 1
                tp = z * (static_cast<unsigned int>(1) << int(input_b % 16));

                // note that we don't assign 64-chunks for a/b, as we can build them from
                // 16-chunks with constraints under the same logic we only assign the 16 -
                // bit

                // chunks for carries
                for (std::size_t i = 0; i < 4; i++) {
                    a_64_chunks.push_back(chunk_sum_64<value_type>(a_chunks, i));
                    b_64_chunks.push_back(chunk_sum_64<value_type>(b_chunks, i));
                    r_64_chunks.push_back(chunk_sum_64<value_type>(r_chunks, i));
                }
            }


            first_carryless =
                first_carryless_construct<TYPE>(a_64_chunks, b_64_chunks, r_64_chunks);
            second_carryless =
                    second_carryless_construct<TYPE>(a_64_chunks, b_64_chunks, r_64_chunks);

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                // caluclate first row carries
                auto first_row_carries = first_carryless.to_integral() >> 128;
                c_1 = static_cast<value_type>(first_row_carries & (two_64 - 1).to_integral());
                c_2 = static_cast<value_type>(first_row_carries >> 64);
                c_1_chunks = chunk_64_to_16<FieldType>(c_1);
                // no need for c_2 chunks as there is only a single chunk

                auto second_row_carries =
                    (second_carryless + c_1 + c_2 * two_64) .to_integral() >> 128;
                c_3 = static_cast<value_type>(second_row_carries & (two_64 - 1).to_integral());
                c_4 = static_cast<value_type>(second_row_carries >> 64);
                c_3_chunks = chunk_64_to_16<FieldType>(c_3);

                c_1_64 = chunk_sum_64<TYPE>(c_1_chunks, 0);
                c_3_64 = chunk_sum_64<TYPE>(c_3_chunks, 0);

                // lookup constrain b0p < 16, b0pp < 16, b0ppp < 256
                b0p_range_check = 4096 * b0p;
                b0pp_range_check = 4096 * b0pp;
                b0ppp_range_check = 256 * b0ppp;

                two_powers = 0;
                unsigned int pow = 1;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    indic_1[i] = (b0p - i).is_zero() ? 0 : (b0p - i).inversed();
                    indic_2[i] = (b0pp - i).is_zero() ? 0 : (b0pp - i).inversed();
                    two_powers += (1 - (b0p - i) * indic_1[i]) * pow;
                    pow *= 2;
                }
            }

            allocate(b0p_range_check, 0, 2);
            allocate(b0pp_range_check, 1, 2);
            allocate(b0ppp_range_check, 2, 2);
            for (std::size_t i = 0; i < 4; i++) {
                allocate(c_1_chunks[i], 3 + i, 2);
                allocate(c_3_chunks[i], 7 + i, 2);
            }

            for (std::size_t i = 0; i < chunk_amount; i++) {
                allocate(a_chunks[i], i, 0);
                allocate(b_chunks[i], i + chunk_amount, 0);
                allocate(input_b_chunks[i], i, 1);
                allocate(r_chunks[i], i + chunk_amount, 1);
                res[i] = r_chunks[i];
            }

            allocate(tp, 14, 2);
            allocate(z, 15, 2);
            allocate(I1, 33, 0);
            allocate(I2, 34, 0);

            allocate(b0p, 11, 2);
            allocate(b0pp, 12, 2);
            allocate(b0ppp, 13, 2);
            allocate(two_powers, 32, 0);
            allocate(sum_b, 35, 0);

            constrain(tp - z * two_powers);
            for (std::size_t i = 0; i < chunk_amount; i++) {
                allocate(indic_1[i], i + 2 * chunk_amount, 1);
                allocate(indic_2[i], i + 2 * chunk_amount, 2);
                constrain((b0p - i) * (1 - (b0p - i) * indic_1[i]));
                constrain((b0pp - i) * (1 - (b0pp - i) * indic_2[i]));
                constrain(b_chunks[i] - tp * (1 - (b0pp - i) * indic_2[i]));
            }

            constrain(input_b_chunks[0] - b0p - 16 * b0pp - 256 * b0ppp);
            constrain(b0ppp * (1 - b0ppp * I1));

            TYPE op_sum_b_I2 = 1 - sum_b * I2;
            allocate(op_sum_b_I2,36,0);
            constrain(sum_b * op_sum_b_I2);
            constrain(z - (1 - b0ppp * I1) * op_sum_b_I2);

            allocate(first_carryless, 16, 2);
            allocate(second_carryless, 17, 2);
            allocate(c_1_64, 18, 2);
            allocate(c_2, 19, 2);
            allocate(c_3_64, 20, 2);
            allocate(c_4, 21, 2);

            constrain(first_carryless - c_1_64 * two_128 - c_2 * two_192);
            constrain(second_carryless + c_1_64 + c_2 * two_64 - c_3_64 * two_128 -
                        c_4 * two_192);
            // add constraints for c_2/c_4: c_2 is 0/1, c_4 is 0/1/2/3
            constrain(c_2 * (c_2 - 1));
            // constrain(c_4 * (c_4 - 1) * (c_4 - 2) * (c_4 - 3));
            TYPE c_4_check = c_4 * 16384; // 16-bit range-check on c_4_check <=> c_4 < 4
            allocate(c_4_check, 22, 2);

            auto A_128 = chunks16_to_chunks128_reversed<TYPE>(a_chunks);
            auto B_128 = chunks16_to_chunks128_reversed<TYPE>(input_b_chunks);
            auto Res_128 = chunks16_to_chunks128_reversed<TYPE>(res);

            TYPE A0, A1, B0, B1, Res0, Res1;
            A0 = A_128.first;
            A1 = A_128.second;
            B0 = B_128.first;
            B1 = B_128.second;
            Res0 = Res_128.first;
            Res1 = Res_128.second;
            allocate(A0, 37, 0);
            allocate(A1, 38, 0);
            allocate(B0, 39, 0);
            allocate(B1, 40, 0);
            allocate(Res0, 41, 0);
            allocate(Res1, 42, 0);

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                constrain(current_state.pc_next() - current_state.pc(2) -
                            1);  // PC transition
                constrain(current_state.gas(2) - current_state.gas_next() -
                            3);  // GAS transition
                constrain(current_state.stack_size(2) - current_state.stack_size_next() -
                            1);  // stack_size transition
                constrain(current_state.memory_size(2) -
                            current_state.memory_size_next());  // memory_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(2) -
                            3);  // rw_counter transition
                std::vector<TYPE> tmp;
                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 1,
                    current_state.rw_counter(0),
                    TYPE(0),  // is_write
                    B0,
                    B1
                );
                lookup(tmp, "zkevm_rw");
                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(1),
                    current_state.stack_size(1) - 2,
                    current_state.rw_counter(1) + 1,
                    TYPE(0),  // is_write
                    A0,
                    A1
                );
                lookup(tmp, "zkevm_rw");
                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 2,
                    current_state.rw_counter(0) + 2,
                    TYPE(1),  // is_write
                    Res0,
                    Res1
                );
                lookup(tmp, "zkevm_rw");
            }
        }
    };

    template<typename FieldType>
    class zkevm_shl_operation : public opcode_abstract<FieldType> {
        public:
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type
                &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT>
                &current_state) override  {
            zkevm_shl_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context,
                                                                            current_state);
        }
        virtual void fill_context(
            typename generic_component<FieldType,
                                        GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS>
                &current_state)  override {
            zkevm_shl_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context,
                                                                            current_state);
        }
        virtual std::size_t rows_amount() override { return 3; }
    };
}