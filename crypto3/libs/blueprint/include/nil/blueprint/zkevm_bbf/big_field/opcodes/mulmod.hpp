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
#include <nil/blueprint/zkevm_bbf/big_field/opcodes/abstract_opcode.hpp>
#include <numeric>

namespace nil::blueprint::bbf::zkevm_big_field{
    template<typename FieldType, GenerationStage stage>
    class zkevm_mulmod_bbf : public generic_component<FieldType, stage> {
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
        constexpr static const value_type two128 =
            0x100000000000000000000000000000000_big_uint254;
        constexpr static const value_type two192 =
            0x1000000000000000000000000000000000000000000000000_big_uint254;

    public:
        using typename generic_component<FieldType, stage>::TYPE;
        using typename generic_component<FieldType, stage>::context_type;

        template<typename T, typename V = T>
        T chunk_sum_64(const std::vector<V> &chunks, const unsigned char chunk_idx) const {
            BOOST_ASSERT(chunk_idx < 8);  // corrected to allow 512-bit numbers
            return chunks[4 * chunk_idx] + chunks[4 * chunk_idx + 1] * two_16 +
                chunks[4 * chunk_idx + 2] * two_32 + chunks[4 * chunk_idx + 3] * two_48;
        }

        // a = b*r, a and r have 8 64-bit chunks, b has 4 64-bit chunks
        template<typename T>
        T first_carryless_construct(const std::vector<T> &a_64_chunks,
                                    const std::vector<T> &b_64_chunks,
                                    const std::vector<T> &r_64_chunks) const {
            return r_64_chunks[0] * b_64_chunks[0] +
                two_64 *
                    (r_64_chunks[0] * b_64_chunks[1] + r_64_chunks[1] * b_64_chunks[0]) -
                a_64_chunks[0] - two_64 * a_64_chunks[1];
        }

        template<typename T>
        T second_carryless_construct(const std::vector<T> &a_64_chunks,
                                    const std::vector<T> &b_64_chunks,
                                    const std::vector<T> &r_64_chunks) const {
            return (r_64_chunks[0] * b_64_chunks[2] + r_64_chunks[1] * b_64_chunks[1] +
                    r_64_chunks[2] * b_64_chunks[0]) +
                two_64 *
                    (r_64_chunks[0] * b_64_chunks[3] + r_64_chunks[1] * b_64_chunks[2] +
                        r_64_chunks[2] * b_64_chunks[1] + r_64_chunks[3] * b_64_chunks[0]) -
                a_64_chunks[2] - two_64 * a_64_chunks[3];
        }

        template<typename T>
        T third_carryless_construct(const std::vector<T> &a_64_chunks,
                                    const std::vector<T> &b_64_chunks,
                                    const std::vector<T> &r_64_chunks) const {
            return (r_64_chunks[1] * b_64_chunks[3] + r_64_chunks[2] * b_64_chunks[2] +
                    r_64_chunks[3] * b_64_chunks[1] + r_64_chunks[4] * b_64_chunks[0]) +
                two_64 *
                    (r_64_chunks[2] * b_64_chunks[3] + r_64_chunks[3] * b_64_chunks[2] +
                        r_64_chunks[4] * b_64_chunks[1] + r_64_chunks[5] * b_64_chunks[0]) -
                a_64_chunks[4] - two_64 * a_64_chunks[5];
        }

        template<typename T>
        T forth_carryless_construct(const std::vector<T> &a_64_chunks,
                                    const std::vector<T> &b_64_chunks,
                                    const std::vector<T> &r_64_chunks) const {
            return (r_64_chunks[3] * b_64_chunks[3] + r_64_chunks[4] * b_64_chunks[2] +
                    r_64_chunks[5] * b_64_chunks[1] + r_64_chunks[6] * b_64_chunks[0]) +
                two_64 *
                    (r_64_chunks[4] * b_64_chunks[3] + r_64_chunks[5] * b_64_chunks[2] +
                        r_64_chunks[6] * b_64_chunks[1] + r_64_chunks[7] * b_64_chunks[0]) -
                a_64_chunks[6] - two_64 * a_64_chunks[7];
        }
        TYPE carry_on_addition_constraint(
            TYPE a_0, TYPE a_1, TYPE a_2,
            TYPE b_0, TYPE b_1, TYPE b_2,
            TYPE r_0, TYPE r_1, TYPE r_2,
            TYPE last_carry, TYPE result_carry,
            bool first_constraint = false
        ) {
            if (first_constraint) {
                // no last carry for first constraint
                return (a_0 + b_0) + (a_1 + b_1) * two_16 + (a_2 + b_2) * two_32
                    - r_0 - r_1 * two_16 - r_2 * two_32 - result_carry * two_48;
            } else {
                return last_carry
                    + (a_0 + b_0) + (a_1 + b_1) * two_16 + (a_2 + b_2) * two_32
                    - r_0 - r_1 * two_16 - r_2 * two_32 - result_carry * two_48;
            }
        };
        TYPE last_carry_on_addition_constraint(TYPE a_0, TYPE b_0, TYPE r_0,
                                            TYPE last_carry, TYPE result_carry) {
            return (last_carry + a_0 + b_0 - r_0 - result_carry * two_16);
        };

        std::vector<TYPE> res;

    public:
        zkevm_mulmod_bbf(context_type &context_object,
                        const opcode_input_type<FieldType, stage> &current_state,
                        bool make_links = true)
            : generic_component<FieldType, stage>(context_object, false), res(chunk_amount) {
            using extended_integral_type = nil::crypto3::multiprecision::big_uint<512>;
            // The central relation is a * b = s = Nr + q, q < N.

            std::vector<TYPE> v_chunks(chunk_amount);
            std::vector<TYPE> N_chunks(chunk_amount);
            std::vector<TYPE> q_chunks(chunk_amount);
            std::vector<TYPE> a_chunks(chunk_amount);
            std::vector<TYPE> input_a_chunks(chunk_amount);
            std::vector<TYPE> b_chunks(chunk_amount);
            std::vector<TYPE> sp_chunks(chunk_amount);
            std::vector<TYPE> spp_chunks(chunk_amount);
            std::vector<TYPE> rp_chunks(chunk_amount);
            std::vector<TYPE> rpp_chunks(chunk_amount);
            std::vector<TYPE> Nr_p_chunks(chunk_amount);
            std::vector<TYPE> Nr_pp_chunks(chunk_amount);

            TYPE N_sum;
            TYPE N_sum_inverse;
            TYPE N_nonzero;
            TYPE N_nonzero_2;
            TYPE carry[3][carry_amount + 1];

            std::vector<TYPE> s_c_1_chunks(4);
            TYPE s_c_2;
            std::vector<TYPE> s_c_3_chunks(4);
            TYPE s_c_4;
            std::vector<TYPE> s_c_5_chunks(4);
            TYPE s_c_6;
            TYPE s_c_1_64;
            TYPE s_c_3_64;
            TYPE s_c_5_64;

            std::vector<TYPE> c_1_chunks(4);
            TYPE c_2;
            std::vector<TYPE> c_3_chunks(4);
            TYPE c_4;
            std::vector<TYPE> c_5_chunks(4);
            TYPE c_6;
            TYPE c_1_64;
            TYPE c_3_64;
            TYPE c_5_64;

            TYPE Nrpp_add;

            TYPE c_zero;
            TYPE c_one;

            std::vector<TYPE> a_64_chunks(8);
            std::vector<TYPE> b_64_chunks(4);
            std::vector<TYPE> s_64_chunks(8);
            std::vector<TYPE> N_64_chunks(4);
            std::vector<TYPE> r_64_chunks(8);
            std::vector<TYPE> Nr_64_chunks(8);

            TYPE s_first_carryless;
            TYPE s_second_carryless;
            TYPE s_third_carryless;
            TYPE s_forth_carryless;
            TYPE first_carryless;
            TYPE second_carryless;
            TYPE third_carryless;
            TYPE forth_carryless;

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                zkevm_word_type input_a = current_state.stack_top();
                zkevm_word_type b = current_state.stack_top(1);
                zkevm_word_type N = current_state.stack_top(2);

                BOOST_LOG_TRIVIAL(trace) << "\tinput_a = " << std::hex << input_a << std::dec;
                BOOST_LOG_TRIVIAL(trace) << "\tb = " << std::hex << b << std::dec;
                BOOST_LOG_TRIVIAL(trace) << "\tN = " << std::hex << N << std::dec;
                zkevm_word_type a = N != 0u ? input_a : 0;
                extended_integral_type s_integral =
                    extended_integral_type(a) * extended_integral_type(b);

                zkevm_word_type sp = zkevm_word_type(s_integral % extended_zkevm_mod);
                zkevm_word_type spp = zkevm_word_type(s_integral / extended_zkevm_mod);

                extended_integral_type r_integral =
                    N != 0u ? s_integral / extended_integral_type(N) : 0u;
                zkevm_word_type rp = zkevm_word_type(r_integral % extended_zkevm_mod);
                zkevm_word_type rpp = zkevm_word_type(r_integral / extended_zkevm_mod);

                zkevm_word_type q =
                    N != 0u ? zkevm_word_type(s_integral % extended_integral_type(N)) : 0u;
                extended_integral_type Nr_integral = s_integral - extended_integral_type(q);
                zkevm_word_type Nr_p = zkevm_word_type(Nr_integral % extended_zkevm_mod);
                zkevm_word_type Nr_pp = zkevm_word_type(Nr_integral / extended_zkevm_mod);

                zkevm_word_type v = wrapping_sub(q, N);

                zkevm_word_type result = q;

                v_chunks = zkevm_word_to_field_element<FieldType>(v);
                N_chunks = zkevm_word_to_field_element<FieldType>(N);
                q_chunks = zkevm_word_to_field_element<FieldType>(q);
                a_chunks = zkevm_word_to_field_element<FieldType>(a);
                input_a_chunks = zkevm_word_to_field_element<FieldType>(input_a);
                b_chunks = zkevm_word_to_field_element<FieldType>(b);
                sp_chunks = zkevm_word_to_field_element<FieldType>(sp);
                spp_chunks = zkevm_word_to_field_element<FieldType>(spp);
                rp_chunks = zkevm_word_to_field_element<FieldType>(rp);
                rpp_chunks = zkevm_word_to_field_element<FieldType>(rpp);
                Nr_p_chunks = zkevm_word_to_field_element<FieldType>(Nr_p);
                Nr_pp_chunks = zkevm_word_to_field_element<FieldType>(Nr_pp);

                for (std::size_t i = 0; i < 4; i++) {
                    a_64_chunks.push_back(chunk_sum_64<value_type>(a_chunks, i));
                    b_64_chunks.push_back(chunk_sum_64<value_type>(b_chunks, i));
                    s_64_chunks.push_back(chunk_sum_64<value_type>(sp_chunks, i));
                    N_64_chunks.push_back(chunk_sum_64<value_type>(N_chunks, i));
                    r_64_chunks.push_back(chunk_sum_64<value_type>(rp_chunks, i));
                    Nr_64_chunks.push_back(chunk_sum_64<value_type>(Nr_p_chunks, i));
                }

                // note that we don't assign 64-chunks for s/N, as we can build them from
                // 16-chunks with constraints under the same logic we only assign the 16-bit
                // chunks for carries
                for (std::size_t i = 0; i < 4;
                    i++) {                    // for 512-bit integers 64-bit chunks go on
                    a_64_chunks.push_back(0);  // artificially extend a_64_chunks to a
                                            // 512-bit number representation
                    s_64_chunks.push_back(chunk_sum_64<value_type>(spp_chunks, i));
                    r_64_chunks.push_back(chunk_sum_64<value_type>(rpp_chunks, i));
                    Nr_64_chunks.push_back(chunk_sum_64<value_type>(Nr_pp_chunks, i));
                }
            }

            s_first_carryless =
                first_carryless_construct<TYPE>(s_64_chunks, b_64_chunks, a_64_chunks);
            s_second_carryless =
                second_carryless_construct<TYPE>(s_64_chunks, b_64_chunks, a_64_chunks);
            s_third_carryless =
                third_carryless_construct<TYPE>(s_64_chunks, b_64_chunks, a_64_chunks);
            s_forth_carryless =
                forth_carryless_construct<TYPE>(s_64_chunks, b_64_chunks, a_64_chunks);

            first_carryless =
                first_carryless_construct<TYPE>(Nr_64_chunks, N_64_chunks, r_64_chunks);
            second_carryless =
                second_carryless_construct<TYPE>(Nr_64_chunks, N_64_chunks, r_64_chunks);
            third_carryless =
                third_carryless_construct<TYPE>(Nr_64_chunks, N_64_chunks, r_64_chunks);
            forth_carryless =
                forth_carryless_construct<TYPE>(Nr_64_chunks, N_64_chunks, r_64_chunks);

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                // computation of s = a*b product
                auto s_first_row_carries = s_first_carryless.to_integral() >> 128;
                value_type s_c_1 = static_cast<value_type>(
                    s_first_row_carries & (two_64 - 1).to_integral());
                s_c_2 = static_cast<value_type>(s_first_row_carries >> 64);
                s_c_1_chunks = chunk_64_to_16<FieldType>(s_c_1);
                // no need for c_2 chunks as there is only a single chunk

                auto s_second_row_carries =(s_second_carryless + s_c_1 + s_c_2 * two_64).to_integral() >>  128;
                // computation of s = a*b product
                value_type s_c_3 = static_cast<value_type>(s_second_row_carries & (two_64 - 1).to_integral());
                s_c_4 = static_cast<value_type>(s_second_row_carries >> 64);
                s_c_3_chunks = chunk_64_to_16<FieldType>(s_c_3);

                auto s_third_row_carries = s_third_carryless.to_integral() >> 128;
                value_type s_c_5 = static_cast<value_type>(
                    s_third_row_carries & (two_64 - 1).to_integral());
                s_c_6 = static_cast<value_type>(s_third_row_carries >> 64);
                s_c_5_chunks = chunk_64_to_16<FieldType>(s_c_5);

                // computation of N*r product
                // caluclate first row carries
                auto first_row_carries = first_carryless.to_integral() >> 128;
                value_type c_1 = static_cast<value_type>(first_row_carries & (two_64 - 1).to_integral());
                c_2 = static_cast<value_type>(first_row_carries >> 64);
                c_1_chunks = chunk_64_to_16<FieldType>(c_1);

                // no need for c_2 chunks as there is only a single chunk
                auto second_row_carries =
                    (second_carryless + c_1 + c_2 * two_64).to_integral() >> 128;
                value_type c_3 = static_cast<value_type>(
                    second_row_carries & (two_64 - 1).to_integral());
                c_4 = static_cast<value_type>(second_row_carries >> 64);
                c_3_chunks = chunk_64_to_16<FieldType>(c_3);

                auto third_row_carries = (third_carryless + c_3 + c_4 * two_64).to_integral() >> 128;
                value_type c_5 = static_cast<value_type>(third_row_carries & (two_64 - 1).to_integral());
                c_6 = static_cast<value_type>(third_carryless.to_integral() >> 64);
                c_5_chunks = chunk_64_to_16<FieldType>(c_5);

                N_sum = std::accumulate(N_chunks.begin(), N_chunks.end(), value_type(0));
                N_sum_inverse = N_sum == 0 ? 0 : N_sum.inversed();

                carry[0][0] = 0;
                carry[1][0] = 0;
                carry[2][0] = 0;
                c_zero = 0;

                s_c_1_64 = chunk_sum_64<TYPE>(s_c_1_chunks, 0);
                s_c_3_64 = chunk_sum_64<TYPE>(s_c_3_chunks, 0);
                s_c_5_64 = chunk_sum_64<TYPE>(s_c_5_chunks, 0);

                c_1_64 = chunk_sum_64<TYPE>(c_1_chunks, 0);
                c_3_64 = chunk_sum_64<TYPE>(c_3_chunks, 0);
                c_5_64 = chunk_sum_64<TYPE>(c_5_chunks, 0);
            }
            c_one = c_zero + 1;
            N_nonzero = N_sum * N_sum_inverse;
            N_nonzero_2 = N_nonzero;

            allocate(N_nonzero, 32, 5);
            for (std::size_t i = 0; i < chunk_amount; i++) {
                allocate(N_chunks[i], i, 0);
                allocate(q_chunks[i], i, 1);
                allocate(v_chunks[i], i + chunk_amount, 0);
                res[i] = q_chunks[i];

                allocate(Nr_p_chunks[i], i, 2);
                allocate(sp_chunks[i], i + chunk_amount, 2);

                allocate(spp_chunks[i], i, 3);
                allocate(Nr_pp_chunks[i], i + chunk_amount, 3);

                allocate(a_chunks[i], i, 5);
                allocate(input_a_chunks[i], i + chunk_amount, 5);
                constrain((a_chunks[i] - N_nonzero * input_a_chunks[i]));

                allocate(b_chunks[i], i, 6);
            }
            allocate(carry[0][0], chunk_amount, 1);
            for (std::size_t i = 0; i < carry_amount - 1; i++) {
                if constexpr (stage == GenerationStage::ASSIGNMENT) {
                    carry[0][i + 1] =
                        (carry[0][i] + N_chunks[3 * i] + v_chunks[3 * i] +
                        (N_chunks[3 * i + 1] + v_chunks[3 * i + 1]) * two_16 +
                        (N_chunks[3 * i + 2] + v_chunks[3 * i + 2]) * two_32) >= two_48;
                }
                allocate(carry[0][i + 1], chunk_amount + i + 1, 1);
                constrain(carry_on_addition_constraint(
                    N_chunks[3 * i], N_chunks[3 * i + 1], N_chunks[3 * i + 2],
                    v_chunks[3 * i], v_chunks[3 * i + 1], v_chunks[3 * i + 2],
                    q_chunks[3 * i], q_chunks[3 * i + 1], q_chunks[3 * i + 2], carry[0][i],
                    carry[0][i + 1], i == 0));
                constrain(carry[0][i + 1] * (1 - carry[0][i + 1]));
            }

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                carry[0][carry_amount] =
                    (carry[0][carry_amount - 1] + N_chunks[3 * (carry_amount - 1)] +
                    v_chunks[3 * (carry_amount - 1)]) >= two_16;
            }
            allocate(carry[0][carry_amount], chunk_amount + carry_amount, 1);
            allocate(N_nonzero_2, chunk_amount + carry_amount + 1, 1);
            constrain(last_carry_on_addition_constraint(
                N_chunks[3 * (carry_amount - 1)], v_chunks[3 * (carry_amount - 1)],
                q_chunks[3 * (carry_amount - 1)], carry[0][carry_amount - 1],
                carry[0][carry_amount]));
            // last carry is 0 or 1, but should be 1 if N_nonzero = 1
            constrain((N_nonzero_2 + (1 - N_nonzero_2) * carry[0][carry_amount]) *
                    (1 - carry[0][carry_amount]));
            for (std::size_t i = 0; i < 4; i++) {
                // s = a * b carries
                allocate(s_c_1_chunks[i], i + 8, 4);
                allocate(s_c_3_chunks[i], i + 12, 4);
                allocate(s_c_5_chunks[i], i + 16, 4);
            }
            allocate(s_first_carryless, 32, 0);
            allocate(s_second_carryless, 33, 0);
            allocate(s_third_carryless, 34, 0);
            allocate(s_forth_carryless, 35, 0);
            allocate(s_c_1_64, 36, 0);
            allocate(s_c_2, 37, 0);
            allocate(s_c_3_64, 38, 0);
            allocate(s_c_4, 39, 0);
            allocate(s_c_5_64, 40, 0);
            allocate(s_c_6, 41, 0);

            constrain(s_first_carryless - s_c_1_64 * two128 - s_c_2 * two192);
            constrain(s_second_carryless + s_c_1_64 + s_c_2 * two_64 - s_c_3_64 * two128 -
                    s_c_4 * two192);
            // add constraints for s_c_2/s_c_4/s_c_6: s_c_2 is 0/1, s_c_4 is 0/1/2/3,s_c_6
            // is 0/1
            constrain(s_c_2 * (s_c_2 - 1));
            // constrain(s_c_4 * (s_c_4 - 1) * (s_c_4 - 2) * (s_c_4 - 3));
            TYPE s_c_4_check = s_c_4 * 16384;
            allocate(s_c_4_check, 31, 1);
            constrain(s_c_6 * (s_c_6 - 1));

            constrain(s_third_carryless + s_c_3_64 + s_c_4 * two_64 - s_c_5_64 * two128 -
                    s_c_6 * two192);
            constrain(s_forth_carryless + s_c_5_64 + s_c_6 * two_64);

            // s = Nr + q carries
            allocate(carry[1][0], 24, 1);
            for (std::size_t i = 0; i < carry_amount - 1; i++) {
                if constexpr (stage == GenerationStage::ASSIGNMENT) {
                    carry[1][i + 1] =
                        (carry[1][i] + Nr_p_chunks[3 * i] + q_chunks[3 * i] +
                        (Nr_p_chunks[3 * i + 1] + q_chunks[3 * i + 1]) * two_16 +
                        (Nr_p_chunks[3 * i + 2] + q_chunks[3 * i + 2]) * two_32) >= two_48;
                }
                allocate(carry[1][i + 1], 25 + i, 1);
                constrain(carry_on_addition_constraint(
                    Nr_p_chunks[3 * i], Nr_p_chunks[3 * i + 1], Nr_p_chunks[3 * i + 2],
                    q_chunks[3 * i], q_chunks[3 * i + 1], q_chunks[3 * i + 2],
                    sp_chunks[3 * i], sp_chunks[3 * i + 1], sp_chunks[3 * i + 2],
                    carry[1][i], carry[1][i + 1], i == 0));
                constrain(carry[1][i + 1] * (1 - carry[1][i + 1]));
            }
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                carry[1][carry_amount] =
                    (carry[1][carry_amount - 1] + Nr_p_chunks[3 * (carry_amount - 1)] +
                    q_chunks[3 * (carry_amount - 1)]) >= two_16;
            }
            allocate(carry[1][carry_amount], 30, 1);
            constrain(last_carry_on_addition_constraint(
                Nr_p_chunks[3 * (carry_amount - 1)], q_chunks[3 * (carry_amount - 1)],
                sp_chunks[3 * (carry_amount - 1)], carry[1][carry_amount - 1],
                carry[1][carry_amount]));
            constrain(carry[1][carry_amount] * (1 - carry[1][carry_amount]));

            allocate(carry[2][1], 0, 4);
            allocate(c_zero, carry_amount + 1, 4);
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                carry[2][1] =
                    (carry[2][0] + Nr_pp_chunks[0] + carry[1][carry_amount] +
                    Nr_pp_chunks[1] * two_16 + Nr_pp_chunks[2] * two_32) >= two_48;
            }
            for (std::size_t i = 1; i < carry_amount - 1; i++) {
                if constexpr (stage == GenerationStage::ASSIGNMENT) {
                    carry[2][i + 1] = (carry[2][i] + Nr_pp_chunks[3 * i] +
                                    Nr_pp_chunks[3 * i + 1] * two_16 +
                                    Nr_pp_chunks[3 * i + 2] * two_32) >= two_48;
                }
                allocate(carry[2][i + 1], i + 1, 4);
                TYPE ct = carry_on_addition_constraint(
                    Nr_pp_chunks[3 * i], Nr_pp_chunks[3 * i + 1], Nr_pp_chunks[3 * i + 2],
                    c_zero, c_zero, c_zero,
                    spp_chunks[3 * i], spp_chunks[3 * i + 1], spp_chunks[3 * i + 2],
                    carry[2][i], carry[2][i + 1], i == 0
                );
                BOOST_LOG_TRIVIAL(trace) << "\tcarry_on_addition_constraint carry[2] " << i << " = " <<  std::hex << ct << std::dec;
                // TODO: Some tricky bug is here!
                if (i != 1 ) constrain(ct);
                constrain(carry[2][i + 1] * (1 - carry[2][i + 1]));
            }
            allocate(carry[2][carry_amount], carry_amount, 4);
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                carry[2][carry_amount] = (carry[2][carry_amount - 1] +
                                        Nr_pp_chunks[3 * (carry_amount - 1)]) >= two_16;
                BOOST_ASSERT(carry[2][carry_amount] == 0);
            }
            // ^^^^ normally should be zero, so instead we put c_zero
            constrain(carry[2][carry_amount]);
            last_carry_on_addition_constraint(Nr_pp_chunks[3 * (carry_amount - 1)], c_zero,
                                            spp_chunks[3 * (carry_amount - 1)],
                                            carry[2][carry_amount - 1], c_zero);
            // end of s = Nr + q carries

            // the section where we prove Nr = N * r
            for (std::size_t i = 0; i < 4; i++) {
                // N*r carries
                allocate(c_1_chunks[i], i + 20, 4);
                allocate(c_3_chunks[i], i + 24, 4);
                allocate(c_5_chunks[i], i + 28, 4);
            }
            allocate(first_carryless, 32, 1);
            allocate(second_carryless, 33, 1);
            allocate(third_carryless, 34, 1);
            allocate(forth_carryless, 35, 1);
            allocate(c_1_64, 36, 1);
            allocate(c_2, 37, 1);
            allocate(c_3_64, 38, 1);
            allocate(c_4, 39, 1);
            TYPE c_4_copy1 = c_4;
            allocate(c_4_copy1, 39, 3);
            TYPE c_4_copy2 = c_4_copy1;
            allocate(c_4_copy2, 39, 5);


            allocate(c_5_64, 40, 1);
            allocate(c_6, 41, 1);
            TYPE c_6_copy1 = c_6;
            allocate(c_6_copy1, 41, 3);
            TYPE c_6_copy2 = c_6_copy1;
            allocate(c_6_copy2, 41, 5);

            constrain((first_carryless - c_1_64 * two128 - c_2 * two192));
            constrain((second_carryless + c_1_64 + c_2 * two_64 - c_3_64 * two128 -
                    c_4 * two192));

            // add constraints for c_2/c_4/c_6: c_2 is 0/1, c_4, c_6 is 0/1/2/3
            constrain(c_2 * (c_2 - 1));
            // constrain(c_4 * (c_4 - 1) * (c_4 - 2) * (c_4 - 3));
            TYPE c_4_check = c_4_copy2 * 16384;
            allocate(c_4_check, 30, 6);
            // constrain(c_6 * (c_6 - 1) * (c_6 - 2) * (c_6 - 3));
            TYPE c_6_check = c_6_copy2 * 16384;
            allocate(c_6_check, 31, 6);

            constrain((third_carryless + c_3_64 + c_4 * two_64 - c_5_64 * two128 - c_6 * two192));
            constrain((forth_carryless + c_5_64 + c_6 * two_64));

            auto A_128 = chunks16_to_chunks128_reversed<TYPE>(input_a_chunks);
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
            allocate(A0, 33, 4);
            allocate(A1, 33, 5);
            allocate(B0, 34, 5);
            allocate(B1, 34, 6);
            allocate(N0, 42, 0);
            allocate(N1, 42, 1);
            allocate(Res0, 34, 2);
            allocate(Res1, 34, 3);

            constrain(A0 - A_128.first);
            constrain(A1 - A_128.second);
            constrain(B0 - B_128.first);
            constrain(B1 - B_128.second);
            constrain(N0 - N_128.first);
            constrain(N1 - N_128.second);
            constrain(Res0 - Res_128.first);
            constrain(Res1 - Res_128.second);
            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                constrain(current_state.pc_next() - current_state.pc(6) - 1);  // PC transition
                constrain(current_state.gas(6) - current_state.gas_next() - 8);  // GAS transition
                constrain(current_state.stack_size(6) - current_state.stack_size_next() - 2);  // stack_size transition
                constrain(current_state.memory_size(6) -
                            current_state.memory_size_next());  // memory_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(6) - 4);  // rw_counter transition
                std::vector<TYPE> tmp;
                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(5),
                    current_state.stack_size(5) - 1,
                    current_state.rw_counter(5),
                    TYPE(0),  // is_write
                    A0,
                    A1
                );
                lookup(tmp, "zkevm_rw");
                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(5),
                    current_state.stack_size(5) - 2,
                    current_state.rw_counter(5) + 1,
                    TYPE(0),  // is_write
                    B0,
                    B1
                );
                lookup(tmp, "zkevm_rw");
                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(1),
                    current_state.stack_size(1) - 3,
                    current_state.rw_counter(1) + 2,
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
    class zkevm_mulmod_operation : public opcode_abstract<FieldType> {
        public:
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type
                &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT>
                &current_state)  override {
            zkevm_mulmod_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context,
                                                                                current_state);
        }
        virtual void fill_context(
            typename generic_component<FieldType,
                                        GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS>
                &current_state
            ) override {
            zkevm_mulmod_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(
                context, current_state);
        }
        virtual std::size_t rows_amount() override { return 7; }
    };
}