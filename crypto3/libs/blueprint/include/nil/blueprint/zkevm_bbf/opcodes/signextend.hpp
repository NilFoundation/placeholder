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
            class zkevm_signextend_bbf : public generic_component<FieldType, stage> {
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

                std::vector<TYPE> res;

              public:
                zkevm_signextend_bbf(context_type &context_object,
                                     const opcode_input_type<FieldType, stage> &current_state)
                    : generic_component<FieldType, stage>(context_object, false),
                      res(chunk_amount) {
                    std::vector<TYPE> b_chunks(chunk_amount);
                    std::vector<TYPE> x_chunks(chunk_amount);
                    std::vector<TYPE> r_chunks(chunk_amount);
                    std::vector<TYPE> indic(chunk_amount);
                    std::vector<TYPE> cur(chunk_amount);

                    TYPE b_sum;
                    TYPE x_sum;
                    TYPE b_sum_inverse;
                    TYPE b0p;
                    TYPE parity;
                    TYPE n;
                    TYPE xn;
                    TYPE xp;
                    TYPE xpp;
                    TYPE sb;
                    TYPE sgn;
                    TYPE saux;

                    TYPE range_check_n;
                    TYPE range_check_xp;
                    TYPE range_check_xpp;
                    TYPE range_check_saux;

                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        zkevm_word_type b = current_state.stack_top();
                        zkevm_word_type x = current_state.stack_top(1);

                        int len = (b < 32) ? int(b) + 1 : 32;
                        zkevm_word_type sign = (x << (8 * (32 - len))) >> 255;
                        zkevm_word_type result =
                            wrapping_add(
                                wrapping_mul(
                                    (wrapping_sub(zkevm_word_type(1) << 8 * (32 - len), 1) << 8 * len),
                                    sign
                                ),
                                ((x << (8 * (32 - len))) >> (8 * (32 - len)))
                            );

                        unsigned int b0 = static_cast<unsigned int>(b % 65536);
                        unsigned int b0p_ui = (b > 65535) ? 32 : b0;
                        b0p = b0p_ui;
                        unsigned int parity_ui = b0p_ui%2;
                        parity = parity_ui;
                        unsigned int n_ui = (b0p_ui-parity_ui)/2;
                        n = n_ui;
                        unsigned int xn_ui = static_cast<unsigned int>(
                            (x << (16 * (n_ui > 15 ? 16 : 15 - n_ui))) >> (16 * 15));
                        xn = xn_ui;
                        unsigned int xpp_ui = xn_ui % 256;
                        xpp = xpp_ui;
                        xp = (xn - xpp) / 256;
                        sb = (parity == 0) ? xpp : xp;
                        sgn = (sb > 128);
                        saux = sb + 128 - sgn * 256;

                        b_chunks = zkevm_word_to_field_element<FieldType>(b);
                        x_chunks = zkevm_word_to_field_element<FieldType>(x);
                        r_chunks = zkevm_word_to_field_element<FieldType>(result);
                        for (std::size_t i = 0; i < chunk_amount; i++) {
                            cur[i] = i;
                            indic[i] = (cur[i] == n) ? 0 : (cur[i]-n).inversed();
                        }

                        b_sum = 0;
                        for (std::size_t i = 1; i < chunk_amount; i++) {
                            b_sum += b_chunks[i];
                        }
                        b_sum_inverse = b_sum.is_zero() ? 0 : b_sum.inversed();

                        x_sum = 0;
                        for (std::size_t i = 0; i < chunk_amount; i++) {
                            x_sum += x_chunks[i] * (1 - (i - n) * indic[i]);
                        }
                        range_check_n = 2 * n;
                        range_check_xp = xp * 256;
                        range_check_xpp = xpp * 256;
                        range_check_saux = saux * 256;
                    }

                    allocate(n, 23, 1);
                    for (std::size_t i = 0; i < chunk_amount; i++) {
                        allocate(b_chunks[i], i, 0);
                        allocate(x_chunks[i], i + chunk_amount, 0);
                        allocate(r_chunks[i], i, 1);
                        allocate(indic[i], i + 2 * chunk_amount, 0);
                        res[i] = r_chunks[i];
                        constrain((i - n) * (1 - (i - n) * indic[i]));
                    }

                    allocate(b_sum, 32, 1);
                    allocate(b_sum_inverse, 33, 1);
                    allocate(x_sum, 34, 1);
                    allocate(b0p, 35, 1);
                    allocate(parity, 36, 1);
                    allocate(xn, 37, 1);
                    allocate(xp, 20, 1);
                    allocate(xpp, 21, 1);
                    allocate(sb, 38, 1);
                    allocate(sgn, 39, 1);
                    allocate(saux, 22, 1);

                    constrain(b_sum * (1 - b_sum_inverse * b_sum));
                    constrain((b0p - b_chunks[0] * (1 - b_sum * b_sum_inverse) -
                               32 * b_sum * b_sum_inverse));
                    constrain(parity * (1 - parity));
                    constrain(b0p - parity - 2 * n);
                    // n < 32768 range check
                    allocate(range_check_n);
                    // xp, xpp,saux < 256
                    allocate(range_check_xp);
                    allocate(range_check_xpp);
                    allocate(range_check_saux);

                    constrain(xn - x_sum);
                    constrain(xn - xp * 256 - xpp);

                    constrain(sb - (1 - parity) * xpp - parity * xp);
                    constrain(sgn * (1 - sgn));
                    constrain(sb + 128 - saux - 256 * sgn);

                    auto B_128 = chunks16_to_chunks128_reversed<TYPE>(b_chunks);
                    auto X_128 = chunks16_to_chunks128_reversed<TYPE>(x_chunks);
                    auto Res_128 = chunks16_to_chunks128_reversed<TYPE>(res);

                    TYPE B0, B1, X0, X1, Res0, Res1;
                    B0 = B_128.first;
                    B1 = B_128.second;
                    X0 = X_128.first;
                    X1 = X_128.second;
                    Res0 = Res_128.first;
                    Res1 = Res_128.second;
                    allocate(B0, 42, 1);
                    allocate(B1, 43, 1);
                    allocate(X0, 44, 1);
                    allocate(X1, 45, 1);
                    allocate(Res0, 46, 1);
                    allocate(Res1, 47, 1);

                    if constexpr (stage == GenerationStage::CONSTRAINTS) {

                        constrain(current_state.pc_next() - current_state.pc(1) -
                                  1);  // PC transition
                        constrain(current_state.gas(1) - current_state.gas_next() -
                                  5);  // GAS transition
                        constrain(current_state.stack_size(1) - current_state.stack_size_next() -
                                  1);  // stack_size transition
                        constrain(current_state.memory_size(1) -
                                  current_state.memory_size_next());  // memory_size transition
                        constrain(current_state.rw_counter_next() - current_state.rw_counter(1) -
                                  3);  // rw_counter transition
                        std::vector<TYPE> tmp;
                        tmp = rw_table<FieldType, stage>::stack_lookup(
                            current_state.call_id(1),
                            current_state.stack_size(1) - 1,
                            current_state.rw_counter(1),
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
                            X0,
                            X1
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
                }
            };

            template<typename FieldType>
            class zkevm_signextend_operation : public opcode_abstract<FieldType> {
              public:
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type
                        &context,
                    const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT>
                        &current_state)  override {
                    zkevm_signextend_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(
                        context, current_state);
                }
                virtual void fill_context(
                    typename generic_component<FieldType,
                                               GenerationStage::CONSTRAINTS>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS>
                        &current_state)  override {
                    zkevm_signextend_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(
                        context, current_state);
                }
                virtual std::size_t rows_amount() override { return 2; }
            };
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil
