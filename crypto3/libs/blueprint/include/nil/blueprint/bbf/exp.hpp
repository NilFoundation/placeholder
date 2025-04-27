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
// @file Declaration of interfaces for PLONK BBF exp component class
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_PLONK_BBF_EXP_COMPONENT_HPP
#define CRYPTO3_BLUEPRINT_PLONK_BBF_EXP_COMPONENT_HPP

#include <functional>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/bbf/exp_table.hpp>
#include <nil/blueprint/zkevm/zkevm_word.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {

            template<typename FieldType, GenerationStage stage>
            class exp_circuit : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;

              public:
                using typename generic_component<FieldType, stage>::TYPE;
                using word_type = zkevm_word_type;

                std::size_t max_rows;
                std::size_t max_exponentiations;


                constexpr static std::size_t num_chunks = 2;
                constexpr static const typename FieldType::value_type one    = 1;
                constexpr static const typename FieldType::value_type two_16 = 65536;
                constexpr static const typename FieldType::value_type two_32 = 4294967296;
                constexpr static const typename FieldType::value_type two_48 = 281474976710656;
                constexpr static const typename FieldType::value_type two_64 = 0x10000000000000000_big_uint254;
                constexpr static const typename FieldType::value_type two_80 = 0x100000000000000000000_big_uint254;
                constexpr static const typename FieldType::value_type two_96 = 0x1000000000000000000000000_big_uint254;
                constexpr static const typename FieldType::value_type two112 = 0x10000000000000000000000000000_big_uint254;
                constexpr static const typename FieldType::value_type two128 = 0x100000000000000000000000000000000_big_uint254;
                constexpr static const typename FieldType::value_type two192 = 0x1000000000000000000000000000000000000000000000000_big_uint254;

                template<typename T, typename V = T>
                T chunk_sum_64(const std::vector<V> &chunks, const unsigned char chunk_idx) const {
                    BOOST_ASSERT(chunk_idx < 4);
                    return chunks[4 * chunk_idx] + chunks[4 * chunk_idx + 1] * two_16 +
                           chunks[4 * chunk_idx + 2] * two_32 + chunks[4 * chunk_idx + 3] * two_48;
                }

                template<typename T, typename V = T>
                T chunk_sum_128(const std::vector<V> &chunks, const unsigned char chunk_idx) const {
                    BOOST_ASSERT(chunk_idx < 2);
                    return chunks[8 * chunk_idx] + chunks[8 * chunk_idx + 1] * two_16 +
                           chunks[8 * chunk_idx + 2] * two_32 + chunks[8 * chunk_idx + 3] * two_48 +
                           chunks[8 * chunk_idx + 4] * two_64 + chunks[8 * chunk_idx + 5] * two_80 +
                           chunks[8 * chunk_idx + 6] * two_96 + chunks[8 * chunk_idx + 7] * two112;
                }

                template<typename T>
                T first_carryless_consrtruct(const std::vector<T> &a_64_chunks,
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

              public:

                exp_circuit(context_type &context_object,
                            const exp_table_input_type &input,
                            std::size_t max_rows_amount, std::size_t max_exponentiations_,
                            bool make_links = true) :
                    max_rows(max_rows_amount),
                    max_exponentiations(max_exponentiations_),
                    generic_component<FieldType, stage>(context_object)
                    {

                        std::size_t num_proving_blocks = (max_rows) / 3;
                        std::vector<std::array<TYPE, num_chunks>> base = std::vector<std::array<TYPE, num_chunks>>(max_rows);
                        std::vector<std::array<TYPE, num_chunks>> exponent = std::vector<std::array<TYPE, num_chunks>>(max_rows);
                        std::vector<std::array<TYPE, num_chunks>> exponentiation = std::vector<std::array<TYPE, num_chunks>>(max_rows);

                        std::vector<std::vector<TYPE>> a_chunks = std::vector<std::vector<TYPE>>(num_proving_blocks, std::vector<TYPE>(16));
                        std::vector<std::vector<TYPE>> b_chunks = std::vector<std::vector<TYPE>>(num_proving_blocks, std::vector<TYPE>(16));
                        std::vector<std::vector<TYPE>> r_chunks = std::vector<std::vector<TYPE>>(num_proving_blocks, std::vector<TYPE>(16));

                        std::vector<std::vector<TYPE>> c_1_chunks = std::vector<std::vector<TYPE>>(num_proving_blocks, std::vector<TYPE>(4));
                        std::vector<std::vector<TYPE>> c_3_chunks = std::vector<std::vector<TYPE>>(num_proving_blocks, std::vector<TYPE>(4));

                        std::vector<TYPE> c_2 = std::vector<TYPE>(num_proving_blocks);
                        std::vector<TYPE> c_4 = std::vector<TYPE>(num_proving_blocks);
                        std::vector<std::array<TYPE, num_chunks>> itermediate_exponents = std::vector<std::array<TYPE, 2>>(max_rows);
                        std::vector<TYPE> hi_last = std::vector<TYPE>(num_proving_blocks);
                        std::vector<TYPE> exp_is_even = std::vector<TYPE>(num_proving_blocks);
                        std::vector<TYPE> is_last = std::vector<TYPE>(max_rows);
                        std::vector<TYPE> header_selector = std::vector<TYPE>(max_rows);



                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            auto triplets = input.get_triplets(); // TODO: work with exp_table interface directly
                            std::size_t cur = 0;
                            BOOST_ASSERT(triplets.size() <= max_exponentiations);
                            for(std::size_t i = 0; i < triplets.size(); i++){

                                word_type exp_a = triplets[i][0];
                                word_type exp_d = triplets[i][1];
                                word_type exp_A = triplets[i][2];

                                word_type e = exp_d;
                                std::vector<bool> bitmap;
                                std::vector<word_type> tmp_exp;
                                while( e >= 2){
                                    tmp_exp.push_back(e);
                                    if(e & 1){
                                        bitmap.push_back(true);
                                        e = e - 1;
                                    }else{
                                        bitmap.push_back(false);
                                        e = e >> 1;
                                    }
                                }
                                std::reverse(bitmap.begin(), bitmap.end());
                                std::vector<std::array<word_type, 3>> intermediate_triplets;
                                word_type a, b;

                                e = exp_a;
                                for(const auto &bit : bitmap){
                                    a = e;
                                    if(!bit){
                                        b = a;
                                    }else{
                                        b = exp_a;
                                    }
                                    e = a * b;
                                    intermediate_triplets.push_back({a, b, e});
                                }
                                BOOST_ASSERT(intermediate_triplets.size() == bitmap.size());
                                BOOST_ASSERT(tmp_exp.size() == bitmap.size());

                                std::size_t its = intermediate_triplets.size();

                                for(std::size_t j = 0; j < its; j++){
                                    BOOST_ASSERT(cur < num_proving_blocks);

                                    header_selector[3*cur] = (j == 0) ? 1 : 0;
                                    header_selector[3*cur + 1] = 0;
                                    header_selector[3*cur + 2] = 0;

                                    base[3*cur][0] = w_hi<FieldType>(exp_a);
                                    base[3*cur][1] = w_lo<FieldType>(exp_a);

                                    base[3*cur + 1][0] = base[3*cur][0];
                                    base[3*cur + 1][1] = base[3*cur][1];

                                    base[3*cur + 2][0] = base[3*cur][0];
                                    base[3*cur + 2][1] = base[3*cur][1];


                                    exponent[3*cur][0] = w_hi<FieldType>(tmp_exp[j]);
                                    exponent[3*cur][1] = w_lo<FieldType>(tmp_exp[j]);

                                    exponent[3*cur + 1][0] = exponent[3*cur][0];
                                    exponent[3*cur + 1][1] = exponent[3*cur][1];

                                    exponent[3*cur + 2][0] = exponent[3*cur][0];
                                    exponent[3*cur + 2][1] = exponent[3*cur][1];

                                    exponentiation[3*cur][0] = w_hi<FieldType>(intermediate_triplets[its - j - 1][2]);
                                    exponentiation[3*cur][1] = w_lo<FieldType>(intermediate_triplets[its - j - 1][2]);

                                    exponentiation[3*cur + 1][0] = exponentiation[3*cur][0];
                                    exponentiation[3*cur + 1][1] = exponentiation[3*cur][1];

                                    exponentiation[3*cur + 2][0] = exponentiation[3*cur][0];
                                    exponentiation[3*cur + 2][1] = exponentiation[3*cur][1];

                                    exp_is_even[cur] = (bitmap[its - j - 1]) ? 0 : 1;
                                    hi_last[cur] = static_cast<TYPE>(
                                        exponent[3 * cur][0].to_integral() &
                                        one.to_integral());

                                    is_last[3*cur] = (j == its - 1) ? 1 : 0;
                                    is_last[3*cur + 1] = is_last[3*cur];
                                    is_last[3*cur + 2] = is_last[3*cur];


                                    a_chunks[cur] = zkevm_word_to_field_element<FieldType>(intermediate_triplets[its - j - 1][0]);
                                    b_chunks[cur] = zkevm_word_to_field_element<FieldType>(intermediate_triplets[its - j - 1][1]);
                                    r_chunks[cur] = zkevm_word_to_field_element<FieldType>(intermediate_triplets[its - j - 1][2]);

                                    std::vector<TYPE> a_64_chunks, b_64_chunks, r_64_chunks;
                                    for (std::size_t k = 0; k < 4; k++) {
                                        a_64_chunks.push_back(chunk_sum_64<TYPE>(a_chunks[cur], k));
                                        b_64_chunks.push_back(chunk_sum_64<TYPE>(b_chunks[cur], k));
                                        r_64_chunks.push_back(chunk_sum_64<TYPE>(r_chunks[cur], k));
                                    }

                                    auto first_row_carries =
                                        first_carryless_consrtruct<TYPE>(
                                            a_64_chunks, b_64_chunks, r_64_chunks)
                                            .to_integral() >>
                                        128;
                                    TYPE c_1 = static_cast<TYPE>(
                                        first_row_carries & (two_64 - 1).to_integral());
                                    c_2[cur] = static_cast<TYPE>(first_row_carries >> 64);
                                    c_1_chunks[cur] = chunk_64_to_16<FieldType>(c_1);
                                    // no need for c_2 chunks as there is only a single chunk
                                    auto second_row_carries =
                                        (second_carryless_construct<TYPE>(
                                             a_64_chunks, b_64_chunks, r_64_chunks) +
                                         c_1 + c_2[cur] * two_64)
                                            .to_integral() >>
                                        128;
                                    TYPE c_3 = static_cast<TYPE>(
                                        second_row_carries & (two_64 - 1).to_integral());
                                    c_4[cur] = static_cast<TYPE>(second_row_carries >> 64);
                                    c_3_chunks[cur] = chunk_64_to_16<FieldType>(c_3);

                                    cur++;
                                }

                            }
                            while(cur < num_proving_blocks){
                                // unused rows will be filled with zeros. To satisfy all constraints
                                // exp_is_even is set 1 (because 0 is even)
                                exp_is_even[cur++] = 1;
                            }
                        }

                        for(std::size_t i = 0; i < max_rows; i++){
                            allocate(header_selector[i], 0, i);

                            for(std::size_t j = 0; j < num_chunks; j++){
                                allocate(base[i][j], j + 1, i);
                                allocate(exponent[i][j], num_chunks + j + 1, i);
                                allocate(exponentiation[i][j], 2*num_chunks + j + 1,i);
                            }
                            allocate(is_last[i], 3*num_chunks + 1, i);
                        }

                        for(std::size_t i=0; i < num_proving_blocks; i++){
                            // TODO: 16-bit range check lookup
                            for(std::size_t j = 0; j < 16; j++){
                                allocate(r_chunks[i][j], 3*num_chunks + j + 2, 3*i);
                                allocate(b_chunks[i][j], 3*num_chunks + j + 2, 3*i + 1);
                                allocate(a_chunks[i][j], 3*num_chunks + j + 2, 3*i + 2);
                            }
                            for(std::size_t j = 0; j < 4; j++){
                                allocate(c_1_chunks[i][j], 3*num_chunks + j + 18, 3*i);
                                allocate(c_3_chunks[i][j], 3*num_chunks + j + 18, 3*i + 1);
                            }
                            allocate(c_2[i], 3*num_chunks + 18, 3*i + 2);
                            allocate(c_4[i], 3*num_chunks + 19, 3*i + 2);

                            allocate(exp_is_even[i], 3*num_chunks + 20, 3*i + 2);
                            allocate(hi_last[i], 3*num_chunks + 21, 3*i + 2);
                        }

                        if(make_links){

                        }

                        for(std::size_t i = 0; i < max_rows; i++){
                            lookup(std::vector<TYPE>({header_selector[i]*base[i][0], header_selector[i]*base[i][1],
                                    header_selector[i]*exponent[i][0], header_selector[i]*exponent[i][1] + (1 - header_selector[i]),
                                    header_selector[i]*exponentiation[i][0],header_selector[i]*exponentiation[i][1]}), "exp_table");

                            constrain(header_selector[i]*(1-header_selector[i]));
                            constrain(is_last[i]*(1-is_last[i]));
                        }

                        for(std::size_t i = 0; i < num_proving_blocks; i++){
                            copy_constrain(base[3*i][0], base[3*i+1][0]);
                            copy_constrain(base[3*i][0], base[3*i+2][0]);

                            copy_constrain(exponent[3*i][0], exponent[3*i+1][0]);
                            copy_constrain(exponent[3*i][0], exponent[3*i+2][0]);

                            copy_constrain(exponentiation[3*i][0], exponentiation[3*i+1][0]);
                            copy_constrain(exponentiation[3*i][0], exponentiation[3*i+2][0]);

                            copy_constrain(base[3*i][1], base[3*i+1][1]);
                            copy_constrain(base[3*i][1], base[3*i+2][1]);

                            copy_constrain(exponent[3*i][1], exponent[3*i+1][1]);
                            copy_constrain(exponent[3*i][1], exponent[3*i+2][1]);

                            copy_constrain(exponentiation[3*i][1], exponentiation[3*i+1][1]);
                            copy_constrain(exponentiation[3*i][1], exponentiation[3*i+2][1]);

                            copy_constrain(is_last[3*i], is_last[3*i+1]);
                            copy_constrain(is_last[3*i], is_last[3*i+2]);


                            constrain(exp_is_even[i]*(1-exp_is_even[i]));
                            constrain(hi_last[i]*(1-hi_last[i]));

                            constrain(chunk_sum_128<TYPE>(r_chunks[i], 0) - exponentiation[3*i][1]); // exponent_lo = r_chunk[0:7]
                            constrain(chunk_sum_128<TYPE>(r_chunks[i], 1) - exponentiation[3*i][0]); // exponent_hi = r_chunk[8:15]
                            for(std::size_t j = 0; j < 16; j++){
                                constrain(exp_is_even[i]*(a_chunks[i][j] - b_chunks[i][j]));  // if exp is even a = b
                            }
                            constrain((1-exp_is_even[i])*(chunk_sum_128<TYPE>(b_chunks[i], 0) - base[3*i][1])); // if exp is odd b[0:7] = base_lo
                            constrain((1-exp_is_even[i])*(chunk_sum_128<TYPE>(b_chunks[i], 1) - base[3*i][0])); // if exp is odd b[8:15] = base_hi

                            // if is_last ==> exp_is_even and exp_lo = 2, exp_lo = 0, and a = b = base
                            // One constraint is enough. The other can be decuded from exp_is_even => a=b constraint
                            constrain(is_last[3*i]*(exponent[3*i][1]- 2));
                            constrain(is_last[3*i]*(exponent[3*i][0]));
                            constrain(is_last[3*i]*(1 - exp_is_even[i]));
                            constrain(is_last[3*i]*(chunk_sum_128<TYPE>(b_chunks[i], 1) - base[3*i][0]));
                            constrain(is_last[3*i]*(chunk_sum_128<TYPE>(b_chunks[i], 0) - base[3*i][1]));

                            if( i > 1){
                            //     if prev_exp is odd prev_exp = curr_exp + 1
                               constrain((1 - exp_is_even[i-1])*(exponent[3*i - 1][0] - exponent[3*i][0]));   // that is prev_exp_hi = cur_exp_hi
                               constrain((1 - exp_is_even[i-1])*(exponent[3*i - 1][1] - exponent[3*i][1] - 1)); // prev_exp_lo = cur_exp_lo + 1
                            //     if prev_exp is even prev_exp = cur_exp * 2 except is_last = 1
                                constrain((1-is_last[3*i-1])*exp_is_even[i-1]*(exponent[3*i - 1][0] - 2 * exponent[3*i][0] - hi_last[i-1]));    //  that is prev_exp_hi = 2* cur_exp_hi + prev_exp_hi & 2
                                constrain((1-is_last[3*i-1])*exp_is_even[i-1]*(exponent[3*i - 1][1] - 2 * exponent[3*i][1] + two128*hi_last[i-1]));   //  prev_exp_lo = cur_exp_lo * 2 - (prev_exp_hi & 2) << 128
                            }


                            std::vector<TYPE> a_64_chunks = {
                                chunk_sum_64<TYPE>(a_chunks[i], 0),
                                chunk_sum_64<TYPE>(a_chunks[i], 1),
                                chunk_sum_64<TYPE>(a_chunks[i], 2),
                                chunk_sum_64<TYPE>(a_chunks[i], 3)
                            };
                            std::vector<TYPE> b_64_chunks = {
                                chunk_sum_64<TYPE>(b_chunks[i], 0),
                                chunk_sum_64<TYPE>(b_chunks[i], 1),
                                chunk_sum_64<TYPE>(b_chunks[i], 2),
                                chunk_sum_64<TYPE>(b_chunks[i], 3)
                            };
                            std::vector<TYPE> r_64_chunks = {
                                chunk_sum_64<TYPE>(r_chunks[i], 0),
                                chunk_sum_64<TYPE>(r_chunks[i], 1),
                                chunk_sum_64<TYPE>(r_chunks[i], 2),
                                chunk_sum_64<TYPE>(r_chunks[i], 3)
                            };

                            TYPE c_1_64 = chunk_sum_64<TYPE>(c_1_chunks[i], 0);
                            TYPE c_3_64 = chunk_sum_64<TYPE>(c_3_chunks[i], 0);
                            TYPE first_carryless = first_carryless_consrtruct<TYPE>(a_64_chunks, b_64_chunks, r_64_chunks);
                            constrain(first_carryless - c_1_64 * two128 - c_2[i] * two192);

                            TYPE second_carryless = second_carryless_construct<TYPE>(a_64_chunks, b_64_chunks, r_64_chunks);
                            constrain(second_carryless + c_1_64 + c_2[i] * two_64 - c_3_64 * two128 - c_4[i] * two192);
                            constrain(c_2[i] * (c_2[i] - 1));
                            constrain(c_4[i] * (c_4[i] - 1) * (c_4[i] - 2) * (c_4[i] - 3));
                        }

                    };
                };
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil

#endif  // CRYPTO3_BLUEPRINT_PLONK_BBF_EXP_COMPONENT_HPP
