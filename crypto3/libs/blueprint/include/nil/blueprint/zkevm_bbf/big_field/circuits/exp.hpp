//---------------------------------------------------------------------------//
// Copyright (c) 2025 Valeh Farzaliyev <estoniaa@nil.foundation>
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

#pragma once

#include <boost/multiprecision/cpp_int.hpp>
#include <functional>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/subcomponents/exp_table.hpp>
#include <nil/blueprint/zkevm_bbf/util.hpp>

namespace nil::blueprint::bbf::zkevm_big_field{
    template<typename FieldType, GenerationStage stage>
    class exponentiation : public generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

    public:
        using ExpTable = exp_table<FieldType, stage>;

        using input_type = ExpTable::input_type;

        using typename generic_component<FieldType, stage>::TYPE;
        using typename generic_component<FieldType, stage>::table_params;
        using word_type = zkevm_word_type;
        using to_integral = typename FieldType::integral_type;

        const std::size_t start_row = 1;
        std::size_t max_rows;
        std::size_t max_working_rows;
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

        static table_params get_minimal_requirements(std::size_t max_rows_amount,
                                                    std::size_t max_exponentiations) {
            return {
                .witnesses = 48 + ExpTable::get_witness_amount(),
                .public_inputs = 1,
                .constants = 2,
                .rows = max_rows_amount
            };
        }

        static void allocate_public_inputs(
                context_type &context, input_type &input,
                std::size_t max_rows_amount, std::size_t max_exponentiations) {}

        exponentiation(
            context_type &context_object,
            const input_type &input,
            std::size_t max_rows_amount,
            std::size_t max_exponentiations_
        ) :
            max_rows(max_rows_amount),
            max_exponentiations(max_exponentiations_),
            generic_component<FieldType, stage>(context_object)
        {
            max_working_rows = max_rows - start_row;

            std::size_t num_proving_blocks = (max_working_rows) / 3;
            std::vector<std::array<TYPE, num_chunks>> base = std::vector<std::array<TYPE, num_chunks>>(max_working_rows);
            std::vector<std::array<TYPE, num_chunks>> exponent = std::vector<std::array<TYPE, num_chunks>>(max_working_rows);
            std::vector<std::array<TYPE, num_chunks>> exponentiation = std::vector<std::array<TYPE, num_chunks>>(max_working_rows);

            std::vector<std::vector<TYPE>> a_chunks = std::vector<std::vector<TYPE>>(num_proving_blocks, std::vector<TYPE>(16));
            std::vector<std::vector<TYPE>> b_chunks = std::vector<std::vector<TYPE>>(num_proving_blocks, std::vector<TYPE>(16));
            std::vector<std::vector<TYPE>> r_chunks = std::vector<std::vector<TYPE>>(num_proving_blocks, std::vector<TYPE>(16));

            std::vector<std::vector<TYPE>> c_1_chunks = std::vector<std::vector<TYPE>>(num_proving_blocks, std::vector<TYPE>(4));
            std::vector<std::vector<TYPE>> c_3_chunks = std::vector<std::vector<TYPE>>(num_proving_blocks, std::vector<TYPE>(4));

            std::vector<TYPE> c_2 = std::vector<TYPE>(num_proving_blocks);
            std::vector<TYPE> c_4 = std::vector<TYPE>(num_proving_blocks);
            std::vector<std::array<TYPE, num_chunks>> itermediate_exponents = std::vector<std::array<TYPE, 2>>(max_working_rows);
            std::vector<TYPE> hi_last = std::vector<TYPE>(num_proving_blocks);
            std::vector<TYPE> exp_is_even = std::vector<TYPE>(num_proving_blocks);
            std::vector<TYPE> is_last = std::vector<TYPE>(max_working_rows);
            std::vector<TYPE> header_selector = std::vector<TYPE>(max_working_rows);

            std::size_t current_column = 48;
            std::vector<std::size_t> exp_lookup_area;
            for( std::size_t i = 0; i < ExpTable::get_witness_amount(); i++){
                exp_lookup_area.push_back(current_column++);
            }
            context_type exp_ct = context_object.subcontext( exp_lookup_area, start_row, max_exponentiations);
            ExpTable exp_t = ExpTable(exp_ct, input, max_exponentiations);

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                std::size_t cur = 0;
                BOOST_ASSERT(input.size() <= max_exponentiations);
                for(std::size_t i = 0; i < input.size(); i++){
                    word_type exp_a = input[i].first;
                    word_type exp_d = input[i].second;
                    word_type exp_A = exp_by_squaring(exp_a, exp_d);
                    // We don't prove zero and one exponent by lookup table
                    if( exp_d == 0 || exp_d == 1 ) continue;

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
                        e = wrapping_mul(a, b);
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
                        hi_last[cur] = exponent[3*cur][0].to_integral() & 1;

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

                        auto first_row_carries = first_carryless_consrtruct<TYPE>(a_64_chunks, b_64_chunks, r_64_chunks).to_integral() >> 128;
                        TYPE c_1 = first_row_carries & ((two_64 - 1).to_integral());
                        c_2[cur] = first_row_carries >> 64;
                        c_1_chunks[cur] = chunk_64_to_16<FieldType>(c_1);
                        // no need for c_2 chunks as there is only a single chunk
                        auto second_row_carries = (second_carryless_construct<TYPE>(a_64_chunks, b_64_chunks, r_64_chunks) + c_1 + c_2[cur] * two_64).to_integral() >> 128;
                        TYPE c_3 = second_row_carries & to_integral((two_64 - 1).to_integral());
                        c_4[cur] = second_row_carries >> 64;
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

            for(std::size_t row_idx = 0; row_idx < max_working_rows; row_idx++){
                // start row is not zero, because we shouldn't place lookup table in the first row.
                std::size_t current_row = row_idx + start_row;
                allocate(header_selector[row_idx], 0, current_row);

                for(std::size_t chunk_idx = 0; chunk_idx < num_chunks; chunk_idx++){
                    allocate(base[row_idx][chunk_idx], chunk_idx + 1, current_row);
                    allocate(exponent[row_idx][chunk_idx], num_chunks + chunk_idx + 1, current_row);
                    allocate(exponentiation[row_idx][chunk_idx], 2*num_chunks + chunk_idx + 1, current_row);
                }
                allocate(is_last[row_idx], 3*num_chunks + 1, current_row);
            }

            for(std::size_t block_idx =0; block_idx < num_proving_blocks; block_idx++){
                std::size_t block_start_row = 3*block_idx + start_row; // Each block needs 3 rows. First row is empty

                for(std::size_t j = 0; j < 16; j++){
                    allocate(r_chunks[block_idx][j], 3*num_chunks + j + 2, block_start_row);
                    allocate(b_chunks[block_idx][j], 3*num_chunks + j + 2, block_start_row + 1);
                    allocate(a_chunks[block_idx][j], 3*num_chunks + j + 2, block_start_row + 2);
                    lookup(r_chunks[block_idx][j], "chunk_16_bits/full");
                    lookup(b_chunks[block_idx][j], "chunk_16_bits/full");
                    lookup(a_chunks[block_idx][j], "chunk_16_bits/full");
                }
                for(std::size_t j = 0; j < 4; j++){
                    allocate(c_1_chunks[block_idx][j], 3*num_chunks + j + 18, block_start_row);
                    allocate(c_3_chunks[block_idx][j], 3*num_chunks + j + 18, block_start_row + 1);
                }
                allocate(c_2[block_idx], 3*num_chunks + 18, block_start_row + 2);
                allocate(c_4[block_idx], 3*num_chunks + 19, block_start_row + 2);

                allocate(exp_is_even[block_idx], 3*num_chunks + 20, block_start_row + 2);
                allocate(hi_last[block_idx], 3*num_chunks + 21, block_start_row + 2);
            }

            for(std::size_t i = 0; i < max_working_rows; i++){
                lookup(std::vector<TYPE>({
                    header_selector[i],
                    header_selector[i]*base[i][0],
                    header_selector[i]*base[i][1],
                    header_selector[i]*exponent[i][0],
                    header_selector[i]*exponent[i][1],
                    header_selector[i]*exponentiation[i][0],
                    header_selector[i]*exponentiation[i][1]
                }), "zkevm_exp");

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
                    if(i > 0){
                        constrain((1-is_last[3*i-1])*(a_chunks[i-1][j] - r_chunks[i][j])); // r = prev a
                    }
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
                lookup(16384*c_4[i], "chunk_16_bits/full"); // => c_4[i] = 0,1,2 or 3
            }
            lookup_table("exp_prover", {0,1,2,3,4,5,6}, start_row ,max_working_rows);
            for( std::size_t i = start_row; i < max_exponentiations; i++){
                lookup({
                    exp_t.selector[i],
                    exp_t.selector[i] * exp_t.base_hi[i],
                    exp_t.selector[i] * exp_t.base_lo[i],
                    exp_t.selector[i] * exp_t.exponent_hi[i],
                    exp_t.selector[i] * exp_t.exponent_lo[i],
                    exp_t.selector[i] * exp_t.exponentiation_hi[i],
                    exp_t.selector[i] * exp_t.exponentiation_lo[i]
                }, "exp_prover");
            }
        }
    };
}
