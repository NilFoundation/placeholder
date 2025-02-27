//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/bench/scoped_profiler.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/rw_table.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            template <typename TYPE>
            std::pair<TYPE, TYPE>chunks16_to_chunks128(const std::vector<TYPE> &chunks){
                TYPE result_hi, result_lo;
                for(std::size_t i = 0; i < 8; i++){
                    result_hi *= 0x10000;
                    result_hi += chunks[i];
                    result_lo *= 0x10000;
                    result_lo += chunks[i+8];
                }
                return {result_hi, result_lo};
            }

            template <typename TYPE>
            std::pair<TYPE, TYPE>chunks16_to_chunks128_reversed(const std::vector<TYPE> &chunks){
                TYPE result_hi, result_lo;
                for(std::size_t i = 0; i < 8; i++){
                    result_lo *= 0x10000;
                    result_lo += chunks[7 - i];
                    result_hi *= 0x10000;
                    result_hi += chunks[15 - i];
                }
                return {result_hi, result_lo};
            }

            template <typename TYPE>
            std::pair<TYPE, TYPE>chunks8_to_chunks128(const std::vector<TYPE> &chunks){
                TYPE result_hi, result_lo;
                for(std::size_t i = 0; i < 16; i++){
                    result_hi *= 0x100;
                    result_hi += chunks[i];
                    result_lo *= 0x100;
                    result_lo += chunks[i+16];
                }
                return {result_hi, result_lo};
            }

            zkevm_word_type exp_by_squaring(zkevm_word_type a, zkevm_word_type n) {
                if (n == 0x00_big_uint256) return 1;
                if (n == 0x01_big_uint256) return a;

                zkevm_word_type exp = exp_by_squaring(a, n >> 1);
                zkevm_word_type exp2 = wrapping_mul(exp, exp);
                if (n & 1) {
                    return wrapping_mul(exp2, a);
                }
                return exp2;
            }

            std::size_t count_significant_bytes(zkevm_word_type d) {
                std::size_t count = 0;
                while (d > 0) d /= 256u, ++count;
                return count;
            }

            std::size_t memory_size_word_util(std::size_t memory_byte_size){
                return (memory_byte_size + 31) / 32;
            }

            std::size_t memory_cost_util(std::size_t memory_byte_size){
                return (memory_size_word_util(memory_byte_size) * memory_size_word_util(memory_byte_size)) / 512 + (3 * memory_size_word_util(memory_byte_size));
            }

            std::size_t memory_expansion_cost(std::size_t new_memory_byte_size, std::size_t last_memory_byte_size) {
                return memory_cost_util(new_memory_byte_size) - memory_cost_util(last_memory_byte_size);
            }

            // We define constants using the smallest possible bitlengths from nil/crypto3/multiprecision/literals.hpp
            // Maybe it would have been better to define more bitlenghts, but this will probably all disappear, once
            // small fields are introduced.
            static const unsigned int two_15 = 32768;
            static const unsigned int two_16 = 65536;
            static const nil::crypto3::multiprecision::big_uint<64> two_32 = 4294967296;
            static const nil::crypto3::multiprecision::big_uint<64> two_48 = 281474976710656;
            static const nil::crypto3::multiprecision::big_uint<92> two_64 = 0x10000000000000000_big_uint92;
            static const nil::crypto3::multiprecision::big_uint<130> two_128 = 0x100000000000000000000000000000000_big_uint130;
            static const nil::crypto3::multiprecision::big_uint<205>
                two_192 = 0x1000000000000000000000000000000000000000000000000_big_uint205;

            template<typename T, typename V = T>
            T chunk_sum_64(const std::vector<V> &chunks, const unsigned char chunk_idx) {
                BOOST_ASSERT(chunk_idx < 4);
                return chunks[4 * chunk_idx] + chunks[4 * chunk_idx + 1] * two_16 +
                       chunks[4 * chunk_idx + 2] * two_32 + chunks[4 * chunk_idx + 3] * two_48;
            }

            // computes 128-bit chunks of r*b + q - a
            template<typename T>
            T first_carryless_construct(const std::vector<T> &a_64_chunks,
                                        const std::vector<T> &b_64_chunks,
                                        const std::vector<T> &r_64_chunks,
                                        const std::vector<T> &q_64_chunks) {
                return r_64_chunks[0] * b_64_chunks[0] + q_64_chunks[0] +
                       T(two_64) * (r_64_chunks[0] * b_64_chunks[1] +
                                 r_64_chunks[1] * b_64_chunks[0] + q_64_chunks[1]) -
                       a_64_chunks[0] - T(two_64) * a_64_chunks[1];
            }

            template<typename T>
            T second_carryless_construct(const std::vector<T> &a_64_chunks,
                                         const std::vector<T> &b_64_chunks,
                                         const std::vector<T> &r_64_chunks,
                                         const std::vector<T> &q_64_chunks) {
                return (r_64_chunks[0] * b_64_chunks[2] + r_64_chunks[1] * b_64_chunks[1] +
                        r_64_chunks[2] * b_64_chunks[0] + q_64_chunks[2] - a_64_chunks[2]) +
                       T(two_64) *
                           (r_64_chunks[0] * b_64_chunks[3] + r_64_chunks[1] * b_64_chunks[2] +
                            r_64_chunks[2] * b_64_chunks[1] + r_64_chunks[3] * b_64_chunks[0] +
                            q_64_chunks[3] - a_64_chunks[3]);
            }

            template<typename T>
            T third_carryless_construct(const std::vector<T> &b_64_chunks,
                                        const std::vector<T> &r_64_chunks) {
                return (r_64_chunks[1] * b_64_chunks[3] + r_64_chunks[2] * b_64_chunks[2] +
                        r_64_chunks[3] * b_64_chunks[1]) +
                       T(two_64) *
                           (r_64_chunks[2] * b_64_chunks[3] + r_64_chunks[3] * b_64_chunks[2]);
            }
        }
    }
}
