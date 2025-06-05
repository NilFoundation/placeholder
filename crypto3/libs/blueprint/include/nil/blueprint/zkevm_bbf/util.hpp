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

            template <typename TYPE>
            std::pair<TYPE, TYPE>chunks8_to_chunks128(const std::array<TYPE, 32> &chunks){
                TYPE result_hi, result_lo;
                for(std::size_t i = 0; i < 16; i++){
                    result_hi *= 0x100;
                    result_hi += chunks[i];
                    result_lo *= 0x100;
                    result_lo += chunks[i+16];
                }
                return {result_hi, result_lo};
            }

            template <typename TYPE>
            std::vector<TYPE> chunks8_to_chunks16(const std::array<TYPE, 32> &chunks) {
                std::vector<TYPE> res;
                for(std::size_t i = 0; i < 16; i++) {
                    res.push_back(chunks[2*i] * 0x100 + chunks[2*i+1]);
                }
                return res;
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

            std::vector<std::uint8_t> byte_vector_from_hex_string(const std::string &hex_string, std::size_t prefix_size = 0) {
                std::vector<std::uint8_t> result;
                for (std::size_t i = prefix_size; i < hex_string.size(); i += 2) {
                    std::uint8_t byte = char_to_hex(hex_string[i]) * 16 + char_to_hex(hex_string[i + 1]);
                    result.push_back(byte);
                }
                return result;
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

            std::string byte_vector_to_hex_string(const std::vector<std::uint8_t> &byte_vector, std::size_t offset = 0, int length = -1) {
                std::stringstream ss;
                if( length < 0 ) length = byte_vector.size();
                for (std::size_t i = offset; i < length; ++i) {
                    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte_vector[i]);
                }
                return ss.str();
            }

            std::string byte_vector_to_sparse_hex_string(const std::vector<std::uint8_t> &byte_vector, std::size_t offset = 0, int length = -1) {
                std::stringstream ss;
                if( length < 0 ) length = byte_vector.size();
                for (std::size_t i = offset; i < length; ++i) {
                    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte_vector[i]) << " ";
                }
                return ss.str();
            }
        }
    }
}
