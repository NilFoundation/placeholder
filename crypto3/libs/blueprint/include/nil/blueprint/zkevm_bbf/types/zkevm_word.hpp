//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#include <nil/crypto3/multiprecision/literals.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/keccak.hpp>

namespace nil {
    namespace blueprint {
        using zkevm_word_type = nil::crypto3::multiprecision::big_uint<256>;
        inline static constexpr zkevm_word_type neg_one =
            zkevm_word_type(1).wrapping_neg();
        inline static constexpr zkevm_word_type min_neg = zkevm_word_type(1) << 255;
        inline static constexpr auto extended_zkevm_mod =
            nil::crypto3::multiprecision::big_uint<512>(1) << 256;

        template<typename BlueprintFieldType>
        std::vector<typename BlueprintFieldType::value_type> zkevm_word_to_field_element(
            const zkevm_word_type &word) {
            using value_type = typename BlueprintFieldType::value_type;
            std::vector<value_type> chunks;
            constexpr const std::size_t chunk_size = 16;
            constexpr const std::size_t num_chunks = 256 / chunk_size;
            constexpr const zkevm_word_type mask = (zkevm_word_type(1) << chunk_size) - 1;
            zkevm_word_type word_copy = word;
            for (std::size_t i = 0; i < num_chunks; ++i) {
                chunks.push_back(word_copy & mask);
                word_copy >>= chunk_size;
            }
            return chunks;
        }

        template<typename BlueprintFieldType>
        std::vector<typename BlueprintFieldType::value_type> zkevm_word_to_field_element_flexible(
            const zkevm_word_type &word, const std::size_t num_chunks, const std::size_t chunk_size = 16) {
            using value_type = typename BlueprintFieldType::value_type;
            std::vector<value_type> chunks;
            const zkevm_word_type mask = (zkevm_word_type(1) << chunk_size) - 1;
            zkevm_word_type word_copy = word;
            for (std::size_t i = 0; i < num_chunks; ++i) {
                chunks.push_back(word_copy & mask);
                word_copy >>= chunk_size;
            }
            return chunks;
        }

        template<typename BlueprintFieldType>
        std::vector<typename BlueprintFieldType::value_type> chunk_64_to_16(
            const typename BlueprintFieldType::value_type &value
        ) {
            using value_type = typename BlueprintFieldType::value_type;
            using integral_type = typename BlueprintFieldType::integral_type;
            std::vector<value_type> chunks;
            constexpr const std::size_t chunk_size = 16;
            constexpr const std::size_t num_chunks = 4;
            constexpr const integral_type mask = (integral_type(1) << chunk_size) - 1;
            integral_type value_copy = value.to_integral();
            for (std::size_t i = 0; i < num_chunks; ++i) {
                chunks.push_back(static_cast<value_type>(value_copy & mask));
                value_copy >>= chunk_size;
            }
            return chunks;
        }

        std::uint8_t char_to_hex(char c) {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        }

        zkevm_word_type zkevm_word_from_string(std::string val){
            zkevm_word_type result;
            for(std::size_t i = 0; i < val.size(); i++ ){
                result *= 16;
                result += char_to_hex(val[i]);
            }
            return result;
        }

        zkevm_word_type zkevm_word_from_bytes(const std::vector<std::uint8_t> &buffer){
            zkevm_word_type result;
            for(std::size_t i = 0; i < buffer.size(); i++ ){
                result *= 256;
                result += buffer[i];
            }
            return result;
        }

        template<typename BlueprintFieldType>
        typename BlueprintFieldType::value_type w_hi(const zkevm_word_type &val) {
            static constexpr zkevm_word_type mask =
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000_big_uint256;
            return (val & mask) >> 128;
        }

        template<typename BlueprintFieldType>
        typename BlueprintFieldType::value_type w_lo(const zkevm_word_type &val) {
            static constexpr zkevm_word_type mask = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256;
            return val & mask;
        }


        std::array<std::uint8_t, 64> w_to_4(const zkevm_word_type &val) {
            std::array<std::uint8_t, 64> result;
            zkevm_word_type tmp(val);
            for(std::size_t i = 0; i < 64; i++){
                result[63-i] = std::uint8_t(tmp & 0xF); tmp >>=  4;
            }
            return result;
        }

        std::array<std::uint8_t, 32> w_to_8(const zkevm_word_type &val) {
            std::array<std::uint8_t, 32> result;
            zkevm_word_type tmp(val);
            for(std::size_t i = 0; i < 32; i++){
                result[31-i] = std::uint8_t(tmp & 0xFF); tmp >>=  8;
            }
            return result;
        }

        std::array<zkevm_word_type, 32> w_8(const zkevm_word_type &val) {
            std::array<std::uint8_t, 32> uints = w_to_8(val);
            std::array<zkevm_word_type, 32> result;
            for (size_t i = 0; i < 32; i++)
            {
                result[i] = zkevm_word_type(uints[i]);
            }
            return result;
            
        }

        std::array<zkevm_word_type, 64> w_4(const zkevm_word_type &val) {
            std::array<std::uint8_t, 64> uints = w_to_4(val);
            std::array<zkevm_word_type, 64> result;
            for (size_t i = 0; i < 64; i++)
            {
                result[i] = zkevm_word_type(uints[i]);
            }
            return result;
            
        }

        std::array<std::size_t, 16> w_to_16(const zkevm_word_type &val) {
            std::array<std::size_t, 16> result;
            zkevm_word_type tmp(val);
            for(std::size_t i = 0; i < 16; i++){
                result[15-i] = std::size_t(tmp & 0xFFFF); tmp >>=  16;
            }
            return result;
        }

        template <typename T = size_t>
        std::array<T, 16> w_to_16_le(const zkevm_word_type &val) {
            std::array<T, 16> result;
            val.export_bits(result.begin(), 16, false);
            return result;
        }

        template <typename BlueprintFieldType>
        std::array<typename BlueprintFieldType::value_type, 2> w_to_128(const zkevm_word_type &val){
            std::array<typename BlueprintFieldType::value_type, 2> result;
            result[0] = w_hi;
            result[1] = w_lo;
            return result;
        }

        // Return a/b, a%b
        std::pair<zkevm_word_type, zkevm_word_type> eth_div(const zkevm_word_type &a, const zkevm_word_type &b){
            zkevm_word_type r_integral = b != 0u ? a / b : 0u;
            zkevm_word_type r = r_integral;
            zkevm_word_type q = b != 0u ? a % b : 0u;
            return {r, q};
        }

        bool is_negative(zkevm_word_type x) { return x.bit_test(255); }

        zkevm_word_type negate_word(const zkevm_word_type &x) { return x.wrapping_neg(); }

        zkevm_word_type abs_word(zkevm_word_type x) { return is_negative(x) ? negate_word(x) : x; }

        zkevm_word_type zkevm_keccak_hash(std::vector<uint8_t> input){
            nil::crypto3::hashes::keccak_1600<256>::digest_type d = nil::crypto3::hash<nil::crypto3::hashes::keccak_1600<256>>(input);
            nil::crypto3::algebra::fields::field<256>::integral_type n(d);
            zkevm_word_type result(n);

            return result;
        }

        // Return a/b, a%b
        std::pair<zkevm_word_type, zkevm_word_type> eth_signed_div(const zkevm_word_type &a,
                                                                   const zkevm_word_type &b_input) {
            zkevm_word_type b = (a == neg_one) && (b_input == min_neg) ? 1u : b_input;
            zkevm_word_type a_abs = abs_word(a),
                        b_abs = abs_word(b);

            // TODO(ioxid): optimize this, use divide_qr
            zkevm_word_type r_abs = b != 0u ? a_abs / b_abs : 0u;
            zkevm_word_type q_abs = b != 0u ? a_abs % b_abs : a_abs,
                            r = (is_negative(a) == is_negative(b)) ? r_abs : negate_word(r_abs),
                            q = is_negative(a) ? negate_word(q_abs) : q_abs;

            zkevm_word_type q_out = b != 0u ? q : 0u;  // according to EVM spec a % 0 = 0

            return {r, q_out};
        }
    }   // namespace blueprint
}   // namespace nil
