//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova   <e.tatuzova@nil.foundation>
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
#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/blueprint/components/hashes/keccak/util.hpp> //Move needed utils to bbf
#include <nil/blueprint/bbf/generic.hpp>

#include <nil/blueprint/zkevm_bbf/types/zkevm_word.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            nil::blueprint::zkevm_word_type
            zkevm_keccak_hash(const std::vector<uint8_t> &buffer){
                nil::crypto3::hashes::keccak_1600<256>::digest_type d = nil::crypto3::hash<nil::crypto3::hashes::keccak_1600<256>>(buffer);
                nil::crypto3::algebra::fields::field<256>::integral_type n(d);
                nil::blueprint::zkevm_word_type hash_value(n);

                return hash_value;
            }

            class zkevm_keccak_buffers {
            public:
                using zkevm_word_type = nil::blueprint::zkevm_word_type;
                using data_item = std::pair<std::vector<std::uint8_t>, zkevm_word_type>;
                using data_type = std::vector<data_item>;

                void fill_data(const data_type& _input){
                    input = _input;
                }

                std::size_t new_buffer(const data_item &_pair){
                    input.push_back(_pair);
                    return input.size() - 1;
                }

                std::size_t new_buffer(const std::vector<std::uint8_t>& buffer){
                    input.push_back({buffer, zkevm_keccak_hash(buffer)});
                    return input.size() - 1;
                }

                void push_byte(std::size_t code_id, std::uint8_t b){
                    BOOST_ASSERT(code_id < input.size());
                    input[code_id].first.push_back(b);
                    input[code_id].second = zkevm_keccak_hash(input[code_id].first);
                }

                const data_type &get_data() const{
                    return input;
                }
                data_type input;
            };

        } // namespace bbf
    } // namespace blueprint
} // namespace nil