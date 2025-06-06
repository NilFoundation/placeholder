//---------------------------------------------------------------------------//
// Copyright (c) 2025 Antoine Cyr   <antoinecyr@nil.foundation>
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
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/type_traits.hpp>

#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/components/hashes/keccak/util.hpp>  //Move needed utils to bbf


namespace nil {
    namespace blueprint {
        namespace bbf {
            const std::size_t filter_chunks_amount = 128;
            struct zkevm_log {
                std::size_t  id;
                std::size_t  index;
                zkevm_word_type address;
                std::vector<zkevm_word_type> topics;
            };
            struct zkevm_filter_indices {
                std::size_t block_id;
                std::size_t tx_id;
                std::size_t index;
                zkevm_word_type value;
                std::size_t type;
                std::size_t indice;
                std::size_t is_last;
                std::size_t is_block;
                std::size_t is_final;
                std::size_t rw_id;
                zkevm_word_type hash;
                std::vector<std::uint8_t> buffer;
                zkevm_word_type filter[filter_chunks_amount];
            };
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil
