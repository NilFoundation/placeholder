//---------------------------------------------------------------------------//
// Copyright (c) 2025 Elena Tatuzova   <e.tatuzova@nil.foundation>
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
#include <nil/blueprint/zkevm_bbf/types/zkevm_word.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            struct zkevm_transaction {
                zkevm_word_type              hash;
                std::size_t                  chain_id;
                std::size_t                  gas;
                zkevm_word_type              to;
                zkevm_word_type              from;
                zkevm_word_type              value;
                zkevm_word_type              gasprice;
                zkevm_word_type              max_fee_per_gas;
                zkevm_word_type              max_fee_per_blob_gas;
                zkevm_word_type              max_priority_fee_per_gas;
                bool                         deploy;
                std::vector<zkevm_word_type> blob_versioned_hashes;
                std::vector<std::uint8_t>    calldata;

                std::set<zkevm_word_type>                               account_access_list;
                std::set<std::pair<zkevm_word_type, zkevm_word_type>>   storage_access_list;
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil
