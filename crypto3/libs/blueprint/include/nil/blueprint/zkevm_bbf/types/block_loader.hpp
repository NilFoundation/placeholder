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
#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/blueprint/components/hashes/keccak/util.hpp> //Move needed utils to bbf
#include <nil/blueprint/bbf/generic.hpp>

#include <nil/blueprint/zkevm_bbf/types/zkevm_block.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_transaction.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            class abstract_block_loader{
            public:
                virtual zkevm_block load_block() = 0;
                virtual std::tuple<zkevm_transaction, std::map<zkevm_word_type, zkevm_account>, std::set<zkevm_word_type>> load_transaction(std::size_t i) = 0;
                virtual bool are_there_more_blocks() = 0;

                // TODO: implement precompiles and remove this function from interface
                virtual std::tuple<zkevm_word_type, std::size_t, std::vector<std::uint8_t>> compute_precompile(zkevm_word_type address, std::vector<std::uint8_t> calldata) = 0;
            };
        }
    }
}