//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova   <e.tatuzova@nil.foundation>
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

#include <nil/blueprint/zkevm/zkevm_word.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            class zkevm_state{
            public:
                zkevm_word_type tx_hash; // full transaction hash. Now it is not used. But it’ll be used some day
                std::size_t     call_id; // call_id — number of current transaction in block
                std::size_t     pc;
                std::size_t     gas;
                std::size_t     rw_counter;
                zkevm_word_type bytecode_hash;
                std::size_t     opcode;
                zkevm_word_type additional_input; // data for pushX opcode
                std::size_t     stack_size;       // BEFORE opcode
                std::size_t     memory_size;      // BEFORE opcode
                bool            tx_finish;       // convinent, but optional11.
                std::size_t     error_opcode;    // real opcode if error

                zkevm_word_type stack_top(std::size_t depth = 0) const{
                    BOOST_ASSERT(depth < stack_slice.size());
                    return stack_slice[stack_slice.size() - 1 - depth];
                }

                zkevm_word_type memory(std::size_t addr) const{
                    if( memory_slice.find(addr) == memory_slice.end() )
                        return 0;
                    else
                        return memory_slice.at(addr);
                }

                zkevm_word_type storage(zkevm_word_type key) const{
                    if( storage_slice.find(key) == storage_slice.end() )
                        return 0;
                    else
                        return storage_slice.at(key);
                }
                zkevm_state(
                    const std::vector<zkevm_word_type>        &stack,
                    const std::map<std::size_t, std::uint8_t> &memory,
                    const std::map<zkevm_word_type, zkevm_word_type> &storage
                ): stack_slice(stack), memory_slice(memory), storage_slice(storage){}

                zkevm_state(){}
            public:
                std::vector<zkevm_word_type>                stack_slice; // BEFORE opcode
                std::map<std::size_t, std::uint8_t>         memory_slice; // BEFORE opcode
                std::map<zkevm_word_type, zkevm_word_type>  storage_slice; // BEFORE opcode
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil