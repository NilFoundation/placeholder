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

#include <nil/blueprint/zkevm_bbf/types/zkevm_state.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            struct zkevm_call_context{
                zkevm_state state;            // State from parent CALL before CALL
                std::size_t call_id;          // Current CALL id
                std::size_t returndataoffset; // CALL opcode parameters
                std::size_t returndatalength; // CALL opcode parameters
                std::map<std::tuple<rw_operation_type, zkevm_word_type, std::size_t, zkevm_word_type>, rw_operation> cold_access_list; // For REVERT proving. First state access rw_operation in the given CALL
                std::map<std::tuple<rw_operation_type, zkevm_word_type, std::size_t, zkevm_word_type>, rw_operation> cold_write_list;

                std::set<std::tuple<zkevm_word_type, std::size_t, zkevm_word_type>> was_accessed; // For SLOAD, SSTORE gas proving
                std::set<std::tuple<zkevm_word_type, std::size_t, zkevm_word_type>> was_written;

                std::size_t end; // rw_counter before opcode that finishes CALL -- REVERT, STOP, RETURN
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil
