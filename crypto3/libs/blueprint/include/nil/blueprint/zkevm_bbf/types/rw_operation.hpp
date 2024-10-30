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
            enum class rw_operation_type {
                start, stack, memory,storage, transient_storage, call_context,
                account, tx_refund_op, tx_access_list_account,
                tx_access_list_account_storage, tx_log, tx_receipt, padding
            };
            static constexpr std::size_t rw_operation_types_amount = 13;

            struct rw_operation{
                rw_operation_type op;           // operation type
                std::size_t       call_id;      // transaction number inside block
                zkevm_word_type   address;      // account_address (160 bits)
                std::uint8_t      field;        // — for storage only. If given value exist before current operation or not
                zkevm_word_type   storage_key;
                std::size_t       rw_counter;
                bool              is_write;
                zkevm_word_type   initial_value; // for stack, memory ,it’s zero, Storage item value before transaction for storage operation
                zkevm_word_type   value;
                zkevm_word_type   initial_root;  // used only for storage.
                zkevm_word_type   root;          // used only for storage. Last operation.
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil