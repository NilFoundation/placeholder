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
#include <nil/blueprint/zkevm/util/ptree.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            enum class rw_operation_type {
                start, stack, memory,storage, transient_storage, call_context,
                account, tx_refund_op, tx_access_list_account,
                tx_access_list_account_storage, tx_log, tx_receipt,
                padding
            };
            static constexpr std::size_t rw_operation_types_amount = 13;

            std::size_t rw_op_to_num(rw_operation_type rw_op){
                if( rw_op == rw_operation_type::start ) return 0;
                if( rw_op == rw_operation_type::stack ) return 1;
                if( rw_op == rw_operation_type::memory ) return 2;
                if( rw_op == rw_operation_type::storage ) return 3;
                if( rw_op == rw_operation_type::transient_storage ) return 4;
                if( rw_op == rw_operation_type::call_context ) return 5;
                if( rw_op == rw_operation_type::account ) return 6;
                if( rw_op == rw_operation_type::tx_refund_op ) return 7;
                if( rw_op == rw_operation_type::tx_access_list_account ) return 8;
                if( rw_op == rw_operation_type::tx_access_list_account_storage ) return 9;
                if( rw_op == rw_operation_type::tx_log ) return 10;
                if( rw_op == rw_operation_type::tx_receipt ) return 11;
                if( rw_op == rw_operation_type::padding ) return 12;
                BOOST_ASSERT(false);
                return 12;

            }

            struct rw_operation{
                using zkevm_word_type = nil::blueprint::zkevm_word_type;

                rw_operation_type op;           // operation type
                std::size_t       call_id;      // transaction number inside block
                zkevm_word_type   address;      // account_address (160 bits)
                std::uint8_t      field;        // — for storage only. If given value exist before current operation or not
                zkevm_word_type   storage_key;
                std::size_t       rw_counter;
                bool              is_write;
                zkevm_word_type   value;
                zkevm_word_type   initial_value; // for stack, memory ,it’s zero, Storage item value before transaction for storage operation
                zkevm_word_type   root;          // used only for storage. Last operation.
                zkevm_word_type   initial_root;  // used only for storage.
                bool operator< (const rw_operation &other) const {
                    if( op != other.op ) return op < other.op;
                    if( call_id != other.call_id ) return call_id < other.call_id;
                    if( address != other.address ) return address < other.address;
                    if( field != other.field ) return field < other.field;
                    if( storage_key != other.storage_key ) return storage_key < other.storage_key;
                    if( rw_counter != other.rw_counter) return rw_counter < other.rw_counter;
                    return false;
                }
            };

            rw_operation start_rw_operation(){
                return rw_operation({rw_operation_type::start, 0, 0, 0, 0, 0, 0, 0});
            }

            rw_operation stack_rw_operation(std::size_t id, uint16_t address, std::size_t rw_id, bool is_write, zkevm_word_type value){
                BOOST_ASSERT(id < ( 1 << 28)); // Maximum calls amount(?)
                BOOST_ASSERT(address < 1024);
                return rw_operation({rw_operation_type::stack, id, address, 0, 0, rw_id, is_write, value, 0});
            }

            rw_operation memory_rw_operation(std::size_t id, zkevm_word_type address, std::size_t rw_id, bool is_write, zkevm_word_type value){
                BOOST_ASSERT(id < ( 1 << 28)); // Maximum calls amount(?)
                return rw_operation({rw_operation_type::memory, id, address, 0, 0, rw_id, is_write, value, 0});
            }

            rw_operation storage_rw_operation(
                std::size_t id,
                zkevm_word_type storage_key,
                std::size_t rw_id,
                bool is_write,
                zkevm_word_type value,
                zkevm_word_type value_prev
            ){
                return rw_operation({rw_operation_type::storage, id, 0, 0, storage_key, rw_id, is_write, value, value_prev});
            }

            rw_operation padding_operation(){
                return rw_operation({rw_operation_type::padding, 0, 0, 0, 0, 0, 0, 0});
            }
        } // namespace bbf
    } // namespace blueprint
} // namespace nil