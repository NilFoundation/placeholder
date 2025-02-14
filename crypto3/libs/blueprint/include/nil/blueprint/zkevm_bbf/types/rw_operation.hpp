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

#include <nil/blueprint/zkevm_bbf/types/zkevm_word.hpp>
#include <nil/blueprint/zkevm_bbf/util/ptree.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            enum class rw_operation_type: std::uint8_t {
                start = 0,
                stack = 1,
                memory = 2,

                state = 3,          // Grouped by block, includes STORAGE and ACCOUNT operations
                transient_storage = 4, // Grouped by transaction
                call_context = 5,   // Grouped by call

                tx_refund =6,
                tx_log = 7,         // Do we really need it?
                tx_receipt = 8,

                call_state = 9,     // STATE operations grouped by call for REVERT proving
                // call_transient_state -- may be later

                padding = 10
            };
            static constexpr std::size_t rw_operation_types_amount = 11;

            std::size_t rw_op_to_num(rw_operation_type rw_op){
                return std::size_t(rw_op);
            }

            struct rw_operation{
                using zkevm_word_type = nil::blueprint::zkevm_word_type;

                rw_operation_type op;           // operation type
                std::size_t       id;           // identifier of CALL, transaction or block for different types of operations
                zkevm_word_type   address;      // account_address (160 bits)
                std::uint8_t      field;
                zkevm_word_type   storage_key;
                std::size_t       rw_counter;
                bool              is_write;
                zkevm_word_type   value;
                zkevm_word_type   initial_value; // for stack, memory ,it’s zero, Storage item value before transaction for storage operation
                zkevm_word_type   root;          // used only for storage and account. Last operation.
                zkevm_word_type   initial_root;  // used only for storage and account.

                //std::size_t       call_id;       // call_id -- call identifier for opcode that produced this operation

                bool operator< (const rw_operation &other) const {
                    if( op != other.op ) return op < other.op;                                      // 16 bits
                    if( id != other.id ) return id < other.id;                                      // 16 bits
                    if( address != other.address ) return address < other.address;                  // 160 bits
                    if( field != other.field ) return field < other.field;                          // 16 bits
                    if( storage_key != other.storage_key ) return storage_key < other.storage_key;  // 256 bits
                    if( rw_counter != other.rw_counter) return rw_counter < other.rw_counter;       // 32 bits
                    return false;
                }
            };

            // For testing purposes
            std::ostream& operator<<(std::ostream& os, const rw_operation& obj){
                if(obj.op == rw_operation_type::start )                           os << "START               : ";
                if(obj.op == rw_operation_type::stack )                           os << "STACK               : ";
                if(obj.op == rw_operation_type::memory )                          os << "MEMORY              : ";
                if(obj.op == rw_operation_type::state )                           os << "STATE               : ";
                if(obj.op == rw_operation_type::transient_storage )               os << "TRANSIENT_STORAGE   : ";
                if(obj.op == rw_operation_type::call_context )                    os << "CALL_CONTEXT_OP     : ";
                if(obj.op == rw_operation_type::tx_refund )                       os << "TX_REFUND_OP        : ";
                if(obj.op == rw_operation_type::tx_log )                          os << "TX_LOG_OP           : ";
                if(obj.op == rw_operation_type::tx_receipt )                      os << "TX_RECEIPT_OP       : ";
                if(obj.op == rw_operation_type::padding )                         os << "PADDING_OP          : ";
                os << "rw_id = " << obj.rw_counter << " id = " << obj.id << ", addr =" << std::hex << obj.address << std::dec;
                if(obj.op == rw_operation_type::state || obj.op == rw_operation_type::transient_storage)
                    os << " storage_key = " << obj.storage_key;
                if(obj.is_write) os << " W "; else os << " R ";
                os << "[" << std::hex << obj.initial_value << std::dec <<"] => ";
                os << "[" << std::hex << obj.value << std::dec <<"]";
                return os;
            }

            rw_operation start_rw_operation(){
                return rw_operation({rw_operation_type::start, 0, 0, 0, 0, 0, 0, 0});
            }

            rw_operation stack_rw_operation(
                std::size_t id,
                uint16_t address,
                std::size_t rw_id,
                bool is_write,
                zkevm_word_type value
            ){
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
                zkevm_word_type value_prev,
                zkevm_word_type root = zkevm_word_type(0)
            ){
                return rw_operation({rw_operation_type::state, id, 0, 0, storage_key, rw_id, is_write, value, value_prev});
            }

            rw_operation account_code_hash_rw_operation(
                std::size_t id,
                zkevm_word_type address,
                std::size_t rw_id,
                bool is_write,
                zkevm_word_type value,
                zkevm_word_type value_prev,
                zkevm_word_type root = zkevm_word_type(0)
            ){
                return rw_operation({rw_operation_type::state, id, address, 0, 0, rw_id, is_write, value, value_prev});
            }

            enum class call_context_field: std::uint8_t {
                parent_id = 1,
                to = 2
            };

            rw_operation call_context_rw_operation(
                std::size_t call_id,
                call_context_field field,
                std::size_t rw_id,
                bool is_write,
                zkevm_word_type value
            ){
                return rw_operation({rw_operation_type::call_context, call_id, 0, std::uint8_t(field), 0, rw_id, is_write, value, 0});
            }

            rw_operation padding_operation(){
                return rw_operation({rw_operation_type::padding, 0, 0, 0, 0, 0, 0, 0});
            }

            class rw_operations_vector: public std::vector<rw_operation>{
            public:
                rw_operations_vector(){
                    this->push_back(start_rw_operation());
                }
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil
