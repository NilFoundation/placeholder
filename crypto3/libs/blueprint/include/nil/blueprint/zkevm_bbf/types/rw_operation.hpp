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

                state = 3,              // Grouped by block, includes STORAGE and ACCOUNT operations
                transient_storage = 4,  // Grouped by transaction
                call_context = 5,       // Grouped by call

                tx_refund =6,
                tx_log = 7,             // Do we really need it? Maybe look strait to reciept hash?
                tx_receipt = 8,

                cold_access = 9,         // STATE operations grouped by call for REVERT proving
                // call_transient_state -- may be latez

                padding = 10
            };
            static constexpr std::size_t rw_operation_types_amount = 11;

            std::size_t rw_op_to_num(rw_operation_type rw_op){
                return std::size_t(rw_op);
            }

            struct rw_operation{
                using zkevm_word_type = nil::blueprint::zkevm_word_type;

                rw_operation():
                    op(rw_operation_type::start),
                    id(0),
                    address(0),
                    field(0),
                    storage_key(0),
                    rw_counter(0),
                    is_write(false),
                    value(0),
                    initial_value(0),
                    helper_id(0),
                    root(0),
                    initial_root(0) {};

                rw_operation_type op;           // operation type
                std::size_t       id;
                zkevm_word_type   address;      // account_address (160 bits)
                std::uint8_t      field;
                zkevm_word_type   storage_key;
                std::size_t       rw_counter;
                bool              is_write;
                zkevm_word_type   value;

                zkevm_word_type   initial_value; // for stack, memory ,it’s zero, Storage item value before transaction for storage operation
                std::size_t       helper_id;

                zkevm_word_type   root;                 // used only for state and transient_storage.
                zkevm_word_type   initial_root;         // used only for state and transient_storage.
                // For cold_access proving
                std::size_t       parent_id;
                std::size_t       call_id_helper;
                std::size_t       rw_counter_helper;
                std::size_t       rw_id_before;
                std::size_t       write_id_before;
                zkevm_word_type   value_before;

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
                if(obj.op == rw_operation_type::cold_access )                     os << "COLD_ACCESS         : ";
                if(obj.op == rw_operation_type::padding )                         os << "PADDING             : ";
                os << "rw_id = " << obj.rw_counter << " id = " << obj.id << ", addr =" << std::hex << obj.address << std::dec;
                if( obj.op == rw_operation_type::state ||
                    obj.op == rw_operation_type::transient_storage ||
                    obj.op == rw_operation_type::cold_access
                )
                    os << " storage_key = " << obj.storage_key;
                if( obj.op == rw_operation_type::call_context){
                    std::cout << " field = ";
                    if(obj.field == 0) os << "parent_id";
                    if(obj.field == 1) os << "modified_items";
                    if(obj.field == 2) os << "block_id";
                    if(obj.field == 3) os << "tx_id";
                    if(obj.field == 4) os << "from";
                    if(obj.field == 5) os << "to";
                    if(obj.field == 6) os << "call_context_address";
                }
                if(obj.op == rw_operation_type::cold_access){
                    os << " parent_id = " << obj.parent_id;
                    os << " call_id_helper = " << obj.call_id_helper;
                    os << " rw_counter_helper = " << obj.rw_counter_helper;
                }
                if(obj.is_write) os << " W "; else os << " R ";
                os << "[" << std::hex << obj.initial_value << std::dec <<"] => ";
                os << "[" << std::hex << obj.value << std::dec <<"]";
                return os;
            }

            rw_operation start_rw_operation(){
                return rw_operation();
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

                rw_operation r;
                r.op = rw_operation_type::stack;
                r.id = id;
                r.address = address;
                r.field = 0;
                r.storage_key = 0;
                r.rw_counter = rw_id;
                r.is_write = is_write;
                r.value = value;
                r.initial_value = 0;

                return r;
            }

            rw_operation memory_rw_operation(std::size_t id, zkevm_word_type address, std::size_t rw_id, bool is_write, zkevm_word_type value){
                BOOST_ASSERT(id < ( 1 << 28)); // Maximum calls amount(?)
                rw_operation r;
                r.op = rw_operation_type::memory;
                r.id = id;
                r.address = address;
                r.rw_counter = rw_id;
                r.is_write = is_write;
                r.value = value;
                return r;
            }

            rw_operation storage_rw_operation(
                std::size_t     block_id,
                zkevm_word_type address,
                zkevm_word_type storage_key,
                std::size_t     rw_id,
                bool            is_write,
                zkevm_word_type value,
                zkevm_word_type initial_value,
                std::size_t     call_id,
                std::size_t     rw_id_before,
                std::size_t     write_id_before,
                zkevm_word_type value_before,
                zkevm_word_type root = zkevm_word_type(0),
                zkevm_word_type initial_root = zkevm_word_type(0)
            ){
                rw_operation r;
                r.op = rw_operation_type::state;
                r.id = block_id;
                r.address = address;
                r.storage_key = storage_key;
                r.field = 0;
                r.rw_counter = rw_id;
                r.is_write = is_write;
                r.initial_value = initial_value;
                r.value = value;
                r.helper_id = call_id;
                r.rw_id_before = rw_id_before;
                r.write_id_before = write_id_before;
                r.value_before = value_before;
                return r;
            }

            rw_operation state_rw_operation(
                std::size_t     block_id,
                zkevm_word_type address,
                std::size_t     field_tag,
                zkevm_word_type storage_key,
                std::size_t     rw_id,
                bool            is_write,
                zkevm_word_type value,
                zkevm_word_type initial_value,
                std::size_t     call_id,
                std::size_t     rw_id_before,
                std::size_t     write_id_before,
                zkevm_word_type value_before,
                zkevm_word_type root = zkevm_word_type(0),
                zkevm_word_type initial_root = zkevm_word_type(0)
            ){
                rw_operation r;
                r.op = rw_operation_type::state;
                r.id = block_id;
                r.address = address;
                r.storage_key = storage_key;
                r.field = field_tag;
                r.rw_counter = rw_id;
                r.is_write = is_write;
                r.initial_value = initial_value;
                r.value = value;
                r.helper_id = call_id;
                r.rw_id_before = rw_id_before;
                r.write_id_before = write_id_before;
                r.value_before = value_before;
                return r;
            }

            rw_operation cold_access_rw_operation(
                const std::size_t   call_id,
                const std::size_t   counter,
                const std::size_t   parent_id,
                const rw_operation& state_op
            ){
                BOOST_ASSERT(state_op.op == rw_operation_type::state);
                rw_operation r;
                r.op = rw_operation_type::cold_access;
                r.id = call_id;
                r.address = state_op.address;
                r.field = state_op.field;
                r.storage_key = state_op.storage_key;
                r.rw_counter = counter;
                r.is_write = state_op.is_write;
                r.value = state_op.value_before;
                r.initial_value = state_op.initial_value;
                r.helper_id = state_op.id; // Block_id
                r.parent_id = parent_id;
                r.call_id_helper = state_op.helper_id;
                r.rw_counter_helper = state_op.rw_counter;
                r.initial_value = state_op.value;
                r.rw_id_before = state_op.rw_id_before;
                r.write_id_before = state_op.write_id_before;
                r.value_before = state_op.value;
                std::cout << "Flush access list " << call_id
                    << " rw_id_before " << r.rw_id_before
                    << " write_id_before " << r.write_id_before
                    << std::endl;

                return r;
            }

            // TODO: define flag correctly
            rw_operation account_code_hash_rw_operation(
                std::size_t id,
                zkevm_word_type address,
                std::size_t rw_id,
                bool is_write,
                zkevm_word_type value,
                zkevm_word_type value_prev,
                zkevm_word_type root = zkevm_word_type(0)
            ){
                rw_operation r;
                r.op = rw_operation_type::state;
                r.id = id;
                r.address = address;
                r.storage_key = 0;
                r.field = 1;
                r.rw_counter = rw_id;
                r.is_write = is_write;
                r.value = value;
                r.initial_value = value_prev;
                return r;
            }

            enum class call_context_field: std::uint8_t {
                // For block, transaction and call
                parent_id = 0,              // For RETURN correctness
                modified_items = 1,

                // For transaction and call only
                block_id = 2,               // For rw_table STATE operation
                tx_id = 3,                  // For cold/hot access detection and for TRANIENT_STORAGE
                from = 4,                   // caller
                to = 5,                     // callee
                call_context_address = 6    // depends on CALL/DELEGATECALL opcodes
            };
            static constexpr std::size_t call_context_field_amount = 7;


            rw_operation call_context_rw_operation(
                std::size_t call_id,
                call_context_field field,
                zkevm_word_type value
            ){
                rw_operation r;
                r.op = rw_operation_type::call_context;
                r.id = call_id;
                r.field = std::uint8_t(field);
                r.rw_counter = call_id + std::uint8_t(field);
                r.value = value;
                return r;
            }

            rw_operation padding_operation(){
                rw_operation r;
                r.op = rw_operation_type::padding;
                return r;
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
