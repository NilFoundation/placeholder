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
                // Grouped by call, no revertions
                start = 0,
                stack = 1,
                memory = 2,
                call_context = 3,
                calldata = 4,
                returndata = 5,

                // May be reverted
                state = 6,              // Grouped by block, includes STORAGE and ACCOUNT operations
                transient_storage = 7,  // Grouped by transaction
                access_list = 8,

                padding = 9
            };
            static constexpr std::size_t rw_operation_types_amount = 10;

            enum class call_context_field: std::uint8_t {
                // For block, transaction and call -- read-only
                parent_id = 0,              // For RETURN correctness
                depth = 1,                  // For rw_table STATE operation
                end = 2,
                hash = 3,

                // For transaction and call only but fixed length -- readonly
                modified_items = 4,         // Do we need it for block?
                block_id = 5,               // For rw_table STATE operation
                tx_id = 6,                  // For cold/hot access detection and for TRANIENT_STORAGE
                is_static = 7,
                from = 8,                   // caller
                to = 9,                     // callee
                call_context_address = 10,  // depends on CALL/DELEGATECALL opcodes
                calldata_size = 11,
                returndata_size = 12,     // real RETURNDATA length (not requested by CALL) for given CALL

                // Fixed-length may be rewritten
                lastcall_id = 14,
                lastcall_returndata_offset = 15,
                lastcall_returndata_length = 16
            };
            static constexpr std::size_t call_context_field_amount = 17;
            static constexpr std::size_t call_context_readonly_field_amount = 13;
            static constexpr std::size_t block_context_field_amount = 4;


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
                    value_before(0),
                    initial_value(0),
                    w_id_before(0),
                    root(0),
                    initial_root(0),
                    call_id(0)
                    {};

                rw_operation_type op;           // operation type
                std::size_t       id;
                zkevm_word_type   address;      // account_address (160 bits)
                std::uint8_t      field;
                zkevm_word_type   storage_key;
                std::size_t       rw_counter;
                bool              is_write;
                zkevm_word_type   value;

                std::size_t       call_id;
                zkevm_word_type   initial_value; // for stack, memory ,it’s zero, Storage item value before transaction for storage operation
                zkevm_word_type   initial_root;         // used for state, OutMessages, InMessages
                zkevm_word_type   root;                 // used for state, OutMessages, InMessages
                zkevm_word_type   value_before;
                std::size_t       w_id_before;      // Important helpers for call_commit proving

                rw_operation(
                    rw_operation_type _op,
                    std::size_t       _id,
                    zkevm_word_type   _address,
                    std::uint8_t      _field,
                    zkevm_word_type    _storage_key,
                    std::size_t       _rw_counter,
                    bool              _is_write,
                    zkevm_word_type   _value,
                    zkevm_word_type   _value_before,
                    zkevm_word_type   _w_id_before,
                    std::size_t       _call_id,
                    zkevm_word_type   _initial_value,
                    zkevm_word_type   _initial_root,
                    zkevm_word_type   _root
                ): op(_op), id(_id), address(_address), field(_field),
                    storage_key(_storage_key), rw_counter(_rw_counter),
                    is_write(_is_write), value(_value), call_id(_call_id),
                    initial_value(_initial_value), initial_root(_initial_root),
                    root(_root), value_before(_value_before), w_id_before(_w_id_before)
                {}

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
                if(obj.op == rw_operation_type::call_context )                    os << "CALL_CONTEXT_OP     : ";
                if(obj.op == rw_operation_type::state )                           os << "STATE               : ";
                if(obj.op == rw_operation_type::transient_storage )               os << "TRANSIENT_STORAGE   : ";
                if(obj.op == rw_operation_type::access_list )                     os << "ACCESS_LIST         : ";
                if(obj.op == rw_operation_type::calldata )                        os << "CALLDATA            : ";
                if(obj.op == rw_operation_type::returndata )                      os << "RETURNDATA          : ";

                if(obj.op == rw_operation_type::padding )                         os << "PADDING             : ";

                os  << " id = " << obj.id
                    << " call_id = " << obj.call_id
                    << " rw_id = " << obj.rw_counter
                    << " addr = " << std::hex
                    << obj.address << std::dec;
                if( obj.op == rw_operation_type::state ||
                    obj.op == rw_operation_type::transient_storage ||
                    obj.op == rw_operation_type::access_list
                )   os << " storage_key = " << obj.storage_key;
                if( obj.op == rw_operation_type::call_context){
                    std::cout << " field = ";
                    if(obj.field == std::size_t(call_context_field::parent_id)) os << "parent_id";
                    if(obj.field == std::size_t(call_context_field::modified_items)) os << "modified_items";
                    if(obj.field == std::size_t(call_context_field::depth)) os << "depth";
                    if(obj.field == std::size_t(call_context_field::end)) os << "end";
                    if(obj.field == std::size_t(call_context_field::block_id)) os << "block_id";
                    if(obj.field == std::size_t(call_context_field::tx_id)) os << "tx_id";
                    if(obj.field == std::size_t(call_context_field::from)) os << "from";
                    if(obj.field == std::size_t(call_context_field::to)) os << "to";
                    if(obj.field == std::size_t(call_context_field::call_context_address)) os << "call_context_address";
                    if(obj.field == std::size_t(call_context_field::calldata_size)) os << "calldata_size";
                    if(obj.field == std::size_t(call_context_field::returndata_size)) os << "returndata_size";
                    if(obj.field == std::size_t(call_context_field::lastcall_id)) os << "lastcall_id";
                    if(obj.field == std::size_t(call_context_field::hash)) os << "hash";
                    if(obj.field == std::size_t(call_context_field::is_static)) os << "is_static";
                    if(obj.field == std::size_t(call_context_field::lastcall_returndata_length)) os << "lastcall_returndata_length";
                    if(obj.field == std::size_t(call_context_field::lastcall_returndata_offset)) os << "lastcall_returndata_offset";
                }
                if(obj.is_write) os << " W "; else os << " R ";
                os << "[" << std::hex << obj.initial_value << std::dec <<"] => ";
                os << "[" << std::hex << obj.value_before << std::dec <<"] => ";
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
                if( address >= 1024 ) std::cout << "address = " << std::hex << address  << std::dec << std::endl;
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

            rw_operation memory_rw_operation(
                std::size_t id,
                zkevm_word_type address,
                std::size_t rw_id,
                bool is_write,
                zkevm_word_type value
            ){
                rw_operation r;
                r.op = rw_operation_type::memory;
                r.id = id;
                r.address = address;
                r.rw_counter = rw_id;
                r.is_write = is_write;
                r.value = value;
                return r;
            }

            rw_operation calldata_rw_operation(
                std::size_t id,
                zkevm_word_type address,
                std::size_t rw_id,
                zkevm_word_type value
            ){
                rw_operation r;
                r.op = rw_operation_type::calldata;
                r.id = id;
                r.address = address;
                r.rw_counter = rw_id;
                r.is_write = false; // calldata is read-only
                r.value = value;
                return r;
            }

            rw_operation returndata_rw_operation(
                std::size_t id,
                zkevm_word_type address,
                std::size_t rw_id,
                zkevm_word_type value
            ){
                rw_operation r;
                r.op = rw_operation_type::returndata;
                r.id = id;
                r.address = address;
                r.rw_counter = rw_id;
                r.is_write = false; // returndata is read-only
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
                std::size_t     w_id_before,
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
                r.call_id = call_id;
                r.w_id_before = w_id_before;
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
                std::size_t     w_id_before,
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
                r.call_id = call_id;
                r.w_id_before = w_id_before;
                r.value_before = value_before;
                return r;
            }

            rw_operation access_list_rw_operation(
                std::size_t     tx_id,
                zkevm_word_type address,
                std::size_t     field_tag,
                zkevm_word_type storage_key,
                std::size_t     rw_id,
                bool            is_write,
                zkevm_word_type value,
                std::size_t     call_id,
                zkevm_word_type value_before,
                std::size_t     w_id_before
            ){
                rw_operation r;
                r.op = rw_operation_type::access_list;
                r.id = tx_id;
                r.address = address;
                r.field = field_tag;
                r.storage_key = storage_key;
                r.rw_counter = rw_id;
                r.is_write = is_write;
                r.value = value;
                r.call_id = call_id;
                r.value_before = value_before;
                r.w_id_before = w_id_before;
                return r;
            }

            // TODO: define flag correctly
            rw_operation account_code_hash_rw_operation(
                std::size_t block_id,
                std::size_t call_id,
                zkevm_word_type address,
                std::size_t rw_id,
                bool is_write,
                zkevm_word_type value,
                zkevm_word_type value_prev,
                zkevm_word_type root = zkevm_word_type(0)
            ){
                rw_operation r;
                r.op = rw_operation_type::state;
                r.op = rw_operation_type::state;
                r.id = block_id;
                r.address = address;
                r.storage_key = 0;
                r.field = 1;
                r.rw_counter = rw_id;
                r.is_write = is_write;
                r.value = value;
                r.initial_value = value_prev;
                r.call_id = call_id;
                return r;
            }

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

            rw_operation call_context_w_operation(
                std::size_t call_id,
                call_context_field field,
                std::size_t rw_counter,
                zkevm_word_type value
            ){
                BOOST_ASSERT(
                    field == call_context_field::lastcall_id
                    || field == call_context_field::lastcall_returndata_offset
                    || field == call_context_field::lastcall_returndata_length
                );
                rw_operation r;
                r.op = rw_operation_type::call_context;
                r.id = call_id;
                r.field = std::uint8_t(field);
                r.is_write = true;
                r.rw_counter = rw_counter;
                r.value = value;
                return r;
            }

            rw_operation call_context_r_operation(
                std::size_t call_id,
                call_context_field field,
                std::size_t rw_counter,
                zkevm_word_type value
            ){
                BOOST_ASSERT(
                    field == call_context_field::lastcall_id
                    || field == call_context_field::lastcall_returndata_offset
                    || field == call_context_field::lastcall_returndata_length
                );
                rw_operation r;
                r.op = rw_operation_type::call_context;
                r.id = call_id;
                r.field = std::uint8_t(field);
                r.is_write = false;
                r.rw_counter = rw_counter;
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
