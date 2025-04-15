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
            enum class state_operation_type: std::uint8_t {
                start = 0,              // May be reverted
                state = 1,              // Grouped by block, includes STORAGE and ACCOUNT operations
                transient_storage = 2,  // Grouped by transaction
                access_list = 3,
                padding = 4
            };
            static constexpr std::size_t state_operation_types_amount = 5;

            std::size_t full_rw_op_to_num(state_operation_type rw_op){
                return std::size_t(rw_op);
            }

            struct state_operation{
                state_operation(){};
                state_operation_type    op = state_operation_type::start;           // operation type
                std::size_t             id = 0;
                zkevm_word_type         address = 0;                                  // account_address (160 bits)
                std::uint8_t            field = 0;
                zkevm_word_type         storage_key = 0;
                std::size_t             rw_counter = 0;
                bool                    is_write = false;
                zkevm_word_type         value = 0;

                std::size_t             call_id = 0;
                zkevm_word_type         initial_value = 0;   // for stack, memory ,it’s zero, Storage item value before transaction for storage operation
                zkevm_word_type         initial_root = 0;    // used for state, OutMessages, InMessages
                zkevm_word_type         root = 0;            // used for state, OutMessages, InMessages
                zkevm_word_type         value_before = 0;
                std::size_t             w_id_before = 0;      // Important helpers for call_commit proving

                state_operation(
                    state_operation_type _op,
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

                bool operator< (const state_operation &other) const {
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
            std::ostream& operator<<(std::ostream& os, const state_operation& obj){
                if(obj.op == state_operation_type::start )                           os << "START               : ";
                if(obj.op == state_operation_type::state )                           os << "STATE               : ";
                if(obj.op == state_operation_type::transient_storage )               os << "TRANSIENT_STORAGE   : ";
                if(obj.op == state_operation_type::access_list )                     os << "ACCESS_LIST         : ";
                if(obj.op == state_operation_type::padding )                         os << "PADDING             : ";

                os  << " id = " << obj.id
                    << " call_id = " << obj.call_id
                    << " rw_id = " << obj.rw_counter
                    << " addr = " << std::hex
                    << obj.address << std::dec
                    << " storage_key = " << obj.storage_key;
                if(obj.is_write) os << " W "; else os << " R ";
                os << "[" << std::hex << obj.initial_value << std::dec <<"] => ";
                os << "[" << std::hex << obj.value_before << std::dec <<"] => ";
                os << "[" << std::hex << obj.value << std::dec <<"]";
                return os;
            }

            state_operation start_state_operation(){
                return state_operation();
            }

            state_operation storage_state_operation(
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
                state_operation r;
                r.op = state_operation_type::state;
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

            state_operation state_state_operation(
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
                state_operation r;
                r.op = state_operation_type::state;
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

            state_operation access_list_state_operation(
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
                state_operation r;
                r.op = state_operation_type::access_list;
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
            state_operation account_code_hash_state_operation(
                std::size_t block_id,
                std::size_t call_id,
                zkevm_word_type address,
                std::size_t rw_id,
                bool is_write,
                zkevm_word_type value,
                zkevm_word_type value_prev,
                zkevm_word_type root = zkevm_word_type(0)
            ){
                state_operation r;
                r.op = state_operation_type::state;
                r.op = state_operation_type::state;
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

            state_operation padding_operation(){
                state_operation r;
                r.op = state_operation_type::padding;
                return r;
            }

            class state_operations_vector: public std::vector<state_operation>{
            public:
                state_operations_vector(){
                    this->push_back(start_state_operation());
                }
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil
