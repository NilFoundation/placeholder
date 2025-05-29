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

#include <nil/blueprint/zkevm_bbf/types/zkevm_word.hpp>
#include <nil/blueprint/zkevm_bbf/types/rw_operation_type.hpp>
#include <nil/blueprint/zkevm_bbf/util/ptree.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            struct state_operation{
                state_operation(){};
                rw_operation_type       op = rw_operation_type::start;           // operation type
                bool                    is_original = true;
                std::size_t             id = 0;
                zkevm_word_type         address = 0;                                  // account_address (160 bits)
                std::uint8_t            field = 0;
                zkevm_word_type         storage_key = 0;
                std::size_t             rw_counter = 0;
                bool                    is_write = false;

                zkevm_word_type         initial_value = 0;
                zkevm_word_type         call_initial_value = 0;
                zkevm_word_type         previous_value = 0;
                zkevm_word_type         value = 0;
                std::size_t             parent_id = 0;
                std::size_t             grandparent_id = 0;
                std::size_t             call_id = 0;
                std::size_t             internal_counter = 0;
                //zkevm_word_type         initial_root = 0;    // uncomment when MPT will be supported
                //zkevm_word_type         root = 0;

                bool operator< (const state_operation &other) const {
                    if( id != other.id ) return id < other.id;                                      // 16 bits
                    if( op != other.op ) return op < other.op;                                      // 16 bits
                    if( address != other.address ) return address < other.address;                  // 160 bits
                    if( field != other.field ) return field < other.field;                          // 16 bits
                    if( storage_key != other.storage_key ) return storage_key < other.storage_key;  // 256 bits
                    if( rw_counter != other.rw_counter) return rw_counter < other.rw_counter;       // 32 bits
                    return false;
                }
            };

            std::ostream& operator<<(std::ostream& os, const state_operation& obj){
                if(obj.op == rw_operation_type::start )                           os << "START       : ";
                if(obj.op == rw_operation_type::state )                           os << "STATE       : ";
                if(obj.op == rw_operation_type::transient_storage )               os << "TRANSIENT   : ";
                if(obj.op == rw_operation_type::access_list )                     os << "ACCESS_LIST : ";
                if(obj.op == rw_operation_type::call_context )                    os << "CALL_CONTEXT: ";
                if(obj.op == rw_operation_type::padding )                         os << "PADDING     : ";

                os
                    << (obj.is_original? std::string("original   ") : std::string("call_commit"))
                    << " id = " << obj.grandparent_id << "=>" << obj.parent_id << "=>" << obj.id
                    << " call_id = " << obj.call_id
                    << " rw_id = " << obj.rw_counter
                    << " addr = " << std::hex
                    << obj.address << std::dec
                    << " storage_key = " << obj.storage_key;
                if(obj.is_write) os << " W "; else os << " R ";
                os << "[" << std::hex << obj.initial_value << std::dec <<"] => ";
                os << "[" << std::hex << obj.call_initial_value << std::dec <<"] => ";
                os << "[" << std::hex << obj.previous_value << std::dec <<"] => ";
                os << "[" << std::hex << obj.value << std::dec <<"]";
                return os;
            }

            class state_operations_vector: public std::vector<state_operation>{
            public:
                state_operations_vector(){
                    this->push_back(state_operation());
                }
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil
