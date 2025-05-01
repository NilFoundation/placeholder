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
#include <nil/blueprint/zkevm_bbf/types/rw_operation_type.hpp>
#include <nil/blueprint/zkevm_bbf/util/ptree.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            enum class block_context_field: std::uint8_t {
                // Grouped by call, no revertions
                number = 0
            };
            static constexpr std::size_t block_context_fields_amount = 1;
            static constexpr std::size_t tx_context_fields_amount = 0;

            struct short_rw_operation{
                rw_operation_type op = rw_operation_type::start;           // operation type
                std::size_t             id = 0;
                std::size_t             address = 0;
                std::size_t             rw_counter = 0;
                bool                    is_write = false;
                zkevm_word_type         value = 0;
                std::size_t             internal_counter = 0;

                bool operator< (const short_rw_operation &other) const {
                    if( op != other.op ) return op < other.op;                                      // 16 bits
                    if( id != other.id ) return id < other.id;                                      // 16 bits
                    if( address != other.address ) return address < other.address;                  // 160 bits
                    if( rw_counter != other.rw_counter) return rw_counter < other.rw_counter;       // 32 bits
                    return false;
                }
            };

            // For testing purposes
            std::ostream& operator<<(std::ostream& os, const short_rw_operation& obj){
                if(obj.op == rw_operation_type::start )                           os << "START         : ";
                if(obj.op == rw_operation_type::stack )                           os << "STACK         : ";
                if(obj.op == rw_operation_type::memory )                          os << "MEMORY        : ";
                if(obj.op == rw_operation_type::call_context )                    os << "CALL_CONTEXT  : ";
                if(obj.op == rw_operation_type::calldata )                        os << "CALLDATA      : ";
                if(obj.op == rw_operation_type::returndata )                      os << "RETURNDATA    : ";
                if(obj.op == rw_operation_type::blobhash )                        os << "BLOBHASH      : ";
                if(obj.op == rw_operation_type::padding )                         os << "PADDING       : ";

                os  << " id = " << obj.id
                    << " rw_id = " << obj.rw_counter
                    << " addr = " << obj.address << std::dec;

                if(obj.is_write) os << " W "; else os << " R ";
                os << "[" << std::hex << obj.value << std::dec <<"]";
                return os;
            }

            short_rw_operation stack_rw_operation(
                std::size_t id,
                uint16_t address,
                std::size_t rw_id,
                bool is_write,
                zkevm_word_type value
            ){
                BOOST_ASSERT(id < ( 1 << 28)); // Maximum calls amount(?)
                if( address >= 1024 ) std::cout << "address = " << std::hex << address  << std::dec << std::endl;
                BOOST_ASSERT(address < 1024);

                short_rw_operation r;
                r.op = rw_operation_type::stack;
                r.id = id;
                r.address = address;
                r.rw_counter = rw_id;
                r.is_write = is_write;
                r.value = value;

                return r;
            }

            short_rw_operation memory_rw_operation(
                std::size_t id,
                std::size_t address,
                std::size_t rw_id,
                bool is_write,
                zkevm_word_type value
            ){
                short_rw_operation r;
                r.op = rw_operation_type::memory;
                r.id = id;
                r.address = address;
                r.rw_counter = rw_id;
                r.is_write = is_write;
                r.value = value;
                return r;
            }

            short_rw_operation calldata_rw_operation(
                std::size_t id,
                std::size_t address,
                std::size_t rw_id,
                bool is_write,
                zkevm_word_type value
            ){
                short_rw_operation r;
                r.op = rw_operation_type::calldata;
                r.id = id;
                r.address = address;
                r.rw_counter = rw_id;
                r.is_write = is_write; // Only first operation may be write
                r.value = value;
                return r;
            }

            short_rw_operation returndata_rw_operation(
                std::size_t id,
                std::size_t address,
                std::size_t rw_id,
                bool is_write,
                zkevm_word_type value
            ){
                short_rw_operation r;
                r.op = rw_operation_type::returndata;
                r.id = id;
                r.address = address;
                r.rw_counter = rw_id;
                r.is_write = is_write; // Only first operation may be write
                r.value = value;
                return r;
            }

            short_rw_operation call_context_header_operation(
                std::size_t call_id,
                call_context_field field,
                zkevm_word_type value
            ){
                short_rw_operation r;
                r.op = rw_operation_type::call_context;
                r.id = call_id;
                r.address = std::uint8_t(field);
                r.rw_counter = call_id + std::uint8_t(field);
                r.value = value;
                return r;
            }

            short_rw_operation call_context_w_operation(
                std::size_t call_id,
                call_context_field field,
                std::size_t rw_counter,
                zkevm_word_type value
            ){
                BOOST_ASSERT(
                    field == call_context_field::lastcall_id
                    || field == call_context_field::lastcall_returndata_offset
                    || field == call_context_field::lastcall_returndata_length
                    || field == call_context_field::call_status
                );
                short_rw_operation r;
                r.op = rw_operation_type::call_context;
                r.id = call_id;
                r.address = std::uint8_t(field);
                r.is_write = true;
                r.rw_counter = rw_counter;
                r.value = value;
                return r;
            }

            short_rw_operation call_context_r_operation(
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
                short_rw_operation r;
                r.op = rw_operation_type::call_context;
                r.id = call_id;
                r.address = std::uint8_t(field);
                r.is_write = false;
                r.rw_counter = rw_counter;
                r.value = value;
                return r;
            }

            class short_rw_operations_vector: public std::vector<short_rw_operation>{
            public:
                short_rw_operations_vector(){
                    this->push_back(short_rw_operation());
                }
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil
