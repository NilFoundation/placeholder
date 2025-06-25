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
#include <nil/blueprint/zkevm_bbf/types/state_item_address.hpp>
#include <nil/blueprint/zkevm_bbf/types/short_rw_operation.hpp>
#include <nil/blueprint/zkevm_bbf/types/state_operation.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            enum class copy_operand_type {
                padding = 0,
                memory = 1,
                bytecode = 2,
                calldata = 3,
                log = 4,
                keccak = 5,
                returndata = 6
            };
            std::size_t copy_op_to_num(copy_operand_type copy_op){
                return std::size_t(copy_op);
            }
            std::string copy_op_to_string(copy_operand_type copy_op){
                switch (copy_op) {
                    case copy_operand_type::padding: return "padding";
                    case copy_operand_type::memory: return "memory";
                    case copy_operand_type::bytecode: return "bytecode";
                    case copy_operand_type::calldata: return "calldata";
                    case copy_operand_type::log: return "log";
                    case copy_operand_type::keccak: return "keccak";
                    case copy_operand_type::returndata: return "returndata";
                    default: return "unknown";
                }
            }
            static constexpr std::size_t copy_operand_types_amount = 7;


            struct copied_data_item{
                rw_operation_type op;
                std::size_t context_id;
                zkevm_word_type address;
                std::size_t field_type;
                zkevm_word_type key;
                zkevm_word_type value;
            };

            struct copy_event{
                using zkevm_word_type = nil::blueprint::zkevm_word_type;

                copy_operand_type   source_type;
                zkevm_word_type     source_id;
                std::size_t         src_counter_1; // Before copy reading
                std::size_t         src_counter_2;
                copy_operand_type   destination_type;
                zkevm_word_type     destination_id;
                std::size_t         dst_counter_1; // Before copy writing
                std::size_t         dst_counter_2;
                std::size_t         length;

                std::size_t get_op(std::size_t i) const {
                    if( bytes.size() != 0 ) return std::size_t(rw_operation_type::memory);
                    BOOST_ASSERT(i < values.size());
                    return std::size_t(values[i].op);
                }

                zkevm_word_type get_address(std::size_t i) const {
                    if( bytes.size() != 0 ) return 0;
                    BOOST_ASSERT(i < values.size());
                    return values[i].address;
                }

                std::size_t get_field_type(std::size_t i) const {
                    if( bytes.size() != 0 ) return 0;
                    BOOST_ASSERT(i < values.size());
                    return std::size_t(values[i].field_type);
                }

                zkevm_word_type get_key(std::size_t i) const {
                    if( bytes.size() != 0 ) return 0;
                    BOOST_ASSERT(i < values.size());
                    return values[i].key;
                }

                const std::size_t get_context_id(std::size_t i) const{
                    if( bytes.size() != 0 ) return 0;
                    return values[i].context_id;
                }

                zkevm_word_type get_value(std::size_t i) const {
                    BOOST_ASSERT( bytes.size() == 0 || values.size() == 0);
                    if( bytes.size() != 0 ) {
                        BOOST_ASSERT(i < bytes.size());
                        return bytes[i];
                    }
                    BOOST_ASSERT(i < values.size());
                    return values[i].value;
                }

                const std::vector<std::uint8_t> &get_bytes() const{
                    return bytes;
                }

                void push_byte(std::uint8_t byte) {
                    bytes.push_back(byte);
                }

                void push_data(copied_data_item data){
                    values.push_back(data);
                }

                std::size_t size() const {
                    return bytes.size() == 0 ? values.size() : bytes.size();
                }
            protected:
                std::vector<std::uint8_t> bytes;
                std::vector<copied_data_item> values;
            };

            copy_event keccak_copy_event(
                std::size_t call_id,
                std::size_t offset,
                std::size_t rw_counter,
                zkevm_word_type hash_value,
                std::size_t length
            ){
                copy_event cpy;
                cpy.source_type = copy_operand_type::memory;
                cpy.source_id = call_id;
                cpy.src_counter_1 = offset;
                cpy.src_counter_2 = rw_counter;
                cpy.destination_type = copy_operand_type::keccak;
                cpy.destination_id = hash_value;
                cpy.dst_counter_1 = 0;
                cpy.dst_counter_2 = 0;
                cpy.length = length;
                return cpy;
            }

            copy_event return_copy_event(
                std::size_t call_id,
                std::size_t offset,
                std::size_t rw_counter,
                std::size_t length
            ){
                copy_event cpy;
                cpy.source_type = copy_operand_type::memory;
                cpy.source_id = call_id;
                cpy.src_counter_1 = offset;
                cpy.src_counter_2 = rw_counter;
                cpy.destination_type = copy_operand_type::returndata;
                cpy.destination_id = call_id;
                cpy.dst_counter_1 = 0;
                cpy.dst_counter_2 = rw_counter + length;
                cpy.length = length;
                return cpy;
            }

            copy_event end_call_copy_event(
                std::size_t caller_id,
                std::size_t offset,
                std::size_t callee_id,
                std::size_t rw_counter,
                std::size_t length
            ){
                copy_event cpy;
                cpy.source_type = copy_operand_type::returndata;
                cpy.source_id = callee_id;
                cpy.src_counter_1 = 0;
                cpy.src_counter_2 = rw_counter;
                cpy.destination_type = copy_operand_type::memory;
                cpy.destination_id = caller_id;
                cpy.dst_counter_1 = offset;
                cpy.dst_counter_2 = rw_counter + length;
                cpy.length = length;
                return cpy;
            }

            copy_event calldatacopy_copy_event(
                std::size_t call_id,
                std::size_t src_address,
                std::size_t dst_address,
                std::size_t rw_counter,
                std::size_t length
            ){
                copy_event cpy;

                cpy.source_type = copy_operand_type::calldata;
                cpy.source_id = call_id;
                cpy.src_counter_1 = src_address; // Before copy reading
                cpy.src_counter_2 = rw_counter;
                cpy.destination_type = copy_operand_type::memory;
                cpy.destination_id = call_id;
                cpy.dst_counter_1 = dst_address; // Before copy writing
                cpy.dst_counter_2 = rw_counter + length;
                cpy.length = length;

                return cpy;
            }

            // May be used for all types of CALL-s
            copy_event call_copy_event(
                std::size_t caller_id,
                std::size_t callee_id,
                std::size_t args_offset,
                std::size_t args_length
            ){
                copy_event cpy;
                cpy.source_type = copy_operand_type::memory;
                cpy.source_id = caller_id;
                cpy.src_counter_1 = args_offset; // Before copy reading
                cpy.src_counter_2 = callee_id - args_length - 1;
                cpy.destination_type = copy_operand_type::calldata;
                cpy.destination_id = callee_id;
                cpy.dst_counter_1 = 0; // Before copy writing
                cpy.dst_counter_2 = callee_id + call_context_readonly_field_amount;
                cpy.length = args_length;
                return cpy;
            }

            copy_event returndatacopy_copy_event(
                std::size_t lastcall_id,
                std::size_t offset,
                std::size_t caller_id,
                std::size_t dest_offset,
                std::size_t rw_counter,
                std::size_t length
            ){
                copy_event cpy;
                cpy.source_type = copy_operand_type::returndata;
                cpy.source_id = lastcall_id;
                cpy.src_counter_1 = offset; // Before copy reading
                cpy.src_counter_2 = rw_counter;
                cpy.destination_type = copy_operand_type::memory;
                cpy.destination_id = caller_id;
                cpy.dst_counter_1 = dest_offset; // Before copy writing
                cpy.dst_counter_2 = rw_counter + length;
                cpy.length = length;
                return cpy;
            }

            copy_event memcpy_copy_event(){
                copy_event cpy;
                return cpy;
            }

            copy_event codecopy_copy_event(
                zkevm_word_type bytecode_hash,
                std::size_t src_offset,
                std::size_t call_id,
                std::size_t dst_offset,
                std::size_t rw_counter,
                std::size_t length
            ){
                copy_event cpy;
                cpy.source_type = copy_operand_type::bytecode;
                cpy.source_id = bytecode_hash;
                cpy.src_counter_1 = src_offset; // Before copy reading
                cpy.src_counter_2 = 0;
                cpy.destination_type = copy_operand_type::memory;
                cpy.destination_id = call_id;
                cpy.dst_counter_1 = dst_offset; // Before copy writing
                cpy.dst_counter_2 = rw_counter;
                cpy.length = length;
                return cpy;
            }
        } // namespace bbf
    } // namespace blueprint
} // namespace nil