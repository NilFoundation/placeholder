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
                call_context = 1,       // rw_256
                stack = 2,
                memory = 3,
                calldata = 4,           // rw_8
                returndata = 5,
                blobhash = 6,
                state_call_context = 7,
                access_list = 8,
                state = 9,               // Grouped by block, includes STORAGE and ACCOUNT operations
                transient_storage = 10,  // Grouped by transaction
                padding = 11
            };
            static constexpr std::size_t short_rw_operation_types_amount = 8;
            static constexpr std::size_t state_operation_types_amount = 6;

            std::string rw_operation_type_to_string(rw_operation_type op){
                switch (op) {
                case rw_operation_type::start:
                    return "START";
                case rw_operation_type::call_context:
                    return "CALL_CONTEXT";
                case rw_operation_type::stack:
                    return "STACK";
                case rw_operation_type::memory:
                    return "MEMORY";
                case rw_operation_type::calldata:
                    return "CALLDATA";
                case rw_operation_type::returndata:
                    return "RETURNDATA";
                case rw_operation_type::blobhash:
                    return "BLOBHASH";
                case rw_operation_type::state_call_context:
                    return "STATE_CALL_CONTEXT";
                case rw_operation_type::access_list:
                    return "ACCESS_LIST";
                case rw_operation_type::state:
                    return "STATE";
                case rw_operation_type::transient_storage:
                    return "TRANSIENT_STORAGE";
                default:
                    BOOST_ASSERT(false);
                return "UNKNOWN";
                }
            }

            enum class state_call_context_fields: std::uint8_t {
                parent_id = 0,
                is_reverted = 1,
                modified_items = 2,
                end_call_rw_id = 3
            };
            static constexpr std::size_t state_call_context_fields_amount = 4;

            enum class call_context_field: std::uint8_t {
                // Grouped by call, no revertions
                parent_id = 4,
                block_id = 5,
                tx_id = 6,
                call_context_value = 7,
                call_context_address = 8,
                calldata_size = 9,
                depth = 10,
                returndata_size = 11,
                call_status = 12,

                lastcall_id = 13,
                lastcall_returndata_offset = 14,
                lastcall_returndata_length = 15
            };
            static constexpr std::size_t call_context_readonly_field_amount = 13;
            static constexpr std::size_t call_context_fields_amount = 12;

        } // namespace bbf
    } // namespace blueprint
} // namespace nil
