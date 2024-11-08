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
            enum class copy_operand_type {
                padding, memory, bytecode, calldata, log, keccak, returndata
            };
            std::size_t copy_op_to_num(copy_operand_type copy_op){
                switch(copy_op){
                case copy_operand_type::padding:       return 0;
                case copy_operand_type::memory:        return 1;
                case copy_operand_type::bytecode:      return 2;
                case copy_operand_type::log:           return 3;
                case copy_operand_type::keccak:        return 4;
                case copy_operand_type::returndata:    return 5;
                case copy_operand_type::calldata:      return 6;
                }
                BOOST_ASSERT(false);
                return 0;
            }
            static constexpr std::size_t copy_operand_types_amount = 7;

            struct copy_event{
                using zkevm_word_type = nil::blueprint::zkevm_word_type;

                zkevm_word_type   source_id;
                copy_operand_type source_type;
                std::size_t       src_address;
                zkevm_word_type   destination_id;
                copy_operand_type destination_type;
                std::size_t       dst_address;
                std::size_t       length;
                std::size_t       initial_rw_counter;
                std::vector<std::uint8_t> bytes;
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil