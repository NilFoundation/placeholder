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
            struct zkevm_account{
                zkevm_word_type address;
                bool initialized;
                zkevm_word_type balance;
                zkevm_word_type currency_root;
                zkevm_word_type storage_root;
                zkevm_word_type code_hash;
                zkevm_word_type async_context_root;
                std::size_t     seq_no;
                std::size_t     ext_seq_no;
                std::size_t     request_id;

                std::map<zkevm_word_type, zkevm_word_type> storage; // Optional
                std::vector<std::uint8_t> bytecode;                 // Optional

                void set(std::size_t field_type, zkevm_word_type storage_key, zkevm_word_type value){
                    BOOST_ASSERT(field_type == 0);  // Other field types not implemented yet
                    storage[storage_key] = value;
                }

                virtual ~zkevm_account() {}
            };
            std::ostream &operator<<(std::ostream &os, const zkevm_account &obj){
                os << "\tAddress = 0x" << obj.address << std::dec << std::endl;
                os << "\tBalance = " << obj.balance << std::endl;
                os << "\tCurrency root = 0x" << std::hex << obj.currency_root << std::dec << std::endl;
                os << "\tStorage root = 0x" << std::hex << obj.storage_root << std::dec << std::endl;
                os << "\tCode hash = 0x" << std::hex << obj.code_hash << std::dec << std::endl;
                //os << "\tAsync context root = " << obj.async_context_root << std::endl;
                os << "\tSeq no = " << obj.seq_no << std::endl;
                os << "\tExt seq no = " << obj.ext_seq_no << std::endl;
                os << "\tRequest id = " << obj.request_id << std::endl;
                for( auto &[k,v]: obj.storage){
                    os << "\t\tStorage["
                     << k << "] = " << v << std::endl;
                }
                return os;
            }
        } // namespace bbf
    } // namespace blueprint
} // namespace nil
