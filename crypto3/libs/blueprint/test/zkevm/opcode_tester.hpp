//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#include <nil/blueprint/zkevm/zkevm_circuit.hpp>
#include <nil/blueprint/zkevm/zkevm_opcodes.hpp>
#include <nil/blueprint/zkevm/zkevm_operation.hpp>
#include <nil/blueprint/zkevm/zkevm_machine_interface.hpp>

#include <nil/blueprint/utils/satisfiability_check.hpp>

namespace nil {
    namespace blueprint {
        zkevm_machine_interface get_empty_machine(zkevm_word_type bytecode_hash = 0, unsigned long int init_gas = 65537) { // just some default value for initial gas
            return zkevm_machine_interface(bytecode_hash, init_gas);
        }

        std::vector<std::uint8_t> hex_string_to_bytes(std::string const &hex_string) {
            std::vector<std::uint8_t> bytes;
            if(hex_string[0] != '0' || hex_string[1] != 'x') return {};
            for (std::size_t i = 2; i < hex_string.size(); i += 2) {
                if( !std::isxdigit(hex_string[i]) ||  !std::isxdigit(hex_string[i+1]) ) return {};
                std::string byte_string = hex_string.substr(i, 2);
                bytes.push_back(std::stoi(byte_string, nullptr, 16));
            }
            return bytes;
        }

        // This is a class that bytecodes as a sequence of bytes.
        // It emulates contract if we don't want to compile contract from the solidity code e t.c.
        class zkevm_opcode_tester{
        public:
            zkevm_opcode_tester():opcodes_info_instance(opcodes_info::instance()){}
            // For PUSHx and errors only
            void push_opcode(const zkevm_opcode opcode, const zkevm_word_type &additional_word){
                auto additional_array = w_to_8(additional_word);
                std::vector<uint8_t> additional_input;
                switch( opcode ){
                    case zkevm_opcode::PUSH1:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 1, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH2:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*2) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 2, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH3:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*3) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 3, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH4:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*4) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 4, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH5:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*5) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 5, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH6:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*6) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 6, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH7:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*7) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 7, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH8:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*8) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 8, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH9:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*9 ) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 9, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH10:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*10) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 10, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH11:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*11) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 11, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH12:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*12) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 11, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH13:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*13) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 11, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH14:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*14) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 11, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH15:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*15) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 15, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH16:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*16) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 16, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH17:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*17) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 17, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH18:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*18) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 18, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH19:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*19) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 19, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH20:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*20) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 20, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH21:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*21) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 21, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH22:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*22) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 22, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH23:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*23) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 23, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH24:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*24) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 24, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH25:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*25) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 25, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH26:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*26) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 26, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH27:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*27) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 27, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH28:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*28) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 28, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH29:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*29) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 29, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH30:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*30) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 30, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH31:
                        BOOST_ASSERT(additional_word < (zkevm_word_type(1) << 8*31) - 1);
                        additional_input.insert(additional_input.end(), additional_array.end() - 31, additional_array.end());
                        break;
                    case zkevm_opcode::PUSH32:
                        additional_input.insert(additional_input.end(), additional_array.begin(), additional_array.end());
                        break;
                    default:
                        BOOST_ASSERT(false);
                }
                push_opcode(opcode, additional_input);
            }
            void push_opcode(const zkevm_opcode opcode, const std::vector<std::uint8_t> &additional_input = {}){
                opcodes.push_back({opcode, additional_input});
                bytecode.push_back(opcodes_info_instance.get_opcode_value(opcode));
                bytecode.insert(bytecode.end(), additional_input.begin(), additional_input.end() );
            }
            const std::vector<std::uint8_t> &get_bytecode() const {
                return bytecode;
            }
            const std::vector<std::pair<zkevm_opcode, std::vector<std::uint8_t>>> &get_opcodes() const {
                return opcodes;
            }
        private:
            opcodes_info              opcodes_info_instance;
            std::vector<std::uint8_t> bytecode;
            std::vector<std::pair<zkevm_opcode, std::vector<std::uint8_t>>> opcodes;
        };
    }   // namespace blueprint
}    // namespace nil
