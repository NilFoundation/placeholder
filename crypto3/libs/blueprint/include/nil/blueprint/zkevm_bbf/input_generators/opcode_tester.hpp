//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#include <nil/blueprint/zkevm_bbf/opcodes/zkevm_opcodes.hpp>
#include <nil/blueprint/utils/satisfiability_check.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {

            // This is a class that bytecodes as a sequence of bytes.
            // It emulates contract if we don't want to compile contract from the solidity code e t.c.
            class zkevm_opcode_tester{
            public:
                zkevm_opcode_tester(){}
                void push_opcode(const zkevm_opcode opcode, const std::vector<std::uint8_t> &additional_input = {}){
                    //std::cout << "PC opcode map[" << bytecode.size() << "] = " << opcodes.size() << " opcode = " << opcode_to_string(opcode) << std::endl;
                    std::uint8_t opcode_number = opcode_to_number(opcode);
                    bool is_push = (opcode_number >= 0x60) && (opcode_number <= 0x7f);

                    pc_opcode_map[bytecode.size()] = opcodes.size();
                    opcodes.push_back({opcode, word_from_byte_buffer(additional_input)});
                    bytecode.push_back(opcode_number);
                    if( is_push) {
                        std::uint8_t x = opcode_number - 0x5f;
                        for( std::size_t i = 0; i < x - additional_input.size(); i++){
                            bytecode.push_back(0);
                        }
                        bytecode.insert(bytecode.end(), additional_input.begin(), additional_input.end() );
                        BOOST_ASSERT(additional_input.size() <= x);
                    } else {
                        if( additional_input.size() != 0)
                            std::cout << "WRONG opcode input " << opcode
                                << " " << std::hex << std::size_t(opcode_number) << std::dec
                                << " additional input size = " << additional_input.size()
                                << std::endl;
                        BOOST_ASSERT(additional_input.size() == 0);
                    }
                }

                void push_opcode(const zkevm_opcode opcode, zkevm_word_type additional_input){
                    std::cout << "PC opcode map[" << bytecode.size() << "] = " << opcodes.size() << " opcode = " << opcode_to_string(opcode) << std::endl;
                    std::uint8_t opcode_number = opcode_to_number(opcode);
                    std::uint8_t x = 0;
                    bool is_push = (opcode_number >= 0x60) && (opcode_number <= 0x7f);
                    auto bytes = w_to_8(additional_input);

                    pc_opcode_map[bytecode.size()] = opcodes.size();
                    opcodes.push_back({opcode, additional_input});
                    bytecode.push_back(opcode_number);
                    if( is_push) {
                        x = opcode_number - 0x5f;
                    }
                    for( std::size_t i = 0; i < 32 - x; i++){
                        BOOST_ASSERT(bytes[i] == 0);
                    }
                    for( std::size_t i = 32 - x; i < 32; i++){
                        bytecode.push_back(bytes[i]);
                    }
                }

                const std::vector<std::uint8_t> &get_bytecode() const {
                    return bytecode;
                }
                const std::vector<std::pair<zkevm_opcode, zkevm_word_type>> &get_opcodes() const {
                    return opcodes;
                }

                const std::pair<zkevm_opcode, zkevm_word_type> &get_opcode_by_pc(std::size_t pc) const {
                    BOOST_ASSERT(pc_opcode_map.find(pc) != pc_opcode_map.end());
                    return opcodes[pc_opcode_map.at(pc)];
                }

            private:
                zkevm_word_type word_from_byte_buffer(const std::vector<uint8_t> &bytes){
                    zkevm_word_type result;
                    for( std::size_t i = 0; i < bytes.size(); i++){
                        result *= 0x100;
                        result += bytes[i];
                    }
                    return result;
                }
                std::vector<std::uint8_t> bytecode;
                std::vector<std::pair<zkevm_opcode, zkevm_word_type>> opcodes;
                std::map<std::size_t, std::size_t> pc_opcode_map;
            };
        } // namespace bbf
    }   // namespace blueprint
}    // namespace nil
