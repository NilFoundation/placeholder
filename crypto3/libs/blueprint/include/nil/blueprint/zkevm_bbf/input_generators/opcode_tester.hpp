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
                    std::cout << "PC opcode map[" << bytecode.size() << "] = " << opcodes.size() << " opcode = " << opcode_to_string(opcode) << std::endl;
                    pc_opcode_map[bytecode.size()] = opcodes.size();
                    opcodes.push_back({opcode, word_from_byte_buffer(additional_input)});
                    bytecode.push_back(opcode_to_number(opcode));
                    bytecode.insert(bytecode.end(), additional_input.begin(), additional_input.end() );
                }

                const std::vector<std::uint8_t> &get_bytecode() const {
                    return bytecode;
                }
                const std::vector<std::pair<zkevm_opcode, zkevm_word_type>> &get_opcodes() const {
                    return opcodes;
                }

                const std::pair<zkevm_opcode, zkevm_word_type> &get_opcode_by_pc(std::size_t pc) const {
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
