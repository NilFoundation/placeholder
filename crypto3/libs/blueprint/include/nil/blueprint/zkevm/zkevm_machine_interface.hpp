//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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

#include <nil/blueprint/zkevm/stack.hpp>
#include <nil/blueprint/zkevm/zkevm_word.hpp>
#include "nil/crypto3/multiprecision/detail/big_uint/arithmetic.hpp"

namespace nil {
    namespace blueprint {
        // at the time I am writing this there is no interface to the zkevm machine
        // this is a placeholder

        // Hi! I added to this placeholder a bit more funtionality that shouldn't be in test assigner and in zkevm_state
        class zkevm_machine_interface {
        public:
            using word_type = zkevm_word_type;

            struct state_type{
                zkevm_opcode opcode;
                word_type   additional_input;
                zkevm_stack stack;
                std::vector<uint8_t> memory;
                std::vector<uint8_t> bytecode;
                std::size_t gas;
                std::size_t pc;

                bool tx_finish;
                zkevm_opcode error_opcode;

                state_type():tx_finish(false){}

                state_type(
                    std::vector<uint8_t> &_bytecode,
                    zkevm_opcode _opcode,
                    word_type    _additional_input,
                    zkevm_stack  _stack,
                    std::vector<uint8_t> &_memory,
                    std::size_t _gas,
                    std::size_t _pc
                ): opcode(_opcode), additional_input(_additional_input), stack(_stack), memory(_memory), gas(_gas), pc(_pc), tx_finish(false), bytecode(_bytecode)
                {
                    std::size_t i = 0;
                }

                zkevm_word_type stack_pop(){
                    if(stack.size() == 0 ){
                        tx_finish = true;
                        error_opcode = opcode;
                        opcode = zkevm_opcode::err0;
                        std::cout << "stack_pop error" << std::endl;
                        return 0;
                    }
                    return stack.pop();
                }

                void run_opcode() {
                    switch(opcode) {
                        case zkevm_opcode::PUSH0:
                            stack.push(0);
                            gas-=2;
                            pc++;
                            break;
                        case zkevm_opcode::PUSH1:
                            stack.push(additional_input);
                            gas-=3; pc+=2;
                            break;
                        case zkevm_opcode::PUSH2:
                            stack.push(additional_input);
                            gas-=3; pc+=3;
                            break;
                        case zkevm_opcode::PUSH3:
                            stack.push(additional_input);
                            gas-=3; pc+=4;
                            break;
                        case zkevm_opcode::PUSH4:
                            stack.push(additional_input);
                            gas-=3; pc+=5;
                            break;
                        case zkevm_opcode::PUSH5:
                            stack.push(additional_input);
                            gas-=3; pc+=6;
                            break;
                        case zkevm_opcode::PUSH6:
                            stack.push(additional_input);
                            gas-=3; pc+=7;
                            break;
                        case zkevm_opcode::PUSH7:
                            stack.push(additional_input);
                            gas-=3; pc+=8;
                            break;
                        case zkevm_opcode::PUSH8:
                            stack.push(additional_input);
                            gas-=3; pc+=9;
                            break;
                        case zkevm_opcode::PUSH9:
                            stack.push(additional_input);
                            gas-=3; pc+=10;
                            break;
                        case zkevm_opcode::PUSH10:
                            stack.push(additional_input);
                            gas-=3; pc+=11;
                            break;
                        case zkevm_opcode::PUSH11:
                            stack.push(additional_input);
                            gas-=3; pc+=12;
                            break;
                        case zkevm_opcode::PUSH12:
                            stack.push(additional_input);
                            gas-=3; pc+=13;
                            break;
                        case zkevm_opcode::PUSH13:
                            stack.push(additional_input);
                            gas-=3; pc+=14;
                            break;
                        case zkevm_opcode::PUSH14:
                            stack.push(additional_input);
                            gas-=3; pc+=15;
                            break;
                        case zkevm_opcode::PUSH15:
                            stack.push(additional_input);
                            gas-=3; pc+=16;
                            break;
                        case zkevm_opcode::PUSH16:
                            stack.push(additional_input);
                            gas-=3; pc+=17;
                            break;
                        case zkevm_opcode::PUSH17:
                            stack.push(additional_input);
                            gas-=3; pc+=18;
                            break;
                        case zkevm_opcode::PUSH18:
                            stack.push(additional_input);
                            gas-=3; pc+=19;
                            break;
                        case zkevm_opcode::PUSH19:
                            stack.push(additional_input);
                            gas-=3; pc+=20;
                            break;
                        case zkevm_opcode::PUSH20:
                            stack.push(additional_input);
                            gas-=3; pc+=21;
                            break;
                        case zkevm_opcode::PUSH21:
                            stack.push(additional_input);
                            gas-=3; pc+=22;
                            break;
                        case zkevm_opcode::PUSH22:
                            stack.push(additional_input);
                            gas-=3; pc+=23;
                            break;
                        case zkevm_opcode::PUSH23:
                            stack.push(additional_input);
                            gas-=3; pc+=24;
                            break;
                        case zkevm_opcode::PUSH24:
                            stack.push(additional_input);
                            gas-=3; pc+=25;
                            break;
                        case zkevm_opcode::PUSH25:
                            stack.push(additional_input);
                            gas-=3; pc+=26;
                            break;
                        case zkevm_opcode::PUSH26:
                            stack.push(additional_input);
                            gas-=3; pc+=27;
                            break;
                        case zkevm_opcode::PUSH27:
                            stack.push(additional_input);
                            gas-=3; pc+=28;
                            break;
                        case zkevm_opcode::PUSH28:
                            stack.push(additional_input);
                            gas-=3; pc+=29;
                            break;
                        case zkevm_opcode::PUSH29:
                            stack.push(additional_input);
                            gas-=3; pc+=30;
                            break;
                        case zkevm_opcode::PUSH30:
                            stack.push(additional_input);
                            gas-=3; pc+=31;
                            break;
                        case zkevm_opcode::PUSH31:
                            stack.push(additional_input);
                            gas-=3; pc+=32;
                            break;
                        case zkevm_opcode::PUSH32:
                            stack.push(additional_input);
                            gas-=3; pc+=33;
                            break;
                        case zkevm_opcode::RETURN:
                            stack_pop();
                            stack_pop();
                            pc++; gas -= 2;
                            tx_finish = true;
                            break;
                        case zkevm_opcode::NOT:{
                            word_type a = stack_pop();
                            word_type not_a =
                                word_type(
                                    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256) -
                                a;
                            stack.push(not_a);
                            pc++; gas -=  3;
                            break;
                        }
                        case zkevm_opcode::ADD:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            stack.push(add_wrapping(a, b));
                            pc++; gas -=  3;
                            break;
                        }
                        case zkevm_opcode::SUB:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            stack.push(subtract_wrapping(a, b));
                            pc++; gas -=  3;
                            break;
                        }
                        case zkevm_opcode::MUL:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            stack.push(multiply_wrapping(a, b));
                            pc++; gas -=  5;
                            break;
                        }
                        case zkevm_opcode::MULMOD:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            word_type N = stack_pop();
                            stack.push(
                                N ? word_type((nil::crypto3::multiprecision::big_uint<512>(a) * b) %
                                              N)
                                  : 0u);
                            pc++; gas -=  8;
                            break;
                        }
                        case zkevm_opcode::ADDMOD:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            word_type N = stack_pop();
                            stack.push(
                                N ? word_type((nil::crypto3::multiprecision::big_uint<257>(a) + b) %
                                              N)
                                  : 0u);
                            pc++; gas -=  8;
                            break;
                        }
                        case zkevm_opcode::ISZERO:{
                            word_type a = stack_pop();
                            stack.push(a? 1u : 0u);
                            pc++; gas -=  3;
                            break;
                        }
                        case zkevm_opcode::DIV:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            stack.push(std::get<0>(eth_div(a, b)));
                            pc++; gas -= 5;
                            break;
                        }
                        case zkevm_opcode::SDIV:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            stack.push(std::get<0>(eth_signed_div(a, b)));
                            pc++; gas -= 5;
                            break;
                        }
                        case zkevm_opcode::MOD:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            stack.push(std::get<1>(eth_div(a, b)));
                            pc++; gas -= 5;
                            break;
                        }
                        case zkevm_opcode::SMOD:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            stack.push(std::get<1>(eth_signed_div(a, b)));
                            pc++; gas -= 5;
                            break;
                        }
                        case zkevm_opcode::SIGNEXTEND:{
                            word_type b = stack_pop();
                            word_type x = stack_pop();
                            int len = (b < 32) ? int(b) + 1 : 32;
                            word_type sign = (x << (8 * (32 - len))) >> 255;
                            word_type result =
                                (subtract_wrapping(word_type(1) << 8 * (32 - len), 1)
                                 << 8 * len) *
                                    sign +
                                ((x << (8 * (32 - len))) >> (8 * (32 - len)));
                            stack.push(result);
                            pc++; gas -= 5;
                            break;
                        }
                        case zkevm_opcode::BYTE:{
                            word_type i = stack_pop();
                            word_type x = stack_pop();
                            int shift = (i < 32) ? int(i) : 32;
                            stack.push((x << (8 * shift)) >> (31 * 8));
                            pc++; gas -= 3;
                            break;
                        }
                        case zkevm_opcode::SHL:{
                            word_type a = stack_pop();
                            word_type input_b = stack_pop();
                            int shift = (input_b < 256) ? int(input_b) : 256;
                            stack.push(a << shift);
                            pc++; gas -= 3;
                            break;
                        }
                        case zkevm_opcode::SHR:{
                            word_type a = stack_pop();
                            word_type input_b = stack_pop();
                            int shift = (input_b < 256) ? int(input_b) : 256;
                            word_type r = a << shift;
                            // TODO(ioxid): fix
                            // word_type b = word_type(1) << shift;
                            stack.push(r);
                            pc++; gas -= 3;
                            break;
                        }
                        case zkevm_opcode::SAR:{
                            word_type input_a = stack_pop();
                            word_type input_b = stack_pop();
                            word_type a = abs_word(input_a);
                            int shift = (input_b < 256) ? int(input_b) : 256;
                            word_type r = a << shift;
                            word_type result =
                                is_negative(input_a) ? ((r == 0) ? neg_one : negate_word(r)) : r;
                            stack.push(result);
                            pc++; gas -= 3;
                            break;
                        }
                        case zkevm_opcode::AND:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            stack.push(a & b);
                            pc++; gas -= 3;
                            break;
                        }
                        case zkevm_opcode::OR:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            stack.push(a | b);
                            pc++; gas -= 3;
                            break;
                        }
                        case zkevm_opcode::XOR:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            stack.push(a ^ b);
                            pc++; gas -= 3;
                            break;
                        }
                        case zkevm_opcode::GT:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            stack.push(a > b);
                            pc++; gas -= 3;
                            break;
                        }
                        case zkevm_opcode::LT:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            stack.push(a < b);
                            pc++; gas -= 3;
                            break;
                        }
                        case zkevm_opcode::EQ:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            stack.push(a == b);
                            pc++; gas -= 3;
                            break;
                        }
                        case zkevm_opcode::SGT:{
                            word_type x = stack_pop();
                            word_type y = stack_pop();
                            bool result = (!is_negative(x) && is_negative(y));
                            result = result || (is_negative(x) && is_negative(y) && (abs_word(x) < abs_word(y)));
                            result = result || (!is_negative(x) && !is_negative(y) && (abs_word(x) > abs_word(y)));
                            stack.push(result);
                            pc++; gas -= 3;
                            break;
                        }
                        case zkevm_opcode::SLT:{
                            word_type x = stack_pop();
                            word_type y = stack_pop();
                            bool result = (is_negative(x) && !is_negative(y));
                            result = result || (is_negative(x) && is_negative(y) && (abs_word(x) > abs_word(y)));
                            result = result || (!is_negative(x) && !is_negative(y) && (abs_word(x) < abs_word(y)));
                            stack.push(result);
                            pc++; gas -= 3;
                            break;
                        }
                        case zkevm_opcode::JUMP:{
                            word_type addr = stack_pop();
                            //TODO: add JUMPDEST error processing
                            pc = w_to_16(addr)[15]; gas -= 8;
                            // 0x5B -- JUMPDEST opcode. TODO: do function opcode_to_value more convenient
                            if( pc > bytecode.size() || bytecode[pc] != 0x5B ) {
                                tx_finish = true;
                                error_opcode = opcode;
                                opcode = zkevm_opcode::err1;
                                std::cout << "bad jump destination error" << std::endl;
                            }
                            break;
                        }
                        case zkevm_opcode::JUMPI:{
                            word_type addr = stack_pop();
                            word_type state = stack_pop();
                            //TODO: add JUMPDEST error processing
                            pc = state? w_to_16(addr)[15]: pc+1; gas -= 10;
                            if( state && (pc > bytecode.size() || bytecode[pc] != 0x5B) ) {
                                tx_finish = true;
                                error_opcode = opcode;
                                opcode = zkevm_opcode::err1;
                                std::cout << "bad jump destination error" << std::endl;
                            }
                            break;
                        }
                        case zkevm_opcode::JUMPDEST:{
                            pc++; gas -= 1;
                            break;
                        }
                        case zkevm_opcode::err0:{
                            BOOST_ASSERT(false);
                            break;
                        }
                        case zkevm_opcode::err1:{
                            BOOST_ASSERT(false);
                            break;
                        }
                        default:
                            std::cout << "Test machine unknown opcode " << opcode_to_string(opcode) << std::endl;
                            BOOST_ASSERT_MSG(false, "Opcode is not implemented inside test machine");
                    }
                    if( stack.size() > 1024 ) {
                        tx_finish = true;
                        error_opcode = opcode;
                        opcode = zkevm_opcode::err0;
                        std::cout << "stack overflow error" << std::endl;
                    }
                }
            };

            zkevm_machine_interface(
                std::vector<uint8_t> _bytecode,
                word_type         _bytecode_hash,
                unsigned long int _init_gas
            ) : bytecode(_bytecode),bytecode_hash(_bytecode_hash), is_opcode(fill_is_opcode(_bytecode)) {
                current_state.bytecode = bytecode;
                current_state.gas = new_state.gas = _init_gas;
                current_state.pc = new_state.pc = 0;
            }

            // It is not a part of an interface. Real machine will really run here.
            // But we just read a trace from file and completely update our state.
            // This function is for work with trace
            void update_state(
                zkevm_opcode _opcode,
                std::vector<word_type> _stack,
                std::vector<uint8_t> _memory,
                std::size_t _gas,
                std::size_t _pc,
                word_type   _additional_input
            ){
                current_state = state_type(
                    bytecode,
                    _opcode,
                    _additional_input,
                    zkevm_stack(_stack),
                    _memory,
                    _gas,
                    _pc
                );
                new_state = current_state;
            }

            bool apply_opcode(
                zkevm_opcode _opcode,
                std::vector<std::uint8_t>  param = {}
            ){
                BOOST_ASSERT(!current_state.tx_finish);
                current_state = new_state;
                //std::cout << "Current state.pc = " << current_state.pc << " opcode = " << opcode_to_string(_opcode) << std::endl;
                current_state.bytecode = new_state.bytecode = bytecode;
                current_state.opcode = new_state.opcode = _opcode;
                current_state.additional_input = new_state.additional_input = zkevm_word_from_bytes(param);
                new_state.run_opcode();
                if( new_state.tx_finish ){
                    std::cout << "Final opcode = " << opcode_to_string(current_state.opcode) << std::endl;
                    current_state.tx_finish = true;
                    current_state.error_opcode = current_state.opcode;
                    current_state.opcode = new_state.opcode;
                }
                return current_state.tx_finish;
            }

            void padding_state(){
                current_state.opcode = zkevm_opcode::padding;
                current_state.stack = {};
                current_state.memory = {};
                current_state.gas = 0;
                current_state.pc = 0;
                bytecode_hash = 0;
            }

            const state_type &get_current_state() const {
                return current_state;
            }

            const zkevm_opcode &opcode() const {
                return current_state.opcode;
            }

            const zkevm_word_type &additional_input() const {
                return current_state.additional_input;
            }

            const std::size_t pc() const {
                return current_state.pc;
            }

            const std::size_t pc_next() const {
                return new_state.pc;
            }

            const std::size_t gas() const {
                return current_state.gas;
            }

/*          const std::vector<word_type> & stack() const {
                return current_state.stack;
            }*/

            const std::size_t stack_size() const {
                return current_state.stack.size();
            }

            const std::size_t memory_size() const {
                return current_state.memory.size();
            }

            const zkevm_word_type stack_top(std::size_t depth = 0) const{
                return current_state.stack.top(depth);
            }

            const std::vector<std::uint8_t> & memory() const {
                return current_state.memory;
            }

            const bool tx_finish() const {
                return current_state.tx_finish;
            }

            const zkevm_opcode error_opcode() const {
                return current_state.error_opcode;
            }

            const std::size_t bytecode_length() const {
                return bytecode.size();
            }

            const std::uint8_t bytecode_byte(std::size_t i) const {
                BOOST_ASSERT(i < bytecode.size());
                return bytecode[i];
            }

            const bool is_bytecode_byte_opcode(std::size_t i) const {
                BOOST_ASSERT(i < is_opcode.size());
                return is_opcode[i];
            }
            word_type         bytecode_hash;
        protected:
            std::vector<bool> fill_is_opcode(const std::vector<uint8_t> &_bytecode){
                std::vector<bool> result(_bytecode.size());
                auto it = result.begin();
                while(it != result.end() ){
                    *it = true;
                    if( _bytecode[it - result.begin()] > 0x5f &&  _bytecode[it - result.begin()] < 0x80 ){
                        std::size_t push_size = _bytecode[it - result.begin()] - 0x5f;
                        for( std::size_t i = 0; i < push_size; i++){
                            it++;
                            *it = false;
                        }
                    }
                    it++;
                }
                return result;
            }

        private:
            state_type        current_state;
            state_type        new_state;
            std::vector<uint8_t> bytecode;
            std::vector<bool>  is_opcode;
            bool opcode_added;
        };
    }
}
