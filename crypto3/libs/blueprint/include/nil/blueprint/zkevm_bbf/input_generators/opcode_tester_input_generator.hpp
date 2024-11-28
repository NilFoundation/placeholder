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
#include <boost/property_tree/ptree.hpp>

#include <nil/blueprint/components/hashes/keccak/util.hpp> //Move needed utils to bbf
#include <nil/blueprint/bbf/generic.hpp>

#include <nil/blueprint/zkevm/zkevm_word.hpp>

#include <nil/blueprint/zkevm_bbf/types/hashed_buffers.hpp>
#include <nil/blueprint/zkevm_bbf/types/rw_operation.hpp>
#include <nil/blueprint/zkevm_bbf/types/copy_event.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_state.hpp>

#include <nil/blueprint/zkevm_bbf/types/zkevm_input_generator.hpp>
#include <nil/blueprint/zkevm_bbf/opcodes/zkevm_opcodes.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            class zkevm_opcode_tester_input_generator:zkevm_abstract_input_generator{
            public:
                zkevm_opcode_tester_input_generator(
                    const zkevm_opcode_tester &tester
                ): rw_counter(1), transactions_amount(0){
                    // It may be done for multiple transactions;
                    _rw_operations.push_back(start_rw_operation());
                    apply_tester(tester);
                }

                using integral_type = boost::multiprecision::number<boost::multiprecision::backends::cpp_int_modular_backend<257>>;
                using extended_integral_type = boost::multiprecision::number<boost::multiprecision::backends::cpp_int_modular_backend<512>>;

                void apply_tester(const zkevm_opcode_tester &tester, std::size_t initial_gas = 30000000){
                    transactions_amount++;
                    _keccaks.new_buffer(tester.get_bytecode());
                    std::size_t current_buffer_id = _bytecodes.new_buffer(tester.get_bytecode());

                    std::size_t call_id = transactions_amount - 1;
                    std::size_t pc = 0;
                    std::size_t gas = initial_gas;
                    std::vector<zkevm_word_type> stack;
                    zkevm_word_type bytecode_hash = _bytecodes.get_data()[current_buffer_id].second;
                    const std::map<std::size_t, std::uint8_t> memory;
                    const std::map<zkevm_word_type, zkevm_word_type> storage;

                    while(true){
                        auto [opcode,additional_input] = tester.get_opcode_by_pc(pc);

                        zkevm_state state;              // TODO:optimize
                        state.tx_hash = 0;              // * change it
                        state.opcode = opcode_to_number(opcode);
                        state.call_id = call_id;
                        state.gas = gas;
                        state.pc = pc;
                        state.rw_counter = rw_counter;
                        state.bytecode_hash = _bytecodes.get_data()[current_buffer_id].second;
                        state.additional_input = additional_input;
                        //state.tx_finish = (ind == tester.get_opcodes().size() - 1);
                        state.stack_size = stack.size();
                        state.memory_size = memory.size();
                        state.stack_slice = stack;
                        state.memory_slice = memory;
                        state.storage_slice = storage;
                        _zkevm_states.push_back(state);

                        if(opcode == zkevm_opcode::STOP){
                            break;
                        } else if (opcode == zkevm_opcode::ADD){
                            // 0x01
                            zkevm_word_type a = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, a));
                            zkevm_word_type b = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, b));
                            zkevm_word_type result = (a + b);
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            pc++;
                            gas -= 3;
                        } else if (opcode == zkevm_opcode::MUL){
                            // 0x02
                            zkevm_word_type a = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, a));
                            zkevm_word_type b = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, b));
                            zkevm_word_type result = (a * b);
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            pc++;
                            gas -= 3;
                        } else if (opcode == zkevm_opcode::SUB){
                            // 0x03
                            zkevm_word_type a = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, a));
                            zkevm_word_type b = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, b));
                            zkevm_word_type result = (a - b);
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            pc++;
                            gas -= 3;
                        } else if (opcode == zkevm_opcode::DIV){
                            // 0x04
                            zkevm_word_type a = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, a));
                            zkevm_word_type b = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, b));
                            integral_type r_integral = b != 0u ? integral_type(a) / integral_type(b) : 0u;
                            zkevm_word_type result = zkevm_word_type::backend_type(r_integral.backend());
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            pc++;
                            gas -= 5;
                        } else if (opcode == zkevm_opcode::SDIV){
                            // 0x05
                            zkevm_word_type a = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, a));
                            zkevm_word_type b_input = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, b_input));
                            auto is_negative = [](zkevm_word_type x) {
                                return (integral_type(x) > zkevm_modulus / 2 - 1);
                            };
                            auto negate_word = [](zkevm_word_type x) {
                                return zkevm_word_type(zkevm_modulus - integral_type(x));
                            };
                            auto abs_word = [&is_negative, &negate_word](zkevm_word_type x) {
                                return is_negative(x) ? negate_word(x) : x;
                            };
                            bool overflow = (integral_type(a) == zkevm_modulus - 1) && (integral_type(b_input) == zkevm_modulus / 2);
                            zkevm_word_type b = overflow ? 1 : b_input;
                            zkevm_word_type a_abs = abs_word(a), b_abs = abs_word(b);
                            integral_type r_integral =(b != 0u) ? integral_type(a_abs) / integral_type(b_abs) : 0u;
                            zkevm_word_type r_abs = zkevm_word_type::backend_type(r_integral.backend()),
                                            result = (is_negative(a) == is_negative(b)) ? r_abs: negate_word(r_abs);
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            pc++;
                            gas -= 5;
                        } else if (opcode == zkevm_opcode::MOD){
                            // 0x06
                            zkevm_word_type a = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, a));
                            zkevm_word_type b = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, b));
                            integral_type r_integral = b != 0u ? integral_type(a) / integral_type(b) : 0u;
                            zkevm_word_type r = zkevm_word_type::backend_type(r_integral.backend());
                            zkevm_word_type q = b != 0u ? a % b : a;
                            zkevm_word_type result = b != 0u ? q : 0; // according to EVM spec a % 0 = 0
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            pc++;
                            gas -= 5;
                        } else if (opcode == zkevm_opcode::SMOD){
                            // 0x07
                            zkevm_word_type a = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, a));
                            zkevm_word_type b_input = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, b_input));
                            auto is_negative = [](zkevm_word_type x) {
                                return (integral_type(x) > zkevm_modulus / 2 - 1);
                            };
                            auto negate_word = [](zkevm_word_type x) {
                                return zkevm_word_type(zkevm_modulus - integral_type(x));
                            };
                            auto abs_word = [&is_negative, &negate_word](zkevm_word_type x) {
                                return is_negative(x) ? negate_word(x) : x;
                            };
                            bool overflow = (integral_type(a) == zkevm_modulus - 1) && (integral_type(b_input) == zkevm_modulus / 2);
                            zkevm_word_type b = overflow ? 1 : b_input;
                            zkevm_word_type a_abs = abs_word(a), b_abs = abs_word(b);
                            integral_type r_integral =(b != 0u) ? integral_type(a_abs) / integral_type(b_abs) : 0u;
                            zkevm_word_type r_abs = zkevm_word_type::backend_type(r_integral.backend()),
                                q_abs = b != 0u ? a_abs % b_abs : a_abs,
                                r = (is_negative(a) == is_negative(b)) ? r_abs: negate_word(r_abs),
                                q = is_negative(a) ? negate_word(q_abs) : q_abs;
                            zkevm_word_type result = b != 0u ? q : 0;  // according to EVM spec a % 0 = 0
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            pc++;
                            gas -= 5;
                        } else if(opcode == zkevm_opcode::ADDMOD) {
                            // 0x08
                            zkevm_word_type a = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, a));
                            zkevm_word_type b = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, b));
                            zkevm_word_type modulus = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, modulus));
                            // This is how the result is calculated inside the circuit
                            // It is suppose to avoid overflow of the type zkevm_word_type
                            integral_type s_integral = integral_type(a) + integral_type(b);
                            integral_type r_integral = modulus != 0u ? s_integral / integral_type(modulus) : 0u;
                            zkevm_word_type q = zkevm_word_type(s_integral - r_integral * integral_type(modulus));
                            zkevm_word_type result = modulus != 0u ? q : 0;
                            //zkevm_word_type result = integral_type(modulus) == 0? 0 :(a + b) % modulus;
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            pc++;
                            gas -= 8;
                        } else if(opcode == zkevm_opcode::MULMOD) {
                            // 0x09
                            zkevm_word_type a = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, a));
                            zkevm_word_type b = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, b));
                            zkevm_word_type modulus = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, modulus));
                            a = modulus != 0u ? a : 0;
                            extended_integral_type s_integral = extended_integral_type(integral_type(a)) * extended_integral_type(integral_type(b));
                            zkevm_word_type sp = zkevm_word_type(s_integral % extended_integral_type(zkevm_modulus));
                            zkevm_word_type spp = zkevm_word_type(s_integral / extended_integral_type(zkevm_modulus));
                            extended_integral_type r_integral = modulus != 0u ? s_integral / extended_integral_type(integral_type(modulus)): 0u;
                            zkevm_word_type rp = zkevm_word_type(r_integral % extended_integral_type(zkevm_modulus));
                            zkevm_word_type rpp = zkevm_word_type(r_integral / extended_integral_type(zkevm_modulus));
                            zkevm_word_type result = modulus != 0u ? zkevm_word_type(s_integral % extended_integral_type(integral_type(modulus))): 0u;
                            //zkevm_word_type result = integral_type(modulus) == 0? 0 : (a * b) % modulus;
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            pc++;
                            gas -= 8;
                        } else if (opcode == zkevm_opcode::LT){
                            // 0x10
                            zkevm_word_type a = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, a));
                            zkevm_word_type b = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, b));
                            zkevm_word_type result = a < b;
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            pc++;
                            gas -= 3;
                        } else if (opcode == zkevm_opcode::GT){
                            // 0x11
                            zkevm_word_type a = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, a));
                            zkevm_word_type b = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, b));
                            zkevm_word_type result = a > b;
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            pc++;
                            gas -= 3;
                        } else if (opcode == zkevm_opcode::SLT){
                            // 0x12
                            zkevm_word_type a = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, a));
                            zkevm_word_type b = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, b));
                            zkevm_word_type result;
                            if( is_negative(a) && !is_negative(b) ){
                                result = 1;
                            } else if( is_negative(a) && is_negative(b) ){
                                result = a > b;
                            } else if( !is_negative(a) && !is_negative(b) ){
                                result = a < b;
                            }
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            pc++;
                            gas -= 3;
                        } else if (opcode == zkevm_opcode::SGT){
                            // 0x13
                            zkevm_word_type a = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, a));
                            zkevm_word_type b = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, b));
                            zkevm_word_type result;
                            if( !is_negative(a) && is_negative(b) ){
                                result = 1;
                            } else if( is_negative(a) && is_negative(b) ){
                                result = a < b;
                            } else if( !is_negative(a) && !is_negative(b) ){
                                result = a > b;
                            }
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            pc++;
                            gas -= 3;
                        } else if (opcode == zkevm_opcode::EQ){
                            // 0x14
                            zkevm_word_type a = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, a));
                            zkevm_word_type b = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, b));
                            zkevm_word_type result = (a == b);
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            pc++;
                            gas -= 3;
                        } else if (opcode == zkevm_opcode::ISZERO){
                            // 0x15
                            zkevm_word_type a = stack.back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, a));
                            stack.pop_back();
                            zkevm_word_type result = a == 0u? 1u: 0u;
                            stack.push_back(result);
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, true, result));
                            gas -= 3;
                            pc++;
                        } else if(opcode == zkevm_opcode::AND) {
                            // 0x16
                            zkevm_word_type a = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, a));
                            zkevm_word_type b = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, b));
                            zkevm_word_type result = a & b;
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            pc++;
                            gas -= 3;
                        } else if(opcode == zkevm_opcode::OR) {
                            // 0x17
                            zkevm_word_type a = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, a));
                            zkevm_word_type b = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, b));
                            zkevm_word_type result = a | b;
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            pc++;
                            gas -= 3;
                        } else if(opcode == zkevm_opcode::XOR) {
                            // 0x18
                            zkevm_word_type a = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, a));
                            zkevm_word_type b = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, b));
                            zkevm_word_type result = a ^ b;
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            pc++;
                            gas -= 3;
                        } else if(opcode == zkevm_opcode::NOT) {
                            // 0x19
                            zkevm_word_type a = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, a));
                            zkevm_word_type result = zkevm_word_type(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_cppui_modular257) - a;;
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            pc++;
                            gas -= 3;
                        } else if(opcode == zkevm_opcode::BYTE) {
                            // 0x1a
                            zkevm_word_type N = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, N));
                            zkevm_word_type a = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, a));
                            auto n = w_to_8(N)[31];
                            zkevm_word_type result = N > 31? 0: w_to_8(a)[n];
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            pc++;
                            gas -= 3;
                        }else if(opcode == zkevm_opcode::SHL) {
                            // 0x1b
                            zkevm_word_type b = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, b));
                            zkevm_word_type a = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, a));
                            int shift = (integral_type(b) < 256) ? int(integral_type(b)) : 256;
                            zkevm_word_type result = zkevm_word_type(integral_type(a) << shift);
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            pc++;
                            gas -= 3;
                        }else if(opcode == zkevm_opcode::SHR) {
                            // 0x1c
                            zkevm_word_type b = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, b));
                            zkevm_word_type a = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, a));
                            int shift = (integral_type(b) < 256) ? int(integral_type(b)) : 256;
                            integral_type r_integral = integral_type(a) >> shift;
                            zkevm_word_type result = zkevm_word_type::backend_type(r_integral.backend());
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            pc++;
                            gas -= 3;
                        }else if(opcode == zkevm_opcode::SAR) {
                            //0x1d
                            zkevm_word_type b = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, b));
                            zkevm_word_type input_a = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, input_a));
                            auto is_negative = [](zkevm_word_type x) {
                            return (integral_type(x) > zkevm_modulus / 2 - 1);};
                            auto negate_word = [](zkevm_word_type x) {
                            return zkevm_word_type(zkevm_modulus - integral_type(x));};
                            auto abs_word = [&is_negative, &negate_word](zkevm_word_type x) {
                            return is_negative(x) ? negate_word(x) : x;};
                            zkevm_word_type a = abs_word(input_a);
                            int shift = (integral_type(b) < 256) ? int(integral_type(b)) : 256;
                            integral_type r_integral = integral_type(a) >> shift;
                            zkevm_word_type result = is_negative(a) ? ((r_integral == 0)? zkevm_word_type(zkevm_modulus-1) : negate_word(zkevm_word_type(r_integral))) : zkevm_word_type(r_integral);
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            pc++;
                            gas -= 3;
                        } else if (opcode == zkevm_opcode::PUSH0){
                            // 0x5f
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 2;
                            pc++;
                        }  else  if(opcode == zkevm_opcode::PUSH1){
                            // 0x60
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc+=2;
                        } else if(opcode == zkevm_opcode::PUSH2){
                            // 0x61
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 3;
                        } else if(opcode == zkevm_opcode::PUSH3){
                            // 0x62
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 4;
                        } else if(opcode == zkevm_opcode::PUSH4){
                            // 0x63
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 5;
                        } else if(opcode == zkevm_opcode::PUSH5){
                            // 0x64
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 6;
                        } else if(opcode == zkevm_opcode::PUSH6){
                            // 0x65
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 7;
                        } else if(opcode == zkevm_opcode::PUSH7){
                            // 0x66
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 8;
                        } else if(opcode == zkevm_opcode::PUSH8){
                            // 0x67
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 9;
                        } else if(opcode == zkevm_opcode::PUSH9){
                            // 0x68
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 10;
                        } else if(opcode == zkevm_opcode::PUSH10){
                            // 0x69
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 11;
                        } else if(opcode == zkevm_opcode::PUSH11){
                            // 0x6a
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 12;
                        } else if(opcode == zkevm_opcode::PUSH12){
                            // 0x6b
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 13;
                        } else if(opcode == zkevm_opcode::PUSH13){
                            // 0x6c
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 14;
                        } else if(opcode == zkevm_opcode::PUSH14){
                            // 0x6d
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 15;
                        } else if(opcode == zkevm_opcode::PUSH15){
                            // 0x6e
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 16;
                        } else if(opcode == zkevm_opcode::PUSH16){
                            // 0x6f
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 17;
                        } else if(opcode == zkevm_opcode::PUSH17){
                            // 0x70
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 18;
                        } else if(opcode == zkevm_opcode::PUSH18){
                            // 0x71
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 19;
                        } else if(opcode == zkevm_opcode::PUSH19){
                            // 0x72
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 20;
                        } else if(opcode == zkevm_opcode::PUSH20){
                            // 0x73
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 21;
                        } else if(opcode == zkevm_opcode::PUSH21){
                            // 0x74
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 22;
                        } else if(opcode == zkevm_opcode::PUSH22){
                            // 0x75
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 23;
                        } else if(opcode == zkevm_opcode::PUSH23){
                            // 0x76
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 24;
                        } else if(opcode == zkevm_opcode::PUSH24){
                            // 0x77
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 25;
                        } else if(opcode == zkevm_opcode::PUSH25){
                            // 0x78
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 26;
                        } else if(opcode == zkevm_opcode::PUSH26){
                            // 0x79
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 27;
                        } else if(opcode == zkevm_opcode::PUSH27){
                            // 0x7a
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 28;
                        } else if(opcode == zkevm_opcode::PUSH28){
                            // 0x7b
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 29;
                        } else if(opcode == zkevm_opcode::PUSH29){
                            // 0x7c
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 30;
                        } else if(opcode == zkevm_opcode::PUSH30){
                            // 0x7d
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 31;
                        } else if(opcode == zkevm_opcode::PUSH31){
                            // 0x7e
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 32;
                        } else if(opcode == zkevm_opcode::PUSH32){
                            // 0x7f
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                            stack.push_back(additional_input);
                            gas -= 3;
                            pc += 33;
                        } else {
                            std::cout << "Opcode tester machine doesn't contain " << opcode << " implementation" << std::endl;
                            BOOST_ASSERT(false);
                        }
                    }

                    std::sort(_rw_operations.begin(), _rw_operations.end(), [](rw_operation a, rw_operation b){
                        return a < b;
                    });
                }
            public:
                virtual zkevm_keccak_buffers keccaks() override {return _keccaks;}
                virtual zkevm_keccak_buffers bytecodes() override { return _bytecodes;}
                virtual std::vector<rw_operation> rw_operations() override {return _rw_operations;}
                virtual std::vector<copy_event> copy_events() override { return _copy_events;}
                virtual std::vector<zkevm_state> zkevm_states() override{ return _zkevm_states;}
                virtual std::vector<std::pair<zkevm_word_type, zkevm_word_type>> exponentiations()override{return _exponentiations;}
            protected:
                std::size_t                                              transactions_amount;
                std::size_t                                              rw_counter;
                zkevm_keccak_buffers                                     _keccaks;
                zkevm_keccak_buffers                                     _bytecodes;
                std::vector<rw_operation>                                _rw_operations;
                std::vector<copy_event>                                  _copy_events;
                std::vector<zkevm_state>                                 _zkevm_states;
                std::vector<std::pair<zkevm_word_type, zkevm_word_type>> _exponentiations;
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil