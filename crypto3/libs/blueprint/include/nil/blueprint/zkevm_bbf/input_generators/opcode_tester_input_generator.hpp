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
                    apply_tester(tester);
                }

                using extended_integral_type = nil::crypto3::multiprecision::big_uint<512>;

                void apply_tester(const zkevm_opcode_tester &tester, std::size_t initial_gas = 30000000){
                    transactions_amount++;
                    _keccaks.new_buffer(tester.get_bytecode());
                    std::size_t current_buffer_id = _bytecodes.new_buffer(tester.get_bytecode());

                    std::size_t call_id = transactions_amount - 1;
                    std::size_t pc = 0;
                    std::size_t gas = initial_gas;
                    std::vector<zkevm_word_type> stack;
                    zkevm_word_type bytecode_hash = _bytecodes.get_data()[current_buffer_id].second;
                    std::map<std::size_t, std::uint8_t> memory;
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
                            zkevm_word_type result = wrapping_add(a, b);
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
                            zkevm_word_type result = wrapping_mul(a, b);
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            pc++;
                            gas -= 5;
                        } else if (opcode == zkevm_opcode::SUB){
                            // 0x03
                            zkevm_word_type a = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, a));
                            zkevm_word_type b = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, b));
                            zkevm_word_type result = wrapping_sub(a, b);
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
                            zkevm_word_type result = b != 0u ? a / b : 0u;
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
                            bool overflow = (a == neg_one) && (b_input == min_neg);
                            zkevm_word_type b = overflow ? 1 : b_input;
                            zkevm_word_type a_abs = abs_word(a), b_abs = abs_word(b);
                            zkevm_word_type r_abs = b != 0u ? a_abs / b_abs : 0u;
                            zkevm_word_type result =
                                (is_negative(a) == is_negative(b)) ? r_abs : negate_word(r_abs);
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
                            // word_type r = b != 0u ? a / b : 0u;
                            zkevm_word_type q = b != 0u ? a % b : a;
                            zkevm_word_type result =
                                b != 0u ? q : 0u;  // according to EVM spec a % 0 = 0
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
                            bool overflow = (a == neg_one) && (b_input == min_neg);
                            zkevm_word_type b = overflow ? 1 : b_input;
                            zkevm_word_type a_abs = abs_word(a), b_abs = abs_word(b);
                            zkevm_word_type r_abs = b != 0u ? a_abs / b_abs : 0u;
                            zkevm_word_type q_abs = b != 0u ? a_abs % b_abs : a_abs,
                                            r = (is_negative(a) == is_negative(b))
                                                    ? r_abs
                                                    : negate_word(r_abs),
                                            q = is_negative(a) ? negate_word(q_abs) : q_abs;
                            zkevm_word_type result =
                                b != 0u ? q : 0u;  // according to EVM spec a % 0 = 0
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
                            auto s_full = nil::crypto3::multiprecision::big_uint<257>(a) + b;
                            auto r_full = modulus != 0u ? s_full / modulus : 0u;
                            zkevm_word_type q = wrapping_sub(s_full, wrapping_mul(r_full, modulus)).truncate<256>();
                            zkevm_word_type result = modulus != 0u ? q : 0u;
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
                            extended_integral_type s_integral =
                                extended_integral_type(a) * extended_integral_type(b);
                            zkevm_word_type sp = zkevm_word_type(s_integral % extended_zkevm_mod);
                            zkevm_word_type spp = zkevm_word_type(s_integral / extended_zkevm_mod);
                            extended_integral_type r_integral =
                                modulus != 0u ? s_integral / extended_integral_type(modulus) : 0u;
                            zkevm_word_type rp = zkevm_word_type(r_integral % extended_zkevm_mod);
                            zkevm_word_type rpp = zkevm_word_type(r_integral / extended_zkevm_mod);
                            zkevm_word_type result =
                                modulus != 0u
                                    ? zkevm_word_type(s_integral % extended_integral_type(modulus))
                                    : 0u;
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            pc++;
                            gas -= 8;
                        } else if (opcode == zkevm_opcode::EXP){
                            // 0x0a
                            zkevm_word_type a = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, a));
                            zkevm_word_type d = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, d));
                            zkevm_word_type result = exp_by_squaring(a, d);
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            std::cout << "\tExponentiation: " << a << " ^ " << d << std::endl;
                            _exponentiations.push_back({a, d});
                            pc++;
                            gas -= 10 + 50 * count_significant_bytes(d);
                        } else if (opcode == zkevm_opcode::SIGNEXTEND){
                            // 0x0b
                            zkevm_word_type b = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, b));
                            zkevm_word_type x = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, x));
                            int len = (b < 32) ? int(b) + 1 : 32;
                            zkevm_word_type sign = (x << (8 * (32 - len))) >> 255;
                            zkevm_word_type result =
                                zkevm_word_type(
                                    (wrapping_sub(zkevm_word_type(1) << 8 * (32 - len), 1)
                                     << 8 * len) *
                                    sign) +
                                ((x << (8 * (32 - len))) >> (8 * (32 - len)));
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            pc++;
                            gas -= 5;
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
                            zkevm_word_type result =
                                zkevm_word_type(
                                    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256) -
                                a;
                            ;
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
                            int shift = (b < 256) ? int(b) : 256;
                            zkevm_word_type result = a << shift;
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
                            int shift = (b < 256) ? int(b) : 256;
                            zkevm_word_type result = a >> shift;
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
                            _rw_operations.push_back(stack_rw_operation(
                                call_id, stack.size(), rw_counter++, false, input_a));
                            zkevm_word_type a = abs_word(input_a);
                            int shift = (b < 256) ? int(b) : 256;
                            zkevm_word_type r = a >> shift;
                            zkevm_word_type result =
                                is_negative(a) ? ((r == 0) ? neg_one : negate_word(r)) : r;
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            pc++;
                            gas -= 3;
                        }else if(opcode == zkevm_opcode::CALLDATACOPY){
                            // 0x37
                            
                            auto destOffset = std::size_t(stack.back());
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, destOffset));

                            auto offset = std::size_t(stack.back());
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, offset));

                            auto length = std::size_t(stack.back());
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, length));

                            for( std::size_t i = 0; i < length; i++){
                                _rw_operations.push_back(memory_rw_operation(call_id, stack.size(), rw_counter++, true, 0)); // placeholder
                            }

                            std::size_t minimum_word_size = (length + 31) / 32;
                            std::size_t next_mem = std::max(destOffset + length, state.memory_size);
                            std::size_t memory_expansion = memory_expansion_cost(next_mem, state.memory_size);
                            std::size_t next_memory_size = (memory_size_word_util(next_mem))*32;

                            
                            //placeholder values to mimic memory expansion
                            for (std::size_t i = 0; i < next_memory_size; ++i) {
                                memory[i] = static_cast<std::uint8_t>(i);
                            }

                            gas-=3; //static gas
                            gas -= 3 * minimum_word_size + memory_expansion; //dynamic gas
                            pc++;
                        } else if(opcode == zkevm_opcode::MLOAD) {
                            // 0x51

                            zkevm_word_type addr = stack.back();
                            stack.pop_back();
                            BOOST_ASSERT_MSG(addr < 65536, "Cannot process so large memory address"); // for bigger memory operations use hardhat input generator
                            std::size_t addr1 = w_to_16(addr)[15];
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, addr));
                            for( std::size_t i = 0; i < 32; i++){
                                _rw_operations.push_back(memory_rw_operation(call_id, addr1+i, rw_counter++, false, addr1+i < memory.size() ? memory[addr1+i]: 0));
                            }
                            
                            std::size_t memory_size_word = (memory.size() + 31) / 32;
                            std::size_t last_memory_cost = memory_size_word * memory_size_word / 512 + (3*memory_size_word);

                            std::size_t tmp = addr1 + 32; 
                            tmp = 32*((tmp + 31) / 32);
                            for( std::size_t i = memory.size(); i < tmp; i++){
                                memory[i] = 0;
                            }

                            memory_size_word = (memory.size() + 31) / 32;
                            std::size_t new_memory_cost = memory_size_word * memory_size_word / 512 + (3*memory_size_word);
                            std::size_t memory_expansion = new_memory_cost - last_memory_cost;

                            std::vector<std::uint8_t> byte;
                            for( std::size_t i = addr1; i < addr1 + 32; i++){
                                byte.push_back(memory[i]);
                            }
                            zkevm_word_type result = zkevm_word_from_bytes(byte);
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                            stack.push_back(result);
                            pc++;
                            gas -= 3 + memory_expansion;
                        } else if(opcode == zkevm_opcode::MSTORE) {
                            // 0x52
                            zkevm_word_type addr = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, addr));

                            zkevm_word_type data = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, data));

                            auto bytes = w_to_8(data);
                            auto addr1 = w_to_16(addr)[15];

                            std::size_t memory_size_word = (memory.size() + 31) / 32;
                            std::size_t last_memory_cost = memory_size_word * memory_size_word / 512 + (3*memory_size_word);

                            
                            for(std::size_t i = memory.size(); i < addr1; i++){
                                memory[i] = 0;
                            }
                            for(std::size_t i = 0; i < 32; i++){
                                memory[addr1 + i] = bytes[i];
                                _rw_operations.push_back(memory_rw_operation(call_id, addr1+i, rw_counter++, true, bytes[i]));
                            }
                            addr1+= 32;
                            while(addr1 % 32 != 0){
                                memory[addr1] = 0;
                                addr1++;
                            }

                            memory_size_word = (memory.size() + 31) / 32;
                            std::size_t new_memory_cost = memory_size_word * memory_size_word / 512 + (3*memory_size_word);
                            std::size_t memory_expansion = new_memory_cost - last_memory_cost;

                            gas -= 3 + memory_expansion;
                            pc += 1;
                        } else if(opcode == zkevm_opcode::MSTORE8) {
                            // 0x53
                            zkevm_word_type addr = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, addr));

                            zkevm_word_type data = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, data));
                            auto byte = w_to_8(data)[31];
                            auto addr1 = w_to_16(addr)[15];

                            std::size_t memory_size_word = (memory.size() + 31) / 32;
                            std::size_t last_memory_cost = memory_size_word * memory_size_word / 512 + (3*memory_size_word);

                            for(std::size_t i = memory.size(); i < addr1; i++){
                                memory[i] = 0;
                            }
                            memory[addr1] = byte; // write to memory
                            _rw_operations.push_back(memory_rw_operation(call_id, addr1, rw_counter++, true, byte));
                            
                            addr1++;
                            while(addr1 % 32 != 0){
                                memory[addr1] = 0;
                                addr1++;
                            }

                            memory_size_word = (memory.size() + 31) / 32;
                            std::size_t new_memory_cost = memory_size_word * memory_size_word / 512 + (3*memory_size_word);
                            std::size_t memory_expansion = new_memory_cost - last_memory_cost;

                            gas -= 3 + memory_expansion;
                            pc += 1;
                        } else if(opcode == zkevm_opcode::JUMP){
                            // 0x56
                            auto addr = std::size_t(stack.back());
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, addr));
                            gas -= 8;
                            pc = addr;
                        } else if(opcode == zkevm_opcode::JUMPI){
                            // 0x57
                            auto addr = std::size_t(stack.back());
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, addr));
                            auto condition = std::size_t(stack.back());
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, condition));
                            gas -= 10;
                            pc = condition? addr: pc+1;
                        } else if(opcode == zkevm_opcode::PC){
                            // 0x58
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, pc));
                            stack.push_back(pc);
                            gas -= 2;
                            pc++;
                        } else if(opcode == zkevm_opcode::MSIZE){
                            // 0x59
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, memory.size()));
                            stack.push_back(memory.size());
                            gas -= 2;
                            pc++;
                        } else if(opcode == zkevm_opcode::GAS){
                            // 0x5a
                            gas -= 2;
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, gas));
                            stack.push_back(gas);
                            pc++;
                        } else if(opcode == zkevm_opcode::JUMPDEST){
                            // 0x5b
                            gas -= 1;
                            pc++;
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
                        } else if(opcode == zkevm_opcode::LOG0){
                            // 0xA0
                            auto offset = std::size_t(stack.back());
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, offset));

                            auto length = std::size_t(stack.back());
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, length));

                            for( std::size_t i = 0; i < length; i++){
                                _rw_operations.push_back(memory_rw_operation(call_id, stack.size(), rw_counter++, true, 0)); // placeholder
                            }

                            std::size_t next_mem = std::max(offset + length, state.memory_size);
                            std::size_t memory_expansion = memory_expansion_cost(next_mem, state.memory_size);

                            std::size_t next_memory_size = (memory_size_word_util(next_mem))*32;
                            
                            //placeholder values to mimic memory expansion
                            for (std::size_t i = 0; i < next_memory_size; ++i) {
                                memory[i] = static_cast<std::uint8_t>(i);
                            }
                            gas-=375; //static gas
                            gas -= 8 * length + memory_expansion; //dynamic gas
                            pc++;
                        } else if(opcode == zkevm_opcode::LOG1){
                            // 0xA1
                            auto offset = std::size_t(stack.back());
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, offset));

                            auto length = std::size_t(stack.back());
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, length));

                            auto topic1 = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, topic1));

                            
                            for( std::size_t i = 0; i < length; i++){
                                _rw_operations.push_back(memory_rw_operation(call_id, stack.size(), rw_counter++, true, 0)); // placeholder
                            }
                            
                            std::size_t next_mem = std::max(offset + length, state.memory_size);
                            std::size_t memory_expansion = memory_expansion_cost(next_mem, state.memory_size);
                            std::size_t next_memory_size = (memory_size_word_util(next_mem))*32;
                            //placeholder values to mimic memory expansion
                            for (std::size_t i = 0; i < next_memory_size; ++i) {
                                memory[i] = static_cast<std::uint8_t>(i);
                            }
                            gas-=375; //static gas
                            gas -= 375 + 8 * length + memory_expansion; //dynamic gas
                            pc++;
                        } else if(opcode == zkevm_opcode::LOG2){
                            // 0xA2
                            auto offset = std::size_t(stack.back());
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, offset));

                            auto length = std::size_t(stack.back());
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, length));

                            auto topic1 = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, topic1));

                            auto topic2 = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, topic2));

                            for( std::size_t i = 0; i < length; i++){
                                _rw_operations.push_back(memory_rw_operation(call_id, stack.size(), rw_counter++, true, 0)); // placeholder
                            }
                            
                            std::size_t next_mem = std::max(offset + length, state.memory_size);
                            std::size_t memory_expansion = memory_expansion_cost(next_mem, state.memory_size);
                            std::size_t next_memory_size = (memory_size_word_util(next_mem))*32;
                            //placeholder values to mimic memory expansion
                            for (std::size_t i = 0; i < next_memory_size; ++i) {
                                memory[i] = static_cast<std::uint8_t>(i);
                            }
                            gas-=375; //static gas
                            gas -= 375 * 2 + 8 * length + memory_expansion; //dynamic gas
                            pc++;
                        } else if(opcode == zkevm_opcode::LOG3){
                            // 0xA3
                            auto offset = std::size_t(stack.back());
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, offset));

                            auto length = std::size_t(stack.back());
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, length));

                            auto topic1 = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, topic1));

                            auto topic2 = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, topic2));

                            auto topic3 = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, topic3));

                            for( std::size_t i = 0; i < length; i++){
                                _rw_operations.push_back(memory_rw_operation(call_id, stack.size(), rw_counter++, true, 0)); // placeholder
                            }
                            
                            std::size_t next_mem = std::max(offset + length, state.memory_size);
                            std::size_t memory_expansion = memory_expansion_cost(next_mem, state.memory_size);
                            std::size_t next_memory_size = (memory_size_word_util(next_mem))*32;
                            //placeholder values to mimic memory expansion
                            for (std::size_t i = 0; i < next_memory_size; ++i) {
                                memory[i] = static_cast<std::uint8_t>(i);
                            }
                            gas-=375; //static gas
                            gas -= 375 * 3 + 8 * length + memory_expansion; //dynamic gas
                            pc++;
                        } else if(opcode == zkevm_opcode::LOG4){
                            // 0xA4
                            auto offset = std::size_t(stack.back());
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, offset));

                            auto length = std::size_t(stack.back());
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, length));

                            auto topic1 = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, topic1));

                            auto topic2 = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, topic2));

                            auto topic3 = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, topic3));

                            auto topic4 = stack.back();
                            stack.pop_back();
                            _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, topic4));

                            for( std::size_t i = 0; i < length; i++){
                                _rw_operations.push_back(memory_rw_operation(call_id, stack.size(), rw_counter++, true, 0)); // placeholder
                            }
                            
                            std::size_t next_mem = std::max(offset + length, state.memory_size);
                            std::size_t memory_expansion = memory_expansion_cost(next_mem, state.memory_size);
                            std::size_t next_memory_size = (memory_size_word_util(next_mem))*32;
                            //placeholder values to mimic memory expansion
                            for (std::size_t i = 0; i < next_memory_size; ++i) {
                                memory[i] = static_cast<std::uint8_t>(i);
                            }
                            gas-=375; //static gas
                            gas -= 375 * 4 + 8 * length + memory_expansion; //dynamic gas
                            pc++;
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
                virtual rw_operations_vector rw_operations() override {return _rw_operations;}
                virtual std::vector<copy_event> copy_events() override { return _copy_events;}
                virtual std::vector<zkevm_state> zkevm_states() override{ return _zkevm_states;}
                virtual std::vector<std::pair<zkevm_word_type, zkevm_word_type>> exponentiations()override{return _exponentiations;}
            protected:
                std::size_t                                              transactions_amount;
                std::size_t                                              rw_counter;
                zkevm_keccak_buffers                                     _keccaks;
                zkevm_keccak_buffers                                     _bytecodes;
                rw_operations_vector                                     _rw_operations;
                std::vector<copy_event>                                  _copy_events;
                std::vector<zkevm_state>                                 _zkevm_states;
                std::vector<std::pair<zkevm_word_type, zkevm_word_type>> _exponentiations;
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil
