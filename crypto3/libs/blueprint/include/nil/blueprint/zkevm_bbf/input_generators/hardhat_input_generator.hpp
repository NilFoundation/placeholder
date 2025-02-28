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

#include <nil/blueprint/zkevm_bbf/types/hashed_buffers.hpp>
#include <nil/blueprint/zkevm_bbf/types/rw_operation.hpp>
#include <nil/blueprint/zkevm_bbf/types/copy_event.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_state.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_account.hpp>
#include <nil/blueprint/zkevm_bbf/types/call_context.hpp>

#include <nil/blueprint/zkevm_bbf/types/zkevm_input_generator.hpp>
#include <nil/blueprint/zkevm_bbf/opcodes/zkevm_opcodes.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            class zkevm_hardhat_input_generator:zkevm_abstract_input_generator{
            public:
                zkevm_hardhat_input_generator(
                    const boost::property_tree::ptree &tree
                ){
                    std::cout << "ZKEVM HARDHAT INPUT GENERATOR loaded" << std::endl;
                    // 1. Load eth_accounts
                    for( auto &account: tree.get_child("eth_accounts")){
                        zkevm_account acc;
                        acc.address = zkevm_word_from_string(account.second.get_child("address").data());
                        acc.balance = zkevm_word_from_string(account.second.get_child("balance").data());
                        acc.seq_no = acc.ext_seq_no = std::size_t(zkevm_word_from_string(account.second.get_child("nonce").data()));
                        _accounts_initial_state[acc.address] = acc;
                    }
                    // 2. Load accounts
                    for( auto &account: tree.get_child("accounts")){
                        zkevm_account acc;
                        acc.address = zkevm_word_from_string(account.second.get_child("address").data());
                        acc.balance = zkevm_word_from_string(account.second.get_child("balance").data());
                        acc.seq_no = acc.ext_seq_no = std::size_t(zkevm_word_from_string(account.second.get_child("nonce").data()));
                        acc.storage = key_value_storage_from_ptree(account.second.get_child("storage"));

                        // Bytecode string starts from 0x, so second parameter is 2
                        acc.bytecode = byte_vector_from_hex_string(account.second.get_child("bytecode").data(), 2);
                        acc.code_hash = zkevm_keccak_hash(acc.bytecode);
                        _keccaks.new_buffer(acc.bytecode);
                        _bytecodes.new_buffer(acc.bytecode);

                        _accounts_initial_state[acc.address] = acc;
                    }
                    for( auto &[k,v]: _accounts_initial_state){
                        std::cout << "0x" << std::hex << k << " => " << v << std::dec<< std::endl;
                    }
                    _accounts_current_state = _accounts_initial_state;
                    // 3. Initialize state variables
                    std::size_t rw_counter = 1;
                    std::size_t call_id = 0;
                    std::size_t tx_id = 0;
                    std::size_t block_id = 0;

                    // 3. Start block.
                    for( auto &pt: tree.get_child("blocks")){
                        std::map<std::tuple<zkevm_word_type, std::size_t, zkevm_word_type>, std::size_t>  last_access_rw_counter;
                        std::map<std::tuple<zkevm_word_type, std::size_t, zkevm_word_type>, std::size_t>  last_write_rw_counter;

                        std::cout << "Block with hash " << pt.first.data() << std::endl;
                        block_id = rw_counter;
                        std::cout << "START BLOCK " << block_id << std::endl;
                        {
                            zkevm_state state;
                            state.block_id = rw_counter++;
                            state.tx_id = 0;
                            state.call_id = 0;
                            state.opcode = opcode_number_from_str("start_block");
                            state.gas = 0;
                            state.pc = 0;
                            state.rw_counter = rw_counter;
                            state.bytecode_hash = 0;
                            state.additional_input = 0;
                            state.stack_size = 0;
                            state.memory_slice = {};
                            state.stack_slice = {};
                            state.memory_size = 0;
                            state.last_access_rw_counter = last_access_rw_counter;
                            state.last_write_rw_counter = last_write_rw_counter;
                            _zkevm_states.push_back(state);
                            _call_stack.push_back({state, block_id, 0, 0});

                            _rw_operations.push_back(call_context_rw_operation(
                                block_id, call_context_field::parent_id, 0
                            ));
                        }
                        for( auto &tt: pt.second.get_child("transactions")){
                            tx_id = rw_counter;
                            call_id = rw_counter;
                            zkevm_word_type tx_to = zkevm_word_from_string(tt.second.get_child("tx").get_child("to").data());
                            zkevm_word_type tx_from = zkevm_word_from_string(tt.second.get_child("tx").get_child("from").data());
                            zkevm_word_type bytecode_hash = _accounts_initial_state[tx_to].code_hash;
                            zkevm_word_type call_context_address = tx_to;
                            std::cout << "START TRANSACTION " << tx_id << " to " << std::hex << tx_to << std::dec << std::endl;
                            {
                                zkevm_state state;
                                state.block_id = block_id;
                                state.tx_id = rw_counter;
                                state.call_id = tx_id;
                                state.opcode = opcode_number_from_str("start_transaction");
                                state.gas = 0;
                                state.pc = 0;
                                state.rw_counter = rw_counter;
                                state.bytecode_hash = bytecode_hash;
                                state.additional_input = 0;
                                state.stack_size = 0;
                                state.memory_size = 0;
                                state.memory_slice = {};
                                state.stack_slice = {};
                                state.call_context_address = call_context_address;
                                state.last_access_rw_counter = last_access_rw_counter;
                                state.last_write_rw_counter = last_write_rw_counter;

                                _call_stack.push_back({state, call_id, 0, 0});
                                _zkevm_states.push_back(state);

                                _rw_operations.push_back(call_context_rw_operation(
                                    tx_id, call_context_field::parent_id, block_id
                                ));
                                _rw_operations.push_back(call_context_rw_operation(
                                    tx_id, call_context_field::block_id, block_id
                                ));
                                _rw_operations.push_back(call_context_rw_operation(
                                    tx_id, call_context_field::tx_id, tx_id
                                ));
                                _rw_operations.push_back(call_context_rw_operation(
                                    tx_id, call_context_field::from, tx_from
                                ));
                                _rw_operations.push_back(call_context_rw_operation(
                                    tx_id, call_context_field::to, tx_to
                                ));
                                _rw_operations.push_back(call_context_rw_operation(
                                    tx_id, call_context_field::call_context_address, call_context_address
                                ));
                                rw_counter += call_context_field_amount;
                            }
                            // Initialize transaction
                            //      stack -- empty
                            //      memory -- empty
                            //      storage -- from caller accountt
                            std::vector<zkevm_word_type> stack = {};
                            std::vector<zkevm_word_type> stack_next;
                            std::vector<std::uint8_t> memory = {};
                            std::vector<std::uint8_t> memory_next;
                            // std::map<zkevm_word_type, zkevm_word_type> storage;
                            // std::map<zkevm_word_type, zkevm_word_type> storage_next;

                            auto ptrace = tt.second.get_child("trace.structLogs");
                            std::size_t memory_size_before = 0;
                            for( auto it = ptrace.begin(); it!=ptrace.end(); it++){
                                std::string opcode = it->second.get_child("op").data();
                                std::size_t depth = stoi(it->second.get_child("depth").data());

                                for( std::size_t i = 0; i < depth; i++) std::cout << "\t";
                                    std::cout  << opcode << " call_id = " << call_id << std::endl;

                                if(std::distance(it, ptrace.end()) != 1){
                                    stack_next = zkevm_word_vector_from_ptree(std::next(it)->second.get_child("stack"));
                                    memory_next = byte_vector_from_ptree(std::next(it)->second.get_child("memory"));
                                    // storage_next = key_value_storage_from_ptree(it->second.get_child("storage"));
                                    // for(
                                    //     auto it2 = _accounts_initial_state[call_context_address].storage.begin();
                                    //     it2 != _accounts_initial_state[call_context_address].storage.end(); it2++
                                    // ){
                                    //     if( !storage_next.count(it2->first) )
                                    //         storage_next[it2->first] = _accounts_initial_state[call_context_address].storage[it2->first];
                                    // }
                                    // std::cout << "\t\t\tStorage:" << std::endl;
                                    // for( auto &[k,v]: storage){
                                    //     std::cout << "\t\t\t\t" << std::hex << k << " -> " << v << std::dec<< std::endl;
                                    // }
                                    // std::cout << "\t\t\tStorageNext:" << std::endl;
                                    // for( auto &[k,v]: storage_next){
                                    //     std::cout << "\t\t\t\t" << std::hex << k << " -> " << v << std::dec<< std::endl;
                                    // }
                                }
                                zkevm_state state;
                                state.block_id = block_id;
                                state.tx_id = tx_id;        // TODO: change it
                                state.call_id = call_id;
                                state.opcode = opcode_number_from_str(opcode);
                                state.gas = atoi(it->second.get_child("gas").data().c_str());
                                state.pc = atoi(it->second.get_child("pc").data().c_str());
                                state.rw_counter = rw_counter;
                                state.bytecode_hash = bytecode_hash; // TODO: fix it if possible
                                state.additional_input = opcode.substr(0,4) == "PUSH"? stack_next[stack_next.size() - 1]: 0;
                                state.stack_size = stack.size();
                                state.memory_size = memory_size_before;
                                state.stack_slice = stack;
                                state.call_context_address = call_context_address;
                                state.last_access_rw_counter = last_access_rw_counter;
                                state.last_write_rw_counter = last_write_rw_counter;

                                for( std::size_t i = 0; i < memory.size(); i++){
                                    state.memory_slice[i] = memory[i];
                                }
                                state.storage_slice = _accounts_current_state[call_context_address].storage;
                                memory_size_before = memory.size();
                                if(opcode == "STOP") {
                                    // 0x00 -- no RW operations
                                } else if(opcode == "ADD") {
                                    // 0x01
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "MUL") {
                                    // 0x02
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "SUB") {
                                    // 0x03
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "DIV") {
                                    // 0x04
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "SDIV") {
                                    // 0x05
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                }  else if(opcode == "MOD") {
                                    // 0x06
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                }   else if(opcode == "SMOD") {
                                    // 0x07
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "ADDMOD") {
                                    // 0x08
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-3, rw_counter++, false, stack[stack.size()-3]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "MULMOD") {
                                    // 0x09
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-3, rw_counter++, false, stack[stack.size()-3]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                }   else if(opcode == "EXP") {
                                    // 0x0a
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                    _exponentiations.push_back({stack[stack.size() - 1], stack[stack.size() - 2]});
                                }   else if(opcode == "SIGEXTEND") {
                                    // 0x0b
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "LT") {
                                    // 0x10
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "GT") {
                                    // 0x11
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "SLT") {
                                    // 0x12
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "SGT") {
                                    // 0x13
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "EQ") {
                                    // 0x14
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "ISZERO") {
                                    // 0x15
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "AND") {
                                    // 0x16
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "OR") {
                                    // 0x17
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "XOR") {
                                    // 0x18
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "NOT") {
                                    // 0x19
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "BYTE") {
                                    // 0x1a
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "SHL") {
                                    // 0x1b
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "SHR") {
                                    // 0x1c
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "SAR") {
                                    // 0x1d
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "KECCAK256") {
                                    // 0x20
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));

                                    std::size_t length = std::size_t(stack[stack.size()-2]);
                                    std::size_t  offset = std::size_t(stack[stack.size()-1]);
                                    auto hash_value = stack_next[stack_next.size()-1];

                                    std::cout << "\tAdd copy event for KECCAK256 length = " << length << std::endl;
                                    copy_event cpy;
                                    cpy.source_id = call_id;
                                    cpy.source_type = copy_operand_type::memory;
                                    cpy.src_address = offset;
                                    cpy.destination_id = hash_value;
                                    cpy.destination_type = copy_operand_type::keccak;
                                    cpy.dst_address = 0;
                                    cpy.length = length;
                                    cpy.initial_rw_counter = rw_counter;
                                    cpy.bytes = {};
                                    std::cout << "\toffset = " << offset << std::endl;

                                    std::size_t offset_small = w_to_16(offset)[15];
                                    for( std::size_t i = 0; i < length; i++){
                                        _rw_operations.push_back(memory_rw_operation(call_id, offset+i, rw_counter++, false, memory_next[offset_small + i]));
                                        cpy.bytes.push_back(memory_next[offset_small + i]);
                                    }
                                    _copy_events.push_back(cpy);
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, hash_value));
                                    _keccaks.new_buffer(cpy.bytes);
                                    memory_size_before = memory_next.size();
                                } else if(opcode == "ADDRESS") {
                                    // 0x30
                                    std::cout << "Test ADDRESS opcode, please!" << std::endl;
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));

                                } else if(opcode == "BALANCE") {
                                    // 0x31
                                    // std::cout << "Test me, please!" << std::endl;
                                    std::cout << "Test BALANCE opcode, please!" << std::endl;
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));

                                    // TODO:  add read operations from account
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));

                                } else if(opcode == "ORIGIN") {
                                    // 0x32
                                    // std::cout << "Test me, please!" << std::endl;
                                    std::cout << "Test ORIGIN opcode, please!" << std::endl;
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));

                                } else if(opcode == "CALLER") {
                                    // 0x33
                                    // std::cout << "Test me, please!" << std::endl;
                                    std::cout << "Test CALLER opcode, please!" << std::endl;
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));

                                } else if(opcode == "CALLVALUE") {
                                    // 0x34
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));

                                } else if(opcode == "CALLDATALOAD") {
                                    // 0x35
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));

                                    // TODO: add 32 read operations to calldata
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));

                                } else if(opcode == "CALLDATASIZE") {
                                    // 0x36
                                    // TODO: get real call data size
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));

                                } else if(opcode == "CALLDATACOPY") {
                                    // 0x37
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-3, rw_counter++, false, stack[stack.size()-3]));

                                    std::size_t length = std::size_t(stack[stack.size()-3]);
                                    std::size_t src = std::size_t(stack[stack.size()-2]);
                                    std::size_t dest = std::size_t(stack[stack.size()-1]);
                                    // std::cout << "Length = " << length << std::endl;
                                    // std::cout << "Memory_size " << memory.size() << "=>" << memory_next.size() << std::endl;

                                    std::cout << "\tAdd copy event for CALLDATACOPY length = " << length << std::endl;
                                    copy_event cpy;
                                    cpy.source_id = call_id;
                                    cpy.source_type = copy_operand_type::calldata;
                                    cpy.src_address = src;
                                    cpy.destination_id = call_id;
                                    cpy.destination_type = copy_operand_type::memory;
                                    cpy.dst_address = dest;
                                    cpy.length = length;
                                    cpy.initial_rw_counter = rw_counter;
                                    cpy.bytes = {};

                                    // TODO: add read operations on calldata after calldata final design
                                    for( std::size_t i = 0; i < length; i++){
                                        _rw_operations.push_back(memory_rw_operation(call_id, dest+i, rw_counter++, true, memory_next[dest+i]));
                                        cpy.bytes.push_back(memory_next[dest+i]); //TODO: change it on calldata
                                    }
                                    _copy_events.push_back(cpy);
                                    memory_size_before = memory_next.size();
                                } else if(opcode == "CODESIZE") {
                                    // 0x38
                                    // std::cout << "Test me, please!" << std::endl;
                                    std::cout << "CODESIZE" << std::endl;
                                    exit(2);
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));

                                } else if(opcode == "CODECOPY") {
                                    // 0x39
                                    std::cout << "CODECOPY" << std::endl;
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-3, rw_counter++, false, stack[stack.size()-3]));
                                    auto destination_offset = stack[stack.size()-1];
                                    auto code_offset = stack[stack.size()-2];
                                    auto length = stack[stack.size() - 3];
                                    std::cout
                                        << "\tDestination offset" <<  stack[stack.size()-1] << std::endl
                                        << "\tCurrent code offset" <<  stack[stack.size()-2]<< std::endl
                                        << "\tLength" <<  stack[stack.size()-3] << std::endl;
                                    memory_size_before = memory_next.size();
                                    for(std::size_t i = 0; i < length; i++){
                                        _rw_operations.push_back(memory_rw_operation(call_id, destination_offset+i, rw_counter++, true, _bytecodes.get_data()[call_id].first[std::size_t(code_offset) + i]));
                                    }
                                    // Consistency with bytecode table will be checked by copy circuit
                                } else if(opcode == "GASPRICE") {
                                    // 0x3a
                                    // std::cout << "Test me, please!" << std::endl;
                                    std::cout << "GASPRICE not implemented" << std::endl;
                                    exit(2);
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));

                                } else if(opcode == "EXTCODESIZE") {
                                    // 0x3b
                                    // std::cout << "Test me, please!" << std::endl;
                                    std::cout << "EXTCODESIZE not implemented" << std::endl;
                                    exit(2);
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));

                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));

                                } else if(opcode == "EXTCODECOPY") {
                                    // 0x3c
                                    // std::cout << "Test me, please!" << std::endl;
                                    std::cout << "EXTCODECOPY not implemented" << std::endl;
                                    exit(2);
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-3, rw_counter++, false, stack[stack.size()-3]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-4, rw_counter++, false, stack[stack.size()-4]));

                                    // TODO: add length write operations to memory
                                    // Consistency with bytecode table will be checked by bytecode circuit
                                } else if(opcode == "RETURNDATASIZE") {
                                    // 0x3d
                                    // std::cout << "Test me, please!" << std::endl;
                                    // std::cout << "RETURNDATASIZE not implemented" << std::endl;
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));

                                } else if(opcode == "RETURNDATACOPY") {
                                    // 0x3e
                                    // std::cout << "Test me, please!" << std::endl;
                                    auto dest_offset = stack[stack.size()-1];
                                    auto offset = stack[stack.size()-2];
                                    auto length = stack[stack.size()-3];
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, dest_offset));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, offset));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-3, rw_counter++, false, length));

                                    // TODO: add length read operations from last return data
                                    for( std::size_t ind = 0; ind < length; ind++){
                                        _rw_operations.push_back(
                                            memory_rw_operation(
                                                call_id, dest_offset+ind, rw_counter++, true, memory_next[std::size_t(dest_offset+ind)]
                                            )
                                        );
                                    }
                                    memory_size_before = memory_next.size();
                                    // Where will consistency check be done?
                                } else if(opcode == "EXTCODEHASH") {
                                    // 0x3f
                                    // std::cout << "Test me, please!" << std::endl;
                                    std::cout << "EXTCODEHASH not implemented" << std::endl;
                                    exit(2);
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));

                                } else if(opcode == "BLOCKHASH") {
                                    // 0x40
                                    std::cout << "BLOCKHASH not implemented" << std::endl;
                                    exit(2);
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));

                                } else if(opcode == "COINBASE") {
                                    // 0x41
                                    std::cout << "COINBASE not implemented" << std::endl;
                                    exit(2);
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));

                                } else if(opcode == "TIMESTAMP") {
                                    // 0x42
                                    std::cout << "TIMESTAMP not implemented" << std::endl;
                                    exit(2);
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));

                                } else if(opcode == "NUMBER") {
                                    // 0x43
                                    std::cout << "NUMBER not implemented" << std::endl;
                                    exit(2);
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));

                                } else if(opcode == "DIFFICULTY") {
                                    // 0x44
                                    std::cout << "DIFFICULTY not implemented" << std::endl;
                                    exit(2);
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "GASLIMIT") {
                                    // 0x45
                                    std::cout << "GASLIMIT not implemented" << std::endl;
                                    exit(2);
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "CHAINID") {
                                    // 0x46
                                    std::cout << "CHAINID not implemented" << std::endl;
                                    exit(2);
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "SELFBALANCE") {
                                    // 0x47
                                    std::cout << "SELFBALANCE not implemented" << std::endl;
                                    exit(2);
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));

                                } else if(opcode == "BASEFEE") {
                                    // 0x48
                                    std::cout << "BASEFEE not implemented" << std::endl;
                                    exit(2);
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));

                                } else if(opcode == "BLOBHASH") {
                                    // 0x49
                                    std::cout << "BLOBHASH not implemented" << std::endl;
                                    exit(2);
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));

                                } else if(opcode == "BLOBBASEFEE") {
                                    // 0x4a
                                    std::cout << "BLOBBASEFEE not implemented" << std::endl;
                                    exit(2);
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));

                                } else if(opcode == "POP") {
                                    // 0x50
                                } else if(opcode == "MLOAD") {
                                    // 0x51
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, false, stack[stack.size()-1]));

                                    zkevm_word_type addr = stack[stack.size() - 1];
                                    BOOST_ASSERT_MSG(addr < std::numeric_limits<std::size_t>::max(), "Cannot process so large memory address");
                                    // std::cout << "\t\t Address = 0x" << std::hex << addr << std::dec << " memory size " << memory.size() << std::endl;
                                    for( std::size_t i = 0; i < 32; i++){
                                        _rw_operations.push_back(memory_rw_operation(call_id, addr+i, rw_counter++, false, addr+i < memory.size() ? memory[std::size_t(addr+i)]: 0));

                                    }
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                    memory_size_before = memory_next.size();
                                } else if(opcode == "MSTORE") {
                                    // 0x52
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));

                                    zkevm_word_type addr = stack[stack.size() - 1];
                                    BOOST_ASSERT_MSG(addr < std::numeric_limits<std::size_t>::max(), "Cannot process so large memory address");
                                    // std::cout << "\t\t Address = 0x" << std::hex << addr << std::dec << " memory size " << memory.size() << std::endl;
                                    auto bytes = w_to_8(stack[stack.size() - 2]);
                                    for( std::size_t i = 0; i < 32; i++){
                                    _rw_operations.push_back(memory_rw_operation(call_id, addr + i, rw_counter++, true, bytes[i]));
                                    }
                                    memory_size_before = memory_next.size();
                                } else if(opcode == "MSTORE8") {
                                    // 0x53
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));

                                    zkevm_word_type addr = stack[stack.size() - 1];
                                    BOOST_ASSERT_MSG(addr < std::numeric_limits<std::size_t>::max(), "Cannot process so large memory address");
                                    // std::cout << "\t\t Address = 0x" << std::hex << addr << std::dec << " memory size " << memory.size() << std::endl;
                                    auto bytes = w_to_8(stack[stack.size() - 2]);
                                    _rw_operations.push_back(memory_rw_operation(call_id, addr, rw_counter++, true, bytes[31]));
                                    memory_size_before = memory_next.size();
                                } else if(opcode == "SLOAD") {
                                    // 0x54
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    auto storage_key = stack[stack.size() - 1];
                                    _rw_operations.push_back(storage_rw_operation(
                                        block_id,
                                        call_context_address,
                                        storage_key, //Storage key
                                        rw_counter++,
                                        false,
                                        _accounts_current_state[call_context_address].storage[storage_key],
                                        _accounts_initial_state[call_context_address].storage[storage_key],
                                        call_id,
                                        last_access_rw_counter.count(std::make_tuple(call_context_address, 0, storage_key)) == 0 ? 0 : last_access_rw_counter[std::make_tuple(call_context_address, 0, storage_key)],
                                        last_write_rw_counter.count(std::make_tuple(call_context_address, 0, storage_key)) == 0 ? 0 : last_write_rw_counter[std::make_tuple(call_context_address, 0, storage_key)],
                                        _accounts_current_state[call_context_address].storage[storage_key]
                                    ));
                                    last_access_rw_counter[std::make_tuple(call_context_address, 0, storage_key)] = rw_counter - 1;
                                    std::cout << _rw_operations[_rw_operations.size()-1] << std::endl;
                                    update_cold_access_list(call_context_address,0, storage_key, _rw_operations[_rw_operations.size()-1]);
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                    // TODO: here should be previous value
                                } else if(opcode == "SSTORE") {
                                    // 0x55call_context_rw_operation
                                    auto storage_key = stack[stack.size() - 1];
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, storage_key));
                                    std::cout << _rw_operations[_rw_operations.size()-1] << std::endl;
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    auto value = stack[stack.size() - 2];
                                    std::cout << "Value_after = " << value << std::endl;

                                    _rw_operations.push_back(storage_rw_operation(
                                        block_id,
                                        call_context_address,
                                        storage_key,
                                        rw_counter++,
                                        true,
                                        value,
                                        _accounts_initial_state[call_context_address].storage[storage_key], // initial value
                                        call_id,                                                // For REVERT correctness
                                        last_access_rw_counter.count(std::make_tuple(call_context_address, 0, storage_key)) == 0 ? 0 : last_access_rw_counter[std::make_tuple(call_context_address, 0, storage_key)],
                                        last_write_rw_counter.count(std::make_tuple(call_context_address, 0, storage_key)) == 0 ? 0 : last_write_rw_counter[std::make_tuple(call_context_address, 0, storage_key)],
                                        _accounts_current_state[call_context_address].storage[storage_key]
                                    )); // Second parameter should be transaction_id
                                    last_access_rw_counter[std::make_tuple(call_context_address, 0, storage_key)] = rw_counter-1;
                                    last_write_rw_counter[std::make_tuple(call_context_address, 0, storage_key)] = rw_counter-1;
                                    _accounts_current_state[call_context_address].storage[storage_key] = value;
                                    std::cout << _rw_operations[_rw_operations.size()-1] << std::endl;
                                    update_cold_access_list(call_context_address,0, storage_key, _rw_operations[_rw_operations.size()-1]);
                                } else if(opcode == "JUMP") {
                                    // 0x56
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                } else if(opcode == "JUMPI") {
                                    // 0x57
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));

                                } else if(opcode == "PC") {
                                    // 0x58
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, stack_next[stack_next.size()-1]));

                                } else if(opcode == "MSIZE") {
                                    // 0x58
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, stack_next[stack_next.size()-1]));

                                } else if(opcode == "GAS") {
                                    // 0x59
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, stack_next[stack_next.size()-1]));
                                    std::cout << "Gas " << _rw_operations[_rw_operations.size()-1] << std::endl;
                                } else if(opcode == "JUMPDEST") {
                                    // 0x5a
                                } else if(opcode == "TLOAD") {
                                    // 0x5b
                                    std::cout << "TLOAD not implemented" << std::endl;
                                    exit(2);
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, false, stack[stack.size()-1]));

                                    // TODO: add trasient storage operations
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));

                                } else if(opcode == "TSTORE") {
                                    // 0x5c
                                    std::cout << "TSTORE not implemented" << std::endl;
                                    exit(2);
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, false, stack[stack.size()-1]));

                                    // TODO: add trasient storage write operations
                                } else if(opcode == "MCOPY") {
                                    // 0x5d
                                    std::cout << "MCOPY not implemented. Add copy event" << std::endl;
                                    exit(2);
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-3, rw_counter++, false, stack[stack.size()-3]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));

                                    // TODO: add length read operations to memory
                                    // TODO: add length write operations to memory
                                    // Consistensy will be checked by copy circuit
                                }  else  if(opcode == "PUSH0") {
                                    // 0x5f
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                }  else  if(opcode == "PUSH1") {
                                    // 0x60
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH2") {
                                    // 0x61
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH3") {
                                    // 0x62
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH4") {
                                    // 0x63
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH5") {
                                    // 0x64
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH6") {
                                    // 0x65
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH7") {
                                    // 0x66
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH8") {
                                    // 0x67
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH9") {
                                    // 0x68
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH10") {
                                    // 0x69
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH11") {
                                    // 0x6a
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH12") {
                                    // 0x6b
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH13") {
                                    // 0x6c
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH14") {
                                    // 0x6d
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH15") {
                                    // 0x6e
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH16") {
                                    // 0x6f
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH17") {
                                    // 0x70
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH18") {
                                    // 0x71
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH19") {
                                    // 0x72
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH20") {
                                    // 0x73
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH21") {
                                    // 0x74
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH22") {
                                    // 0x75
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH23") {
                                    // 0x76
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH24") {
                                    // 0x77
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH25") {
                                    // 0x78
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH26") {
                                    // 0x79
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH27") {
                                    // 0x7a
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH28") {
                                    // 0x7b
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH29") {
                                    // 0x7c
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH30") {
                                    // 0x7d
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH31") {
                                    // 0x7e
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "PUSH32") {
                                    // 0x7f
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "DUP1") {
                                    // 0x80
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "DUP2") {
                                    // 0x81
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "DUP3") {
                                    // 0x82
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-3, rw_counter++, false, stack[stack.size()-3]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "DUP4") {
                                    // 0x83
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-4, rw_counter++, false, stack[stack.size()-4]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "DUP5") {
                                    // 0x84
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-5, rw_counter++, false, stack[stack.size()-5]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "DUP6") {
                                    // 0x85
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-6, rw_counter++, false, stack[stack.size()-6]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "DUP7") {
                                    // 0x86
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-7, rw_counter++, false, stack[stack.size()-7]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "DUP8") {
                                    // 0x87
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-8, rw_counter++, false, stack[stack.size()-8]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "DUP9") {
                                    // 0x88
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-9, rw_counter++, false, stack[stack.size()-9]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "DUP10") {
                                    // 0x89
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-10, rw_counter++, false, stack[stack.size()-10]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "DUP11") {
                                    // 0x8a
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-11, rw_counter++, false, stack[stack.size()-11]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "DUP12") {
                                    // 0x8b
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-12, rw_counter++, false, stack[stack.size()-12]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "DUP13") {
                                    // 0x8c
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-13, rw_counter++, false, stack[stack.size()-13]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "DUP14") {
                                    // 0x8d
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-14, rw_counter++, false, stack[stack.size()-14]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "DUP15") {
                                    // 0x8e
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-15, rw_counter++, false, stack[stack.size()-15]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "DUP16") {
                                    // 0x8f
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-16, rw_counter++, false, stack[stack.size()-16]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "SWAP1") {
                                    // 0x90
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-2, rw_counter++, true, stack_next[stack_next.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "SWAP2") {
                                    // 0x91
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-3, rw_counter++, false, stack[stack.size()-3]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-3, rw_counter++, true, stack_next[stack_next.size()-3]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "SWAP3") {
                                    // 0x92
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-4, rw_counter++, false, stack[stack.size()-4]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-4, rw_counter++, true, stack_next[stack_next.size()-4]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "SWAP4") {
                                    // 0x93
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-5, rw_counter++, false, stack[stack.size()-5]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-5, rw_counter++, true, stack_next[stack_next.size()-5]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "SWAP5") {
                                    // 0x94
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-6, rw_counter++, false, stack[stack.size()-6]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-6, rw_counter++, true, stack_next[stack_next.size()-6]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "SWAP6") {
                                    // 0x95
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-7, rw_counter++, false, stack[stack.size()-7]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-7, rw_counter++, true, stack_next[stack_next.size()-7]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "SWAP7") {
                                    // 0x96
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-8, rw_counter++, false, stack[stack.size()-8]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-8, rw_counter++, true, stack_next[stack_next.size()-8]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "SWAP8") {
                                    // 0x97
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-9, rw_counter++, false, stack[stack.size()-9]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-9, rw_counter++, true, stack_next[stack_next.size()-9]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "SWAP9") {
                                    // 0x98
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-10, rw_counter++, false, stack[stack.size()-10]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-10, rw_counter++, true, stack_next[stack_next.size()-10]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "SWAP10") {
                                    // 0x99
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-11, rw_counter++, false, stack[stack.size()-11]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-11, rw_counter++, true, stack_next[stack_next.size()-11]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "SWAP11") {
                                    // 0x9a
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-12, rw_counter++, false, stack[stack.size()-12]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-12, rw_counter++, true, stack_next[stack_next.size()-12]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "SWAP12") {
                                    // 0x9b
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-13, rw_counter++, false, stack[stack.size()-13]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-13, rw_counter++, true, stack_next[stack_next.size()-13]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "SWAP13") {
                                    // 0x9c
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-14, rw_counter++, false, stack[stack.size()-14]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-14, rw_counter++, true, stack_next[stack_next.size()-14]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "SWAP14") {
                                    // 0x9d
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-15, rw_counter++, false, stack[stack.size()-15]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-15, rw_counter++, true, stack_next[stack_next.size()-15]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "SWAP15") {
                                    // 0x9e
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-16, rw_counter++, false, stack[stack.size()-16]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-16, rw_counter++, true, stack_next[stack_next.size()-16]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "SWAP16") {
                                    // 0x9f
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-17, rw_counter++, false, stack[stack.size()-17]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-17, rw_counter++, true, stack_next[stack_next.size()-17]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "LOG0") {
                                    // 0xa0
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                } else if(opcode == "LOG1") {
                                    // 0xa1
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-3, rw_counter++, false, stack[stack.size()-3]));
                                } else if(opcode == "LOG2") {
                                    // 0xa2
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-3, rw_counter++, false, stack[stack.size()-3]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-4, rw_counter++, false, stack[stack.size()-4]));
                                } else if(opcode == "LOG3") {
                                    // 0xa3
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-3, rw_counter++, false, stack[stack.size()-3]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-4, rw_counter++, false, stack[stack.size()-4]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-5, rw_counter++, false, stack[stack.size()-5]));
                                } else if(opcode == "LOG4") {
                                    // 0xa4
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-3, rw_counter++, false, stack[stack.size()-3]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-4, rw_counter++, false, stack[stack.size()-4]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-5, rw_counter++, false, stack[stack.size()-5]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-6, rw_counter++, false, stack[stack.size()-6]));
                                } else if(opcode == "CREATE") {
                                    // 0xf0
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-3, rw_counter++, false, stack[stack.size()-3]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "CALL") {
                                    // 0xf1
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-3, rw_counter++, false, stack[stack.size()-3]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-4, rw_counter++, false, stack[stack.size()-4]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-5, rw_counter++, false, stack[stack.size()-5]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-6, rw_counter++, false, stack[stack.size()-6]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-7, rw_counter++, false, stack[stack.size()-7]));
                                    call_context_address = stack[stack.size()-2];
                                    // MOVED to END_CALL operation
                                    // _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                    //exit(2);
                                } else if(opcode == "CALLCODE") {
                                    // 0xf2
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-7, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-6, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-5, rw_counter++, false, stack[stack.size()-3]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-4, rw_counter++, false, stack[stack.size()-4]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-3, rw_counter++, false, stack[stack.size()-5]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-6]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-7]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));

                                } else if(opcode == "RETURN") {
                                    // 0xf3
                                    std::cout << "RETURN " << "\tAdd copy event for RETURN" << std::endl;
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    std::cout
                                        << "\tOffset " << stack[stack.size()-1]
                                        << "\tLength " << stack[stack.size()-2]
                                        << std::endl;
                                    std::size_t offset = std::size_t(stack[stack.size()-1]);
                                    std::size_t length = std::size_t(stack[stack.size()-2]);

                                    copy_event cpy;
                                    cpy.source_id = call_id;
                                    cpy.source_type = copy_operand_type::memory;
                                    cpy.src_address = offset;
                                    cpy.destination_id = call_id;
                                    cpy.destination_type = copy_operand_type::returndata;
                                    cpy.dst_address = 0;
                                    cpy.length = length;
                                    cpy.initial_rw_counter = rw_counter;
                                    cpy.bytes = {};

                                    std::cout << "\tRETURN length = " << length << " memory size = " << memory.size() << " offset = " << offset << std::endl;
                                    std::cout << "\tInitial RW counter = " << std::hex << rw_counter << std::dec << std::endl;
                                    for(std::size_t i = 0; i < length; i++){
                                        _rw_operations.push_back(memory_rw_operation(call_id, offset+i, rw_counter++, false, offset+i < memory.size() ? memory[offset+i]: 0));
                                        cpy.bytes.push_back(offset+i < memory.size() ? memory[offset+i]: 0);
                                    }
                                    std::cout << std::endl;
                                    _copy_events.push_back(cpy);
                                } else if(opcode == "DELEGATECALL") {
                                    // 0xf4
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-3, rw_counter++, false, stack[stack.size()-3]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-4, rw_counter++, false, stack[stack.size()-4]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-5, rw_counter++, false, stack[stack.size()-5]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-6, rw_counter++, false, stack[stack.size()-6]));
                                } else if(opcode == "CREATE2") {
                                    // 0xf5
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-3, rw_counter++, false, stack[stack.size()-3]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-4, rw_counter++, false, stack[stack.size()-4]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "STATICCALL") {
                                    // 0xfa
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-3, rw_counter++, false, stack[stack.size()-3]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-4, rw_counter++, false, stack[stack.size()-4]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-5, rw_counter++, false, stack[stack.size()-5]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-6, rw_counter++, false, stack[stack.size()-6]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                } else if(opcode == "REVERT") {
                                    // 0xfd
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                                    for( auto &cold_access : _call_stack.back().cold_write_list){
                                        _rw_operations.push_back(
                                            state_rw_operation(
                                                block_id,
                                                cold_access.second.address,
                                                cold_access.second.field,
                                                cold_access.second.storage_key,
                                                rw_counter++,
                                                true,
                                                cold_access.second.value_before,
                                                cold_access.second.initial_value,
                                                call_id,
                                                last_access_rw_counter[cold_access.first],
                                                last_write_rw_counter[cold_access.first],
                                                _accounts_current_state[cold_access.second.address].storage[cold_access.second.storage_key]
                                            )
                                        );
                                        last_access_rw_counter[cold_access.first] = rw_counter-1;
                                        last_write_rw_counter[cold_access.first] = rw_counter-1;
                                        _accounts_current_state[cold_access.second.address].storage[cold_access.second.storage_key] = cold_access.second.value_before;
                                        std::cout << "REVERT " <<  _rw_operations.back() << std::endl;
                                    }
                                } else if(opcode == "SELFDESTRUCT") {
                                    // 0xff
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                                } else {
                                    std::cout << "Unknown opcode " << std::hex << opcode << std::dec << std::endl;
                                    BOOST_ASSERT(false);
                                }
                                _zkevm_states.push_back(state);
                                if( opcode == "CALL" || opcode == "DELEGATECALL" ){
                                    std::size_t parent_id = call_id;
                                    call_id = rw_counter;
                                    zkevm_word_type call_to = stack[stack.size()-2];
                                    std::cout << "START CALL " << call_id << std::endl;

                                    if( opcode == "CALL" )
                                        _call_stack.push_back({state, call_id, std::size_t(stack[stack.size()-6]), std::size_t(stack[stack.size()-7])});
                                    else if( opcode == "DELEGATECALL" )
                                        _call_stack.push_back({state, call_id, std::size_t(stack[stack.size()-5]), std::size_t(stack[stack.size()-6])});
                                    zkevm_state start_call_state;
                                    start_call_state.block_id = block_id;
                                    start_call_state.tx_id = tx_id;
                                    start_call_state.call_id = rw_counter;
                                    start_call_state.opcode = opcode_number_from_str("start_call");
                                    start_call_state.gas = 0;
                                    start_call_state.pc = 0;
                                    start_call_state.rw_counter = rw_counter;
                                    start_call_state.bytecode_hash = 0;
                                    start_call_state.additional_input = 0;
                                    start_call_state.stack_size = 0;
                                    start_call_state.memory_size = 0;
                                    start_call_state.memory_slice = {};
                                    start_call_state.stack_slice = {};
                                    start_call_state.last_access_rw_counter = last_access_rw_counter;
                                    state.last_access_rw_counter = last_access_rw_counter;
                                    _zkevm_states.push_back(start_call_state);

                                    _rw_operations.push_back(call_context_rw_operation(
                                        call_id, call_context_field::parent_id, parent_id
                                    ));
                                    _rw_operations.push_back(call_context_rw_operation(
                                        call_id, call_context_field::block_id, block_id
                                    ));
                                    _rw_operations.push_back(call_context_rw_operation(
                                        call_id, call_context_field::tx_id, tx_id
                                    ));
                                    _rw_operations.push_back(call_context_rw_operation(
                                        call_id, call_context_field::from, tx_from
                                    ));
                                    _rw_operations.push_back(call_context_rw_operation(
                                        call_id, call_context_field::to, tx_to
                                    ));
                                    _rw_operations.push_back(call_context_rw_operation(
                                        call_id, call_context_field::call_context_address, call_context_address
                                    ));
                                    rw_counter += call_context_field_amount;

                                    call_id = start_call_state.call_id;
                                    memory_size_before = memory_next.size();
                                    bytecode_hash = _accounts_initial_state[call_to].code_hash;
                                }
                                if( opcode == "STOP" ){
                                    while( _call_stack.size() != 1){
                                        zkevm_state end_call_state = _call_stack[_call_stack.size() - 1].state;
                                        end_call_state.opcode = _call_stack.size() == 1? opcode_number_from_str("end_transaction") : opcode_number_from_str("end_call");
                                        end_call_state.last_write_rw_counter = last_write_rw_counter;
                                        end_call_state.last_access_rw_counter = last_access_rw_counter;
                                        _zkevm_states.push_back(end_call_state);
                                        append_cold_access_rw_operations();
                                        successful_call_finish_cold_access_update();
                                    }
                                }
                                if( opcode == "RETURN"){
                                    std::size_t offset = std::size_t(stack[stack.size()-1]); // Real value
                                    std::size_t length = std::size_t(stack[stack.size()-2]); // Real value
                                    zkevm_state end_call_state = _call_stack[_call_stack.size() - 1].state;
                                    std::size_t returndataoffset = _call_stack[_call_stack.size() - 1].returndataoffset; // caller CALL opcode parameters
                                    std::size_t returndatalength = _call_stack[_call_stack.size() - 1].returndatalength; // caller CALL opcode parameters
                                    append_cold_access_rw_operations();
                                    successful_call_finish_cold_access_update();
                                    // end_call_state.block_id = block_id;
                                    // end_call_state.tx_id = tx_id;
                                    // end_call_state.call_id = call_id;
                                    end_call_state.opcode = _call_stack.size() == 1? opcode_number_from_str("end_transaction") : opcode_number_from_str("end_call");
                                    // end_call_state.gas = 0;
                                    // end_call_state.pc = 0;
                                    // end_call_state.rw_counter = rw_counter;
                                    // end_call_state.bytecode_hash = 0;
                                    // end_call_state.additional_input = 0;
                                    // end_call_state.stack_size = 0;
                                    // end_call_state.memory_size = {};
                                    // end_call_state.stack_slice = {};
                                    end_call_state.last_access_rw_counter = last_access_rw_counter;
                                    end_call_state.last_write_rw_counter = last_write_rw_counter;
                                    _zkevm_states.push_back(end_call_state);
                                    call_id = end_call_state.call_id;
                                    memory_size_before = memory_next.size();
                                    bytecode_hash = end_call_state.bytecode_hash;
                                    call_context_address = end_call_state.call_context_address;
                                    if( call_id != 0 ){
                                        for(std::size_t i = 0; i < returndatalength; i++){
                                            _rw_operations.push_back(memory_rw_operation(
                                                call_id,
                                                returndataoffset+i,
                                                rw_counter++,
                                                true,
                                                offset+i < state.memory_size? state.memory(offset+i): 0
                                            ));
                                        }
                                    }
                                    // Push CALL status to stack
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                }
                                if( opcode == "REVERT"){
                                    std::size_t offset = std::size_t(stack[stack.size()-1]); // Real value
                                    std::size_t length = std::size_t(stack[stack.size()-2]); // Real value
                                    zkevm_state end_call_state = _call_stack[_call_stack.size() - 1].state;
                                    std::size_t returndataoffset = _call_stack[_call_stack.size() - 1].returndataoffset; // caller CALL opcode parameters
                                    std::size_t returndatalength = _call_stack[_call_stack.size() - 1].returndatalength; // caller CALL opcode parameters
                                    append_cold_access_rw_operations();
                                    unsuccessful_call_finish_cold_access_update();
                                    // end_call_state.block_id = block_id;
                                    // end_call_state.tx_id = tx_id;
                                    // end_call_state.call_id = call_id;
                                    end_call_state.opcode = _call_stack.size() == 1? opcode_number_from_str("end_transaction") : opcode_number_from_str("end_call");
                                    // end_call_state.gas = 0;
                                    // end_call_state.pc = 0;
                                    // end_call_state.rw_counter = rw_counter;
                                    // end_call_state.bytecode_hash = 0;
                                    // end_call_state.additional_input = 0;
                                    // end_call_state.stack_size = 0;
                                    // end_call_state.memory_size = {};
                                    // end_call_state.stack_slice = {};
                                    end_call_state.last_access_rw_counter = last_access_rw_counter;
                                    end_call_state.last_write_rw_counter = last_write_rw_counter;
                                    _zkevm_states.push_back(end_call_state);
                                    call_id = end_call_state.call_id;
                                    memory_size_before = memory_next.size();
                                    bytecode_hash = end_call_state.bytecode_hash;
                                    call_context_address = end_call_state.call_context_address;
                                    if( call_id != 0 ){
                                        for(std::size_t i = 0; i < returndatalength; i++){
                                            _rw_operations.push_back(memory_rw_operation(
                                                call_id,
                                                returndataoffset+i,
                                                rw_counter++,
                                                true,
                                                offset+i < state.memory_size? state.memory(offset+i): 0
                                            ));
                                        }
                                    }
                                    // Push CALL status to stack
                                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                                }
                                stack = stack_next;
                                memory = memory_next;
                            }
                        }
                        std::cout << "END BLOCK " << block_id << std::endl;
                        {
                            zkevm_state state;
                            state.block_id = block_id;
                            state.tx_id = 0;
                            state.call_id = 0;
                            state.opcode = opcode_number_from_str("end_block");
                            state.gas = 0;
                            state.pc = 0;
                            state.rw_counter = rw_counter;
                            state.bytecode_hash = 0; // TODO: fix it if possible
                            state.additional_input = 0;
                            state.stack_size = 0;
                            state.memory_size = {};
                            state.stack_slice = {};
                            _zkevm_states.push_back(state);
                            _accounts_initial_state = _accounts_current_state;
                            append_cold_access_rw_operations();
                            _call_stack.pop_back();
                        }
                    }

                    // std::cout << "RW operations before sorting" << std::endl;
                    // for( std::size_t i = 0; i < _rw_operations.size(); i++ ){
                    //     if( _rw_operations[i].op != rw_operation_type::padding )
                    //         std::cout << "\t" << _rw_operations[i] << std::endl;
                    // }
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
                void update_cold_access_list(
                    zkevm_word_type     address,
                    std::size_t         field_tag,
                    zkevm_word_type     storage_key,
                    const rw_operation  &rw_op
                ){
                    std::cout << "Update cold access RW operations depth = " << _call_stack.size() << std::endl;
                    std::size_t end = _call_stack.size() - 1;

                    if( !_call_stack[end].cold_access_list.count(std::make_tuple(address, field_tag, storage_key)) ){
                        _call_stack[end].cold_access_list[std::make_tuple(address, field_tag, storage_key)] = rw_op;
                    }
                    if( !rw_op.is_write ) return;
                    if( !_call_stack[end].cold_write_list.count(std::make_tuple(address, field_tag, storage_key)) ){
                        _call_stack[end].cold_write_list[std::make_tuple(address, field_tag, storage_key)] = rw_op;
                    }
                }

                void successful_call_finish_cold_access_update(){
                    auto &call = _call_stack.back();
                    _call_stack.pop_back();

                    std::size_t back = _call_stack.size() - 1;
                    if( back == 0 ) return;

                    for(auto &[k,v]: call.cold_access_list){
                        if( !_call_stack[back].cold_access_list.count(k) ) _call_stack[back].cold_access_list[k] = v;
                    }
                    for(auto &[k,v]: call.cold_write_list){
                        if( !_call_stack[back].cold_write_list.count(k) ) _call_stack[back].cold_write_list[k] = v;
                    }
                }

                void unsuccessful_call_finish_cold_access_update(){
                    _call_stack.pop_back();
                }

                void append_cold_access_rw_operations(){
                    std::cout << "Append cold access RW operations depth = " << _call_stack.size();
                    auto &call_context = _call_stack[_call_stack.size()-1];
                    std::size_t parent_id = _call_stack.size() == 1? 0 : _call_stack[_call_stack.size()-2].call_id;
                    std::cout << " parent_id = " << parent_id << std::endl;
                    std::size_t counter = 1;
                    for( auto &cold_access : call_context.cold_write_list ){
                        _rw_operations.push_back(
                            cold_access_rw_operation(
                                call_context.call_id,
                                counter++,
                                parent_id,
                                cold_access.second
                            )
                        );
                        std::cout << "\t" << cold_access.second << std::endl;
                    }
                    _rw_operations.push_back(
                        call_context_rw_operation(
                            call_context.call_id,
                            call_context_field::modified_items,
                            call_context.cold_write_list.size()
                        )
                    );
                }

                std::map<zkevm_word_type, zkevm_account>                _accounts_initial_state; // Initial state; Update it after block.
                std::map<zkevm_word_type, zkevm_account>                _accounts_current_state; // Initial state; Update it after block.
                std::vector<zkevm_call_context>                          _call_stack;

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