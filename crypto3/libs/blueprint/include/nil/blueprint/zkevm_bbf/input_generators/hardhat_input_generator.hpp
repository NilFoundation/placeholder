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
            protected:
                std::map<zkevm_word_type, zkevm_account>                _accounts_initial_state; // Initial state; Update it after block.
                std::map<zkevm_word_type, zkevm_account>                _accounts_current_state; // Initial state; Update it after block.
                std::vector<zkevm_call_context>                          _call_stack;

                zkevm_keccak_buffers                                     _keccaks;
                zkevm_keccak_buffers                                     _bytecodes;
                rw_operations_vector                                     _rw_operations;
                std::vector<copy_event>                                  _copy_events;
                std::vector<zkevm_state>                                 _zkevm_states;
                std::vector<std::pair<zkevm_word_type, zkevm_word_type>> _exponentiations;
                std::map<std::size_t,zkevm_call_commit>                   _call_commits;
                std::map<std::tuple<rw_operation_type, zkevm_word_type, std::size_t, zkevm_word_type>, std::size_t>  last_write_rw_counter;

                std::size_t     call_id;                // RW counter on start_call
                zkevm_word_type bytecode_hash;
                std::size_t     current_opcode;
                std::size_t     pc;
                std::size_t     stack_size;             // BEFORE opcode
                std::size_t     memory_size;            // BEFORE opcode
                std::size_t     rw_counter;
                std::size_t     gas;

                zkevm_word_type additional_input;

                // call_context_state_part;
                std::size_t tx_id;
                std::size_t block_id;
                std::size_t depth;
                zkevm_word_type tx_to;
                zkevm_word_type tx_from;
                zkevm_word_type tx_hash;
                zkevm_word_type block_hash;
                zkevm_word_type transaction_hash;
                zkevm_word_type call_context_address;
                std::vector<std::uint8_t> calldata;
                std::vector<std::uint8_t> returndata;

                // internal execution
                std::vector<zkevm_word_type> stack;
                std::vector<zkevm_word_type> stack_next;
                std::vector<std::uint8_t> memory;
                std::vector<std::uint8_t> memory_next;

                basic_zkevm_state_part get_basic_zkevm_state_part(){
                    basic_zkevm_state_part result;

                    result.call_id = call_id;
                    result.bytecode_hash = bytecode_hash;
                    result.opcode = current_opcode;
                    result.pc = pc;
                    result.stack_size = stack_size;             // BEFORE opcode
                    result.memory_size = memory_size;           // BEFORE opcode
                    result.rw_counter = rw_counter;
                    result.gas = gas;
                    result.stack_slice = stack;

                    return result;
                }
                call_header_zkevm_state_part get_call_header_state_part(){
                    call_header_zkevm_state_part result;
                    result.block_id = block_id;            // RW counter on start_block
                    result.tx_id = tx_id;                  // RW counter on start_transaction
                    result.block_hash = block_hash;
                    result.tx_hash = tx_hash;
                    result.call_context_address = call_context_address;
                    result.depth = depth;
                    result.calldata = calldata;

                    return result;
                }

                call_context_zkevm_state_part get_call_context_state_part(){
                    call_context_zkevm_state_part result;
                    result.lastcall_returndata_slice = _call_stack.back().returndata;
                    result.lastcall_returndataoffset = _call_stack.back().lastcall_returndataoffset;
                    result.lastcall_returndatalength = _call_stack.back().lastcall_returndatalength;
                    result.lastcall_id = _call_stack.back().lastcall_id;

                    return result;
                }

                world_state_zkevm_state_part get_world_state_state_part(){
                    world_state_zkevm_state_part result;
                    result.storage_slice = _accounts_current_state[call_context_address].storage;
                    result.modified_items = _call_stack.back().cold_write_list.size();;
                    result.last_write_rw_counter = last_write_rw_counter;
                    result.was_accessed = _call_stack.back().was_accessed;
                    result.was_written = _call_stack.back().was_written;

                    return result;
                }
            public:
                zkevm_hardhat_input_generator(
                    const boost::property_tree::ptree &tree
                ){
                    std::cout << "ZKEVM HARDHAT INPUT GENERATOR loaded" << std::endl;
                    // 1. Load eth_accounts
                    for( auto &account: tree.get_child("eth_accounts")){
                        std::cout  << "Account " << account.first.data() << std::endl;
                        zkevm_account acc;
                        acc.address = zkevm_word_from_string(account.second.get_child("address").data());
                        acc.balance = zkevm_word_from_string(account.second.get_child("balance").data());
                        acc.seq_no = acc.ext_seq_no = std::size_t(zkevm_word_from_string(account.second.get_child("nonce").data()));
                        _accounts_initial_state[acc.address] = acc;
                        std::cout << "Loaded" << std::endl;
                    }
                    std::cout << "Eth accounts loaded" << std::endl;
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
                    std::cout << "Accounts loaded" << std::endl;
                    for( auto &[k,v]: _accounts_initial_state){
                        std::cout << "0x" << std::hex << k << " => " << v << std::dec<< std::endl;
                    }
                    _accounts_current_state = _accounts_initial_state;
                    // 3. Initialize state variables
                    rw_counter = 1;
                    call_id = 0;
                    tx_id = 0;
                    block_id = 0;

                    // 3. Start block.
                    for( auto &pt: tree.get_child("blocks")){
                        start_block(pt.first.data(), pt.second);
                        execute_block(pt.second);
                        end_block(pt.second);
                        // TODO: Just for correct testing we propose that next block is after previous
                        _accounts_initial_state = _accounts_current_state;
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

                void start_block(zkevm_word_type _block_hash, const boost::property_tree::ptree &pt){
                    last_write_rw_counter.clear();
                    block_id = rw_counter++;
                    block_hash = _block_hash;
                    tx_id = 0;
                    depth = 1;
                    tx_hash = 0;

                    std::cout << "START BLOCK " << block_id << std::endl;
                    _zkevm_states.push_back(start_block_zkevm_state(block_hash, block_id));
                    _rw_operations.push_back(call_context_rw_operation(
                        block_id, call_context_field::parent_id, 0
                    ));
                    _rw_operations.push_back(call_context_rw_operation(
                        block_id, call_context_field::depth, 0
                    ));
                    _rw_operations.push_back(call_context_rw_operation(
                        block_id, call_context_field::hash, block_hash
                    ));
                    rw_counter += block_context_field_amount - 1;
                    _call_stack.push_back({_zkevm_states.back(), block_id});
                }

                void execute_block(const boost::property_tree::ptree &pt){
                    for( auto &tt: pt.get_child("transactions")){
                        start_transaction(tt.first.data(), tt.second);
                        execute_transaction(tt.second);
                        end_transaction(tt.second);
                    }
                }

                void end_block(const boost::property_tree::ptree &pt){
                    depth--;
                    std::cout << "END BLOCK " << block_id << std::endl;
                    _rw_operations.push_back(
                        call_context_rw_operation(
                            block_id,
                            call_context_field::end,
                            rw_counter - 1
                        )
                    );
                    _zkevm_states.push_back(end_block_zkevm_state(block_id, rw_counter));
                    _call_stack.pop_back();
                }

                void start_transaction(std::string _tx_hash, const boost::property_tree::ptree &tt){
                    depth++;
                    tx_id = rw_counter;
                    call_id = rw_counter;
                    tx_to = zkevm_word_from_string(tt.get_child("tx").get_child("to").data());
                    tx_from = zkevm_word_from_string(tt.get_child("tx").get_child("from").data());
                    tx_hash = zkevm_word_from_string(_tx_hash);
                    current_opcode = opcode_to_number(zkevm_opcode::start_transaction);
                    bytecode_hash = _accounts_initial_state[tx_to].code_hash;
                    call_context_address = tx_to;
                    calldata = byte_vector_from_hex_string(tt.get_child("tx").get_child("data").data(), 2);
                    std::cout << "START TRANSACTION " << tx_id << " to " << std::hex << tx_to << std::dec << std::endl;

                    auto base = get_basic_zkevm_state_part();
                    auto call_context = get_call_header_state_part();

                    _zkevm_states.push_back(zkevm_state(base, call_context));
                    _call_stack.push_back({_zkevm_states.back(), call_id, 0, 0, 0, calldata});

                    _rw_operations.push_back(call_context_rw_operation(
                        tx_id, call_context_field::parent_id, block_id
                    ));
                    _rw_operations.push_back(call_context_rw_operation(
                        tx_id, call_context_field::depth, 1
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
                    _rw_operations.push_back(call_context_rw_operation(
                        tx_id, call_context_field::hash, tx_hash
                    ));
                    _rw_operations.push_back(call_context_rw_operation(
                        tx_id, call_context_field::calldata_size, calldata.size()
                    ));
                    rw_counter += call_context_readonly_field_amount;
                    for( std::size_t i = 0; i < calldata.size(); i++){
                        _rw_operations.push_back(calldata_rw_operation(
                            tx_id, i, rw_counter++, calldata[i]
                        ));
                    }
                }
                void execute_transaction(const boost::property_tree::ptree &tt){
                    stack = {};
                    memory = {};
                    stack_next = {};
                    memory_next = {};
                    auto ptrace = tt.get_child("trace.structLogs");
                    for( auto it = ptrace.begin(); it!=ptrace.end(); it++){
                        std::string opcode = it->second.get_child("op").data();
                        current_opcode = opcode_number_from_str(opcode);
                        for( std::size_t i = 1; i < depth; i++) std::cout << "\t";

                        if(std::distance(it, ptrace.end()) != 1){
                            stack_next = zkevm_word_vector_from_ptree(std::next(it)->second.get_child("stack"));
                            memory_next = byte_vector_from_ptree(std::next(it)->second.get_child("memory"));
                        }
                        memory_size = memory.size();
                        additional_input = opcode.substr(0,4) == "PUSH"? stack_next[stack_next.size() - 1]: 0;
                        stack_size = stack.size();
                        gas = atoi(it->second.get_child("gas").data().c_str());
                        pc = atoi(it->second.get_child("pc").data().c_str());

                        std::cout  << opcode
                            << " call_id = " << call_id
                            << " memory_size = " << memory_size
                            << " stack_size = " << stack_size
                            << " rw_counter = " << rw_counter
                            << " gas = " << gas
                            << " pc = " << pc
                            << std::endl;

                        if(opcode == "STOP") { stop(); if(depth > 2) end_call();}
                        else if(
                            opcode == "ADD" || opcode == "MUL" || opcode == "SUB" || opcode == "DIV" ||
                            opcode == "SDIV" || opcode == "MOD" || opcode == "SMOD" ||  opcode == "SIGNEXTEND" ||
                            opcode == "LT" || opcode == "GT"   || opcode == "SLT" || opcode == "SGT" || opcode == "SGT" ||
                            opcode == "EQ"  || opcode == "AND" || opcode == "OR"  || opcode == "XOR" || opcode == "BYTE" ||
                            opcode == "SHL" || opcode == "SHR" || opcode == "SAR"
                        ) {
                            two_operands_arithmetic();
                        } else if(
                            opcode == "ADDMOD" ||
                            opcode == "MULMOD"
                        ) {
                            three_operands_arithmetic();
                        } else if(
                            opcode == "ISZERO" ||
                            opcode == "NOT"
                        ) {
                            one_operand_arithmetic();
                        } else if( opcode == "EXP" )     exp();
                        else if( opcode == "KECCAK256" ) keccak();
                        else if( opcode == "ADDRESS" )   address();
                        else if( opcode == "BALANCE" )   balance();
                        else if( opcode == "ORIGIN" )    origin();
                        else if( opcode == "CALLER" )    caller();
                        else if( opcode == "CALLVALUE" ) callvalue();
                        else if( opcode == "CALLDATALOAD" ) calldataload();
                        else if( opcode == "CALLDATASIZE" ) calldatasize();
                        else if( opcode == "CALLDATACOPY" ) calldatacopy();
                        else if( opcode == "CODESIZE" ) codesize();
                        else if( opcode == "CODECOPY" ) codecopy();
                        else if( opcode == "GASPRICE" ) gasprice();
                        else if( opcode == "RETURNDATASIZE" ) returndatasize();
                        else if( opcode == "RETURNDATACOPY" ) returndatacopy();
                        else if( opcode == "EXTCODESIZE" ) extcodesize();
                        else if(
                            opcode == "EXTCODESIZE" ||
                            opcode == "EXTCODECOPY" ||
                            opcode == "EXTCODEHASH" ||
                            opcode == "BLOCKHASH" ||
                            opcode == "COINBASE" ||
                            opcode == "TIMESTAMP" ||
                            opcode == "NUMBER" ||
                            opcode == "DIFFICULTY" ||
                            opcode == "GASLIMIT" ||
                            opcode == "CHAINID" ||
                            opcode == "SELFBALANCE" ||
                            opcode == "BASEFEE" ||
                            opcode == "BLOBHASH" ||
                            opcode == "BLOBBASEFEE" ||
                            opcode == "TLOAD" ||
                            opcode == "TSTORE" ||
                            opcode == "MCOPY" ||
                            opcode == "CREATE" ||
                            opcode == "CREATE2" ||
                            opcode == "SELFDESTRUCT" ||
                            opcode == "CALLCODE" ||
                            opcode == "STATICCALL"
                        ) not_implemented();
                        else if( opcode == "POP" || opcode == "JUMPDEST" ) simple_dummy();
                        else if( opcode == "MLOAD" ) mload();
                        else if( opcode == "MSTORE" ) mstore();
                        else if( opcode == "MSTORE8" ) mstore8();
                        else if( opcode == "SLOAD" ) sload();
                        else if( opcode == "SSTORE" ) sstore();
                        else if( opcode == "JUMP" ) jump();
                        else if( opcode == "JUMPI" ) jumpi();
                        else if(
                            opcode == "PC" ||
                            opcode == "MSIZE" ||
                            opcode == "GAS"
                        ) one_push_to_stack();
                        else if(opcode.substr(0,4) == "PUSH") push_opcode();
                        else if(opcode == "DUP1") dupx(1);
                        else if(opcode == "DUP2") dupx(2);
                        else if(opcode == "DUP3") dupx(3);
                        else if(opcode == "DUP4") dupx(4);
                        else if(opcode == "DUP5") dupx(5);
                        else if(opcode == "DUP6") dupx(6);
                        else if(opcode == "DUP7") dupx(7);
                        else if(opcode == "DUP8") dupx(8);
                        else if(opcode == "DUP9") dupx(9);
                        else if(opcode == "DUP10") dupx(10);
                        else if(opcode == "DUP11") dupx(11);
                        else if(opcode == "DUP12") dupx(12);
                        else if(opcode == "DUP13") dupx(13);
                        else if(opcode == "DUP14") dupx(14);
                        else if(opcode == "DUP15") dupx(15);
                        else if(opcode == "DUP16") dupx(16);
                        else if(opcode == "SWAP1") swapx(1);
                        else if(opcode == "SWAP2") swapx(2);
                        else if(opcode == "SWAP3") swapx(3);
                        else if(opcode == "SWAP4") swapx(4);
                        else if(opcode == "SWAP5") swapx(5);
                        else if(opcode == "SWAP6") swapx(6);
                        else if(opcode == "SWAP7") swapx(7);
                        else if(opcode == "SWAP8") swapx(8);
                        else if(opcode == "SWAP9") swapx(9);
                        else if(opcode == "SWAP10") swapx(10);
                        else if(opcode == "SWAP11") swapx(11);
                        else if(opcode == "SWAP12") swapx(12);
                        else if(opcode == "SWAP13") swapx(13);
                        else if(opcode == "SWAP14") swapx(14);
                        else if(opcode == "SWAP15") swapx(15);
                        else if(opcode == "SWAP16") swapx(16);
                        else if(opcode == "LOG0") logx(0);
                        else if(opcode == "LOG1") logx(1);
                        else if(opcode == "LOG2") logx(2);
                        else if(opcode == "LOG3") logx(3);
                        else if(opcode == "LOG4") logx(4);
                        else if(opcode == "CALL") { call(); start_call();}
                        else if(opcode == "RETURN"){ return_opcode(); if(depth > 2) end_call();}
                        else if(opcode == "DELEGATECALL") { delegatecall(); start_call();}
                        else if (opcode == "REVERT"){ revert(); if(depth > 2) end_call(); }
                        else {
                            std::cout << "Input generator does not support " << opcode << std::endl;
                        }

                        stack = stack_next;
                        memory = memory_next;
                    }
                }

                void end_transaction(const boost::property_tree::ptree &tt){
                    append_modified_items_rw_operations();
                    std::cout << "END TRANSACTION " << tx_id << std::endl;
                    current_opcode = opcode_to_number(zkevm_opcode::end_transaction);

                    auto base = get_basic_zkevm_state_part();
                    auto call_context = get_call_header_state_part();
                    auto returned_call = _call_stack.back();
                    _call_stack.pop_back();
                    depth--;
                    _zkevm_states.push_back(zkevm_state(base, call_context));
                    std::size_t returndataoffset = _call_stack.back().lastcall_returndataoffset; // caller CALL opcode parameters
                    std::size_t returndatalength = _call_stack.back().lastcall_returndatalength; // caller CALL opcode parameters
                    std::size_t subcall_id = call_id;

                    std::cout << "end_call";
                    std::cout << "\treturndataoffset = " << std::hex << returndataoffset;
                    std::cout << "\treturndataoffset = " << std::hex << returndatalength;
                    std::cout << "\tsubcall_id = " << std::hex << subcall_id << std::endl;
                    std::cout << std::dec <<std::endl;

                    memory_size = memory_next.size();
                    bytecode_hash = returned_call.state.bytecode_hash();
                    call_context_address = returned_call.state.call_context_address();
                    // If it is not transaction, move callee's returndata to callers memory
                    if( _call_stack.size() > 1 ){
                        _rw_operations.push_back(call_context_r_operation(
                            call_id,
                            call_context_field::lastcall_returndata_length,
                            rw_counter++,
                            returndatalength
                        ));
                        _rw_operations.push_back(call_context_r_operation(
                            call_id,
                            call_context_field::lastcall_returndata_offset,
                            rw_counter++,
                            returndataoffset
                        ));
                        _rw_operations.push_back(call_context_r_operation(
                            call_id,
                            call_context_field::lastcall_id,
                            rw_counter++,
                            subcall_id
                        ));
                        copy_event cpy = end_call_copy_event(
                            call_id,
                            returndataoffset,
                            subcall_id,
                            rw_counter,
                            returndatalength
                        );
                        for(std::size_t i = 0; i < returndatalength; i++){
                            _rw_operations.push_back(returndata_rw_operation(
                                subcall_id,
                                i,
                                rw_counter++,
                                i < returned_call.returndata.size()? returned_call.returndata[i]: 0
                            ));
                        }
                        for(std::size_t i = 0; i < returndatalength; i++){
                            _rw_operations.push_back(memory_rw_operation(
                                call_id,
                                returndataoffset+i,
                                rw_counter++,
                                true,
                                i < returned_call.returndata.size()? returned_call.returndata[i]: 0
                            ));
                            cpy.push_byte(std::size_t(i <returned_call.returndata.size()? returned_call.returndata[i]: 0));
                        }
                        _call_stack.back().returndata = returned_call.returndata;
                        _copy_events.push_back(cpy);
                    }
                }

                void stop(){
                    _call_stack.back().end = rw_counter - 1;
                    _call_stack.back().returndata = {};
                    _rw_operations.push_back(
                        call_context_rw_operation(
                            call_id,
                            call_context_field::end,
                            rw_counter - 1
                        )
                    );
                    _rw_operations.push_back(
                        call_context_rw_operation(
                            call_id,
                            call_context_field::returndata_size,
                            0
                        )
                    );
                    _zkevm_states.push_back(call_header_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part()));
                    if( _call_stack.size() > 2 ){
                        _call_stack[_call_stack.size() - 2].was_accessed.insert(_call_stack.back().was_accessed.begin(), _call_stack.back().was_accessed.end());
                        _call_stack[_call_stack.size() - 2].was_written.insert(_call_stack.back().was_written.begin(), _call_stack.back().was_written.end());
                    }
                }

                void one_operand_arithmetic(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                }

                void two_operands_arithmetic(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                }

                void three_operands_arithmetic(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-3]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                }

                void exp(){
                    two_operands_arithmetic();
                    _exponentiations.push_back({stack[stack.size() - 1], stack[stack.size() - 2]});
                }

                void keccak(){
                    _zkevm_states.push_back(memory_zkevm_state(get_basic_zkevm_state_part(), memory));
                    memory_size = memory_next.size();
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));

                    std::size_t length = std::size_t(stack[stack.size()-2]);
                    std::size_t  offset = std::size_t(stack[stack.size()-1]);
                    auto hash_value = stack_next[stack_next.size()-1];

                    std::cout << "\tAdd copy event for KECCAK256 length = " << length << std::endl;
                    auto cpy = keccak_copy_event(
                        call_id, offset, rw_counter, hash_value, length
                    );

                    std::size_t offset_small = w_to_16(offset)[15];
                    for( std::size_t i = 0; i < length; i++){
                        _rw_operations.push_back(memory_rw_operation(call_id, offset+i, rw_counter++, false, memory_next[offset_small + i]));
                        cpy.push_byte(memory_next[offset_small + i]);
                    }
                    _copy_events.push_back(cpy);
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, hash_value));
                    _keccaks.new_buffer(cpy.get_bytes());
                }
                void address(){
                    _zkevm_states.push_back(call_header_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part()));
                    std::cout << "Test ADDRESS opcode, please!" << std::endl;
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                }
                void balance(){
                    _zkevm_states.push_back(call_header_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part()));
                    std::cout << "Test BALANCE opcode, please!" << std::endl;
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                    // TODO:  add read operations from account
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                }
                void origin(){
                    _zkevm_states.push_back(call_header_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part()));
                    std::cout << "Test ORIGIN opcode, please!" << std::endl;
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                }
                void caller(){
                    _zkevm_states.push_back(call_header_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part()));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                }
                void callvalue(){
                    _zkevm_states.push_back(call_header_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part()));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                }
                void calldataload(){
                    _zkevm_states.push_back(call_header_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part()));
                    std::size_t offset = std::size_t(stack[stack.size()-1]);
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, offset));
                    for( std::size_t i = 0; i < 32; i++){
                        auto byte = offset+i < _call_stack.back().calldata.size()? std::size_t(_call_stack.back().calldata[offset+i]) : 0;
                        _rw_operations.push_back(calldata_rw_operation(
                            call_id, offset + i, rw_counter++, byte
                        ));
                    }
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                }
                void calldatasize(){
                    _zkevm_states.push_back(call_header_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part()));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, _call_stack.back().calldata.size()));
                }
                void calldatacopy(){
                    _zkevm_states.push_back(call_header_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part()));
                    memory_size = memory_next.size();
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-3, rw_counter++, false, stack[stack.size()-3]));

                    std::size_t length = std::size_t(stack[stack.size()-3]);
                    std::size_t src = std::size_t(stack[stack.size()-2]);
                    std::size_t dst = std::size_t(stack[stack.size()-1]);
                    // std::cout << "Memory_size " << memory.size() << "=>" << memory_next.size() << std::endl;

                    copy_event cpy = calldatacopy_copy_event(
                        call_id,
                        src,
                        dst,
                        rw_counter,
                        length
                    );

                    for( std::size_t i = 0; i < length; i++){
                        _rw_operations.push_back(calldata_rw_operation(call_id, src+i, rw_counter++, memory_next[dst+i]));
                    }
                    for( std::size_t i = 0; i < length; i++){
                        _rw_operations.push_back(memory_rw_operation(call_id, dst+i, rw_counter++, true, memory_next[dst+i]));
                        cpy.push_byte(memory_next[dst+i]);
                    }
                    _copy_events.push_back(cpy);
                }
                void codesize(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                }
                void codecopy(){
                    memory_size = memory_next.size();
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
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
                    for(std::size_t i = 0; i < length; i++){
                        _rw_operations.push_back(memory_rw_operation(call_id, destination_offset+i, rw_counter++, true, _bytecodes.get_data()[call_id].first[std::size_t(code_offset) + i]));
                    }
                }
                void gasprice(){
                    _zkevm_states.push_back(call_header_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part()));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                }
                void extcodesize(){
                    _zkevm_states.push_back(call_header_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part()));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                    // TODO: get result from the world state
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                }
                void extcodecopy(){
                    _zkevm_states.push_back(call_header_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part()));
                    std::cout << "EXTCODECOPY not implemented" << std::endl;
                    exit(2);
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-3, rw_counter++, false, stack[stack.size()-3]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-4, rw_counter++, false, stack[stack.size()-4]));
                }
                void returndatasize(){
                    _zkevm_states.push_back(returndata_zkevm_state(
                        get_basic_zkevm_state_part(),
                        memory,
                        get_call_context_state_part()
                    ));
                    _rw_operations.push_back(call_context_r_operation(call_id, call_context_field::lastcall_id, rw_counter++, _call_stack.back().lastcall_id));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                }
                void returndatacopy(){
                    _zkevm_states.push_back(returndata_zkevm_state(
                        get_basic_zkevm_state_part(),
                        memory,
                        get_call_context_state_part()
                    ));
                    memory_size = memory_next.size();
                    auto dest_offset = std::size_t(stack[stack.size()-1]);
                    auto offset = std::size_t(stack[stack.size()-2]);
                    auto length = std::size_t(stack[stack.size()-3]);
                    auto lastcall_id = std::size_t(_call_stack.back().lastcall_id);
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, dest_offset));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, offset));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-3, rw_counter++, false, length));

                    _rw_operations.push_back(
                        call_context_r_operation(
                            call_id, call_context_field::lastcall_id, rw_counter++, lastcall_id
                        )
                    );
                    copy_event cpy = returndatacopy_copy_event(
                        lastcall_id, offset, call_id, dest_offset, rw_counter, length
                    );
                    for( std::size_t ind = 0; ind < length; ind++){
                        _rw_operations.push_back(
                            returndata_rw_operation(
                                lastcall_id, offset+ind, rw_counter++,
                                offset+ind < _call_stack.back().returndata.size()? _call_stack.back().returndata[offset+ind] : 0
                            )
                        );
                        cpy.push_byte(offset+ind < _call_stack.back().returndata.size()? _call_stack.back().returndata[offset+ind] : 0);
                    }
                    for( std::size_t ind = 0; ind < length; ind++){
                        _rw_operations.push_back(
                            memory_rw_operation(
                                call_id, dest_offset+ind, rw_counter++, true, memory_next[std::size_t(dest_offset+ind)]
                            )
                        );
                    }
                    _copy_events.push_back(cpy);
                }
                void mload(){
                    _zkevm_states.push_back(memory_zkevm_state(get_basic_zkevm_state_part(), memory));
                    memory_size = memory_next.size();
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, false, stack[stack.size()-1]));

                    zkevm_word_type addr = stack[stack.size() - 1];
                    BOOST_ASSERT_MSG(addr < std::numeric_limits<std::size_t>::max(), "Cannot process so large memory address");
                    // std::cout << "\t\t Address = 0x" << std::hex << addr << std::dec << " memory size " << memory.size() << std::endl;
                    for( std::size_t i = 0; i < 32; i++){
                        _rw_operations.push_back(memory_rw_operation(call_id, addr+i, rw_counter++, false, addr+i < memory.size() ? memory[std::size_t(addr+i)]: 0));

                    }
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                }
                void mstore(){
                    _zkevm_states.push_back(memory_zkevm_state(get_basic_zkevm_state_part(), memory));
                    memory_size = memory_next.size();
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));

                    zkevm_word_type addr = stack[stack.size() - 1];
                    BOOST_ASSERT_MSG(addr < std::numeric_limits<std::size_t>::max(), "Cannot process so large memory address");
                    // std::cout << "\t\t Address = 0x" << std::hex << addr << std::dec << " memory size " << memory.size() << std::endl;
                    auto bytes = w_to_8(stack[stack.size() - 2]);
                    for( std::size_t i = 0; i < 32; i++){
                        _rw_operations.push_back(memory_rw_operation(call_id, addr + i, rw_counter++, true, bytes[i]));
                    }
                }
                void mstore8(){
                    _zkevm_states.push_back(memory_zkevm_state(get_basic_zkevm_state_part(), memory));
                    memory_size = memory_next.size();
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));

                    zkevm_word_type addr = stack[stack.size() - 1];
                    BOOST_ASSERT_MSG(addr < std::numeric_limits<std::size_t>::max(), "Cannot process so large memory address");
                    // std::cout << "\t\t Address = 0x" << std::hex << addr << std::dec << " memory size " << memory.size() << std::endl;
                    auto bytes = w_to_8(stack[stack.size() - 2]);
                    _rw_operations.push_back(memory_rw_operation(call_id, addr, rw_counter++, true, bytes[31]));;
                }
                void sload(){
                    _zkevm_states.push_back(storage_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part(), get_world_state_state_part()));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, false, stack[stack.size()-1]));
                    auto storage_key = stack[stack.size() - 1];
                    _rw_operations.push_back(
                        access_list_rw_operation(
                            tx_id,
                            call_context_address,
                            0,
                            storage_key,
                            rw_counter++,
                            true,
                            _call_stack.back().was_written.contains(std::make_tuple(call_context_address, 0, storage_key)) ? 2: 1,
                            call_id,
                            std::size_t(_call_stack.back().was_accessed.contains(std::make_tuple(call_context_address, 0, storage_key))) +
                            std::size_t(_call_stack.back().was_written.contains(std::make_tuple(call_context_address, 0, storage_key))),
                            last_write_rw_counter.count(std::make_tuple(rw_operation_type::access_list, call_context_address, 0, storage_key)) ? last_write_rw_counter[std::make_tuple(rw_operation_type::access_list, call_context_address, 0, storage_key)]: 0
                        )
                    );
                    last_write_rw_counter[std::make_tuple(rw_operation_type::access_list, call_context_address, 0, storage_key)] = rw_counter-1;
                    update_modified_items_list(rw_operation_type::access_list, call_context_address,0, storage_key, _rw_operations[_rw_operations.size()-1]);
                    _call_stack.back().was_accessed.insert(std::make_tuple(call_context_address, 0, storage_key));

                    _rw_operations.push_back(storage_rw_operation(
                        block_id,
                        call_context_address,
                        storage_key, //Storage key
                        rw_counter++,
                        false,
                        _accounts_current_state[call_context_address].storage[storage_key],
                        _accounts_initial_state[call_context_address].storage[storage_key],
                        call_id,
                        last_write_rw_counter.count(std::make_tuple(rw_operation_type::state, call_context_address, 0, storage_key)) == 0 ? 0 : last_write_rw_counter[std::make_tuple(rw_operation_type::state, call_context_address, 0, storage_key)],
                        _accounts_current_state[call_context_address].storage[storage_key]
                    ));
                    std::cout << _rw_operations[_rw_operations.size()-1] << std::endl;
                    update_modified_items_list(rw_operation_type::state, call_context_address,0, storage_key, _rw_operations[_rw_operations.size()-1]);
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));

                }

                void sstore(){
                    _zkevm_states.push_back(storage_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part(), get_world_state_state_part()));
                    auto storage_key = stack[stack.size() - 1];
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, storage_key));
                    std::cout << _rw_operations[_rw_operations.size()-1] << std::endl;
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                    auto value = stack[stack.size() - 2];
                    std::cout << "Value_after = " << value << std::endl;
                    _rw_operations.push_back(
                        access_list_rw_operation(
                            tx_id,
                            call_context_address,
                            0,
                            storage_key,
                            rw_counter++,
                            true,
                            2,
                            call_id,
                            std::size_t(_call_stack.back().was_accessed.contains(std::make_tuple(call_context_address, 0, storage_key))) +
                            std::size_t(_call_stack.back().was_written.contains(std::make_tuple(call_context_address, 0, storage_key))),
                            last_write_rw_counter.count(std::make_tuple(rw_operation_type::access_list, call_context_address, 0, storage_key)) ? last_write_rw_counter[std::make_tuple(rw_operation_type::access_list, call_context_address, 0, storage_key)]: 0
                        )
                    );
                    last_write_rw_counter[std::make_tuple(rw_operation_type::access_list, call_context_address, 0, storage_key)] = rw_counter-1;
                    update_modified_items_list(rw_operation_type::access_list, call_context_address,0, storage_key, _rw_operations[_rw_operations.size()-1]);
                    _call_stack.back().was_accessed.insert(std::make_tuple(call_context_address, 0, storage_key));
                    _call_stack.back().was_written.insert(std::make_tuple(call_context_address, 0, storage_key));

                    _rw_operations.push_back(storage_rw_operation(
                        block_id,
                        call_context_address,
                        storage_key,
                        rw_counter++,
                        true,
                        value,
                        _accounts_initial_state[call_context_address].storage[storage_key], // initial value
                        call_id,                                                            // For REVERT correctness
                        last_write_rw_counter.count(std::make_tuple(rw_operation_type::state, call_context_address, 0, storage_key)) == 0 ? 0 : last_write_rw_counter[std::make_tuple(rw_operation_type::state, call_context_address, 0, storage_key)],
                        _accounts_current_state[call_context_address].storage[storage_key]
                    )); // Second parameter should be transaction_id
                    last_write_rw_counter[std::make_tuple(rw_operation_type::state, call_context_address, 0, storage_key)] = rw_counter-1;
                    _accounts_current_state[call_context_address].storage[storage_key] = value;
                    std::cout << _rw_operations[_rw_operations.size()-1] << std::endl;
                    update_modified_items_list(rw_operation_type::state, call_context_address,0, storage_key, _rw_operations[_rw_operations.size()-1]);
                }
                void jump(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                }
                void jumpi(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                }
                void one_push_to_stack(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, stack_next[stack_next.size()-1]));
                }
                void push_opcode(){
                    _zkevm_states.push_back(push_zkevm_state(get_basic_zkevm_state_part(), additional_input));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, stack_next[stack_next.size()-1]));
                }
                void dupx(std::size_t d){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-d, rw_counter++, false, stack[stack.size()-d]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                }
                void swapx(std::size_t s){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size() - s - 1, rw_counter++, false, stack[stack.size() - s - 1]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size() - s - 1, rw_counter++, true, stack_next[stack_next.size()- s - 1]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                }
                void logx( std::size_t l){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                    for( std::size_t i = 0; i < l; i++){
                        _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-3-i, rw_counter++, false, stack[stack.size()-3-i]));
                    }
                }

                void call(){
                    _zkevm_states.push_back(call_header_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part()));
                    std::size_t args_offset = std::size_t(stack[stack.size() - 4]);
                    std::size_t args_length = std::size_t(stack[stack.size() - 5]);
                    std::size_t returndataoffset = std::size_t(stack[stack.size()-6]);
                    std::size_t returndatalength = std::size_t(stack[stack.size()-7]);
                    _call_stack.back().lastcall_returndataoffset = returndataoffset;
                    _call_stack.back().lastcall_returndatalength = returndatalength;
                    _call_stack.back().args_offset = args_offset;
                    _call_stack.back().args_length = args_length;
                    std::cout << "\treturndataoffset = " << std::hex << returndataoffset;
                    std::cout << "\treturndataoffset = " << std::hex << returndatalength;
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-3, rw_counter++, false, stack[stack.size()-3]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-4, rw_counter++, false, args_offset));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-5, rw_counter++, false, args_length));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-6, rw_counter++, false, returndataoffset));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-7, rw_counter++, false, returndatalength));
                    _rw_operations.push_back(call_context_w_operation(call_id, call_context_field::lastcall_returndata_offset, rw_counter++, returndataoffset));
                    _rw_operations.push_back(call_context_w_operation(call_id, call_context_field::lastcall_returndata_length, rw_counter++, returndatalength));
                    call_context_address = stack[stack.size()-2];
                    for( std::size_t i = 0; i < args_length; i++){
                        _rw_operations.push_back(memory_rw_operation(
                            call_id, args_offset + i, rw_counter++, false,
                            args_offset + i < memory.size() ? memory[args_offset + i]: 0
                        ));
                    }
                    size_t subcall_id = rw_counter + 1;
                    std::cout << "\tsubcallid = " << std::hex << subcall_id << std::dec << std::endl;
                    _rw_operations.push_back(call_context_w_operation(call_id, call_context_field::lastcall_id, rw_counter++, subcall_id));
                    _call_stack.back().lastcall_id = subcall_id;
                }
                void delegatecall(){
                    _zkevm_states.push_back(call_header_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part()));
                    memory_size = memory_next.size();
                    std::size_t args_offset = std::size_t(stack[stack.size() - 3]);
                    std::size_t args_length = std::size_t(stack[stack.size() - 4]);
                    std::size_t returndataoffset = std::size_t(stack[stack.size()-5]);
                    std::size_t returndatalength = std::size_t(stack[stack.size()-6]);

                    _call_stack.back().lastcall_returndataoffset = returndataoffset;
                    _call_stack.back().lastcall_returndatalength = returndatalength;
                    _call_stack.back().args_offset = args_offset;
                    _call_stack.back().args_length = args_length;
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, stack[stack.size()-2]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-3, rw_counter++, false, args_offset));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-4, rw_counter++, false, args_length));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-5, rw_counter++, false, returndataoffset));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-6, rw_counter++, false, returndatalength));
                    _rw_operations.push_back(call_context_w_operation(call_id, call_context_field::lastcall_returndata_offset, rw_counter++, returndataoffset));
                    _rw_operations.push_back(call_context_w_operation(call_id, call_context_field::lastcall_returndata_length, rw_counter++, returndatalength));
                    for( std::size_t i = 0; i < args_length; i++){
                        _rw_operations.push_back(memory_rw_operation(
                            call_id, args_offset + i, rw_counter++, false,
                            args_offset + i < memory.size()? memory[args_offset + i]: 0
                        ));
                    }
                    size_t subcall_id = rw_counter + 1;
                    std::cout << "\tsubcallid = " << std::hex << subcall_id << std::dec << std::endl;
                    _rw_operations.push_back(call_context_w_operation(call_id, call_context_field::lastcall_id, rw_counter++, subcall_id));
                    _call_stack.back().lastcall_id = subcall_id;
                }
                void return_opcode(){
                    _zkevm_states.push_back(call_header_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part()));
                    _call_stack.back().end = rw_counter - 1;
                    _rw_operations.push_back(
                        call_context_rw_operation(
                            call_id,
                            call_context_field::end,
                            rw_counter - 1
                        )
                    );
                    std::cout << "RETURN " << "\tAdd copy event for RETURN" << std::endl;
                    std::size_t offset = std::size_t(stack[stack.size()-1]);
                    std::size_t length = std::size_t(stack[stack.size()-2]);
                    _rw_operations.push_back(
                        call_context_rw_operation(
                            call_id,
                            call_context_field::returndata_size,
                            length
                        )
                    );
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, offset));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, length));
                    copy_event cpy = return_copy_event(
                        call_id,
                        offset,
                        rw_counter,
                        length
                    );
                    std::cout << "\tRETURN length = " << length << " memory size = " << memory.size() << " offset = " << offset << std::endl;
                    std::cout << "\tInitial RW counter = " << std::hex << rw_counter << std::dec << std::endl;
                    std::vector<std::uint8_t> returndata;
                    for(std::size_t i = 0; i < length; i++){
                        returndata.push_back(offset+i < memory.size() ? memory[offset+i]: 0);
                    }
                    _call_stack.back().returndata = returndata;
                    for(std::size_t i = 0; i < length; i++){
                        _rw_operations.push_back(memory_rw_operation(call_id, offset+i, rw_counter++, false, returndata[i]));
                    }
                    for(std::size_t i = 0; i < length; i++){
                        _rw_operations.push_back(returndata_rw_operation(call_id, i, rw_counter++, returndata[i]));
                        cpy.push_byte(returndata[i]);
                    }
                    _copy_events.push_back(cpy);
                    if( _call_stack.size() > 2 ){
                        _call_stack[_call_stack.size() - 2].was_accessed.insert(_call_stack.back().was_accessed.begin(), _call_stack.back().was_accessed.end());
                        _call_stack[_call_stack.size() - 2].was_written.insert(_call_stack.back().was_written.begin(), _call_stack.back().was_written.end());
                    }
                }
                void revert(){
                    _zkevm_states.push_back(end_call_zkevm_state(
                        get_basic_zkevm_state_part(),
                        get_call_header_state_part(),
                        get_call_context_state_part(),
                        get_world_state_state_part()
                    ));
                    std::size_t offset = std::size_t(stack[stack.size()-1]);    // Offset for returned data
                    std::size_t length = std::size_t(stack[stack.size()-2]);    // Length for returned data

                    _call_stack.back().end = rw_counter - 1;
                    _rw_operations.push_back(
                        call_context_rw_operation(
                            call_id,
                            call_context_field::end,
                            rw_counter - 1
                        )
                    );
                    _rw_operations.push_back(
                        call_context_rw_operation(
                            call_id,
                            call_context_field::returndata_size,
                            length
                        )
                    );

                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, offset));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-2, rw_counter++, false, length));

                    // Append copy event for reverted items
                    auto rev_length = _call_stack.back().cold_write_list.size();
                    auto cpy = revert_copy_event(
                        call_id,
                        block_id,
                        rw_counter,
                        rev_length
                    );
                    for( auto &modified_items : _call_stack.back().cold_write_list){
                        if( modified_items.second.op == rw_operation_type::state ){
                            _rw_operations.push_back(
                                rw_operation(
                                    modified_items.second.op,
                                    modified_items.second.id,
                                    modified_items.second.address,
                                    modified_items.second.field,
                                    modified_items.second.storage_key,
                                    rw_counter++,
                                    true,
                                    modified_items.second.value_before,
                                    _accounts_current_state[modified_items.second.address].storage[modified_items.second.storage_key],
                                    last_write_rw_counter[modified_items.first],
                                    call_id,
                                    modified_items.second.initial_value,
                                    0, // root_before
                                    0  // root_after
                                )
                            );
                            _accounts_current_state[modified_items.second.address].set(
                                modified_items.second.field, modified_items.second.storage_key, modified_items.second.value_before
                            );
                        } else if ( modified_items.second.op == rw_operation_type::access_list ) {
                            _rw_operations.push_back(
                                rw_operation(
                                    modified_items.second.op,
                                    modified_items.second.id,
                                    modified_items.second.address,
                                    modified_items.second.field,
                                    modified_items.second.storage_key,
                                    rw_counter++,
                                    true,
                                    modified_items.second.value_before,
                                    std::size_t(_call_stack.back().was_accessed.contains({modified_items.second.address, modified_items.second.field,modified_items.second.storage_key}))+
                                    std::size_t(_call_stack.back().was_written.contains({modified_items.second.address, modified_items.second.field,modified_items.second.storage_key})),
                                    last_write_rw_counter[modified_items.first],
                                    call_id,
                                    modified_items.second.initial_value,
                                    0, // root_before
                                    0  // root_after
                                )
                            );
                        }
                        // Change state on other kind of changes
                        cpy.push_data({
                            modified_items.second.op,
                            modified_items.second.id,
                            modified_items.second.address,
                            modified_items.second.field,
                            modified_items.second.storage_key,
                            modified_items.second.value_before
                        });
                        last_write_rw_counter[modified_items.first] = rw_counter-1;;
                    }
                    _copy_events.push_back(cpy);

                    // Append copy event from memory to call's returndata
                    cpy = return_copy_event(
                        call_id,
                        offset,
                        rw_counter,
                        length
                    );
                    std::cout << "\tRevert return length = " << length << " memory size = " << memory.size() << " offset = " << offset << std::endl;
                    std::cout << "\tInitial RW counter = " << std::hex << rw_counter << std::dec << std::endl;
                    std::vector<std::uint8_t> returndata;
                    for(std::size_t i = 0; i < length; i++){
                        returndata.push_back(offset+i < memory.size() ? memory[offset+i]: 0);
                    }
                    _call_stack.back().returndata = returndata;
                    for(std::size_t i = 0; i < length; i++){
                        _rw_operations.push_back(memory_rw_operation(call_id, offset+i, rw_counter++, false, returndata[i]));
                    }
                    for(std::size_t i = 0; i < length; i++){
                        _rw_operations.push_back(returndata_rw_operation(call_id, i, rw_counter++, returndata[i]));
                        cpy.push_byte(returndata[i]);
                    }
                    _copy_events.push_back(cpy);
                }

                void start_call(){
                    std::size_t parent_id = call_id;
                    call_id = rw_counter;
                    current_opcode = opcode_number_from_str("start_call");
                    memory_size = memory_next.size();
                    zkevm_word_type call_to = stack[stack.size()-2];
                    bytecode_hash = _accounts_initial_state[call_to].code_hash;
                    depth++;

                    std::cout << "START CALL " << call_id << std::endl;
                    std::size_t args_offset = _call_stack.back().args_offset;
                    std::size_t args_length = _call_stack.back().args_length;
                    std::size_t returndataoffset = _call_stack.back().lastcall_returndataoffset;
                    std::size_t returndatalength = _call_stack.back().lastcall_returndatalength;

                    calldata.clear();
                    for( std::size_t i = 0; i < args_length; i++){
                        calldata.push_back(args_offset + i < memory.size() ? memory[args_offset + i]: 0);
                        std::cout << " " << std::hex << std::size_t(calldata.back()) << std::dec;
                    }
                    std::cout << std::endl;

                    _zkevm_states.push_back(call_header_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part()));
                    _call_stack.push_back({
                        _zkevm_states.back(), call_id, 0, 0, 0, calldata, {},
                        {}, {}, {}, _call_stack.back().was_accessed, _call_stack.back().was_written
                    });

                    _rw_operations.push_back(call_context_rw_operation(
                        call_id, call_context_field::parent_id, parent_id
                    ));
                    _rw_operations.push_back(call_context_rw_operation(
                        call_id, call_context_field::depth, _call_stack.size() - 1
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
                    _rw_operations.push_back(call_context_rw_operation(
                        call_id, call_context_field::calldata_size, calldata.size()
                    ));

                    rw_counter += call_context_readonly_field_amount;

                    copy_event cpy = call_copy_event(
                        parent_id,
                        call_id,
                        args_offset,
                        calldata.size()
                    );
                    for( std::size_t i = 0; i < calldata.size(); i++){
                        _rw_operations.push_back(
                            calldata_rw_operation(call_id, i, rw_counter++, calldata[i])
                        );
                        cpy.push_byte(calldata[i]);
                    }
                    _copy_events.push_back(cpy);
                }
                void end_call(){
                    auto returned_call = _call_stack.back();
                    for( auto &modified_item: returned_call.cold_access_list ){
                        if( !_call_stack.back().cold_access_list.count(modified_item.first) )
                            _call_stack.back().cold_access_list[modified_item.first] = modified_item.second;
                    }
                    for( auto &modified_item: returned_call.cold_write_list ){
                        if( !_call_stack.back().cold_write_list.count(modified_item.first) )
                            _call_stack.back().cold_write_list[modified_item.first] = modified_item.second;
                    }
                    std::cout << "Merged!" << std::endl;
                    append_modified_items_rw_operations();
                    current_opcode = opcode_number_from_str("end_call");

                    _call_stack.pop_back();
                    depth--;

                    std::size_t returndataoffset = _call_stack.back().lastcall_returndataoffset; // caller CALL opcode parameters
                    std::size_t returndatalength = _call_stack.back().lastcall_returndatalength; // caller CALL opcode parameters
                    std::size_t subcall_id = call_id;

                    std::cout << "end_call";
                    std::cout << "\treturndataoffset = " << std::hex << returndataoffset;
                    std::cout << "\treturndataoffset = " << std::hex << returndatalength;
                    std::cout << "\tsubcall_id = " << std::hex << subcall_id << std::endl;
                    std::cout << std::dec <<std::endl;

                    call_id = _call_stack.back().call_id;
                    memory_size = memory_next.size();
                    bytecode_hash = _call_stack.back().state.bytecode_hash();
                    call_context_address = _call_stack.back().state.call_context_address();
                    _zkevm_states.push_back(end_call_zkevm_state(
                        get_basic_zkevm_state_part(),
                        get_call_header_state_part(),
                        get_call_context_state_part(),
                        get_world_state_state_part()
                    ));

                    _rw_operations.push_back(call_context_r_operation(
                        call_id,
                        call_context_field::lastcall_returndata_length,
                        rw_counter++,
                        returndatalength
                    ));
                    _rw_operations.push_back(call_context_r_operation(
                        call_id,
                        call_context_field::lastcall_returndata_offset,
                        rw_counter++,
                        returndataoffset
                    ));
                    _rw_operations.push_back(call_context_r_operation(
                        call_id,
                        call_context_field::lastcall_id,
                        rw_counter++,
                        subcall_id
                    ));
                    copy_event cpy = end_call_copy_event(
                        call_id,
                        returndataoffset,
                        subcall_id,
                        rw_counter,
                        returndatalength
                    );
                    for(std::size_t i = 0; i < returndatalength; i++){
                        _rw_operations.push_back(returndata_rw_operation(
                            subcall_id,
                            i,
                            rw_counter++,
                            i < returned_call.returndata.size()? returned_call.returndata[i]: 0
                        ));
                    }
                    for(std::size_t i = 0; i < returndatalength; i++){
                        _rw_operations.push_back(memory_rw_operation(
                            call_id,
                            returndataoffset+i,
                            rw_counter++,
                            true,
                            i < returned_call.returndata.size()? returned_call.returndata[i]: 0
                        ));
                        cpy.push_byte(std::size_t(i <returned_call.returndata.size()? returned_call.returndata[i]: 0));
                    }
                    _call_stack.back().returndata = returned_call.returndata;
                    _copy_events.push_back(cpy);
                    // Push CALL status to stack
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack_next.size()-1, rw_counter++, true, stack_next[stack_next.size()-1]));
                    std::cout << "end_call status stack push " << _rw_operations.back() << std::endl;
                }

                void not_implemented(){
                    std::cout << "Opcode not implemented" << std::endl;
                    exit(2);
                }
                void simple_dummy(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
                }

                void dummy(){
                    _zkevm_states.push_back(call_header_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part()));
                }
            public:
                virtual zkevm_keccak_buffers keccaks() override {return _keccaks;}
                virtual zkevm_keccak_buffers bytecodes() override { return _bytecodes;}
                virtual rw_operations_vector rw_operations() override {return _rw_operations;}
                virtual std::map<std::size_t,zkevm_call_commit> call_commits() override {return _call_commits;}
                virtual std::vector<copy_event> copy_events() override { return _copy_events;}
                virtual std::vector<zkevm_state> zkevm_states() override{ return _zkevm_states;}
                virtual std::vector<std::pair<zkevm_word_type, zkevm_word_type>> exponentiations()override{return _exponentiations;}

            protected:
                void update_modified_items_list(
                    rw_operation_type   op,
                    zkevm_word_type     address,
                    std::size_t         field_tag,
                    zkevm_word_type     storage_key,
                    const rw_operation  &rw_op
                ){
                    std::cout << "Update cold access RW operations depth = " << _call_stack.size() << std::endl;
                    for( std::size_t i = 0; i < _call_stack.size(); i++ ){
                        if( !_call_stack[i].cold_access_list.count(std::make_tuple(op, address, field_tag, storage_key)) ){
                            _call_stack[i].cold_access_list[std::make_tuple(op, address, field_tag, storage_key)] = rw_op;
                        }
                        if( !rw_op.is_write ) continue;
                        if( !_call_stack[i].cold_write_list.count(std::make_tuple(op, address, field_tag, storage_key)) ){
                            _call_stack[i].cold_write_list[std::make_tuple(op, address, field_tag, storage_key)] = rw_op;
                        }
                    }
                }

                void append_modified_items_rw_operations(){
                    auto &call_context = _call_stack[_call_stack.size()-1];
                    std::cout << "Append cold access RW operations depth = " << _call_stack.size()
                        << " call_id = " << call_context.call_id << std::endl;;
                    _rw_operations.push_back(
                        call_context_rw_operation(
                            call_context.call_id,
                            call_context_field::modified_items,
                            call_context.cold_write_list.size()
                        )
                    );
                    std::cout << _rw_operations.back() << std::endl;
                    _call_commits[call_context.call_id] = {
                        call_context.call_id,                           // call_id
                        _call_stack[_call_stack.size() - 2].call_id,    // parent_id
                        _call_stack.size() - 1,                         // depth
                        call_context.end
                    };
                    for( auto &[k,v]: _call_stack.back().cold_write_list){
                        _call_commits[call_context.call_id].items.push_back(v);
                    }
                }
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil
