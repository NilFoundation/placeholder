//---------------------------------------------------------------------------//
// Copyright (c) 2025 Elena Tatuzova   <e.tatuzova@nil.foundation>
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
#include <nil/blueprint/zkevm_bbf/input_generators/precompiles.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_block.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_transaction.hpp>
#include <nil/blueprint/zkevm_bbf/types/block_loader.hpp>
#include <nil/blueprint/zkevm_bbf/util.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            class zkevm_basic_evm{
                using extended_integral_type = nil::crypto3::multiprecision::big_uint<512>;

            public:
                bool get_execution_status() const {return execution_status;}

                virtual void execute_blocks(){
                    while( block_loader->are_there_more_blocks() ){
                        block = block_loader->load_block();
                        this->start_block(); if (!execution_status) return;
                        for(std::size_t i = 0; i < block.tx_amount; i++){
                            auto [_tx, __accounts_initial_state, __existing_accounts] = block_loader->load_transaction(i);
                            tx = std::move(_tx);
                            // State before block
                            if( i == 0 ){
                                _block_initial_state = __accounts_initial_state;
                            }
                            if( __accounts_initial_state.size() != 0 ){
                                _accounts_initial_state.clear();
                                _accounts_current_state.clear();
                                _existing_accounts.clear();
                                _accounts_initial_state = _accounts_current_state = std::move(__accounts_initial_state);
                                _existing_accounts = std::move(__existing_accounts);
                            } else {
                                _accounts_initial_state = _accounts_current_state;
                            }

                            this->start_transaction();  if (!execution_status) return;
                            this->execute_transaction(); if (!execution_status) return;
                            this->end_transaction(); if (!execution_status) return;
                        }
                        this->end_block(); if (!execution_status) return;
                    }
                }

            protected:
                abstract_block_loader                                   *block_loader;

                // Data preloaded data structures
                std::set<zkevm_word_type>                               _existing_accounts;
                std::map<zkevm_word_type, zkevm_account>                _block_initial_state;
                std::map<zkevm_word_type, zkevm_account>                _accounts_initial_state; // Initial state; Update it after block.
                std::map<zkevm_word_type, zkevm_account>                _accounts_current_state; // Initial state; Update it after block.
                std::vector<zkevm_call_context>                         _call_stack;

                // Variables for current block
                zkevm_block block;

                // Variables for current transaction
                zkevm_transaction tx;

                // Variables for current call
                std::size_t depth;
                zkevm_word_type bytecode_hash;
                zkevm_word_type call_caller;
                zkevm_word_type call_context_address;
                zkevm_word_type call_context_value;
                std::size_t     call_gas;
                zkevm_word_type call_addr;
                zkevm_word_type call_value;
                std::size_t     call_args_offset;
                std::size_t     call_args_length;
                zkevm_word_type call_status;
                zkevm_word_type caller;
                std::vector<std::uint8_t> calldata;
                std::vector<std::uint8_t> returndata;
                bool            call_is_create;
                bool            call_is_create2;
                bool            call_is_precompile;

                // Gas passed to be passed to a new call, must be capped
                zkevm_word_type call_gas_sent;

                std::vector<std::uint8_t> create_hashed_bytes;

                // variables for current opcode
                zkevm_word_type additional_input;
                std::size_t     current_opcode;
                std::size_t     pc;
                std::size_t     stack_size;             // BEFORE opcode
                std::size_t     memory_size;            // BEFORE opcode
                std::size_t     gas;
                bool            is_start_call = false;
                bool            is_end_call = false;
                std::vector<zkevm_word_type> stack;
                std::vector<std::uint8_t> memory;
                std::vector<std::uint8_t> bytecode;

                bool execution_status = true;
                std::string error_message;

                virtual void start_block(){
                    depth = 1;
                    pc = 0;
                    gas = 0;
                    tx.hash = 0;
                    current_opcode = opcode_to_number(zkevm_opcode::start_block);

                    _call_stack.push_back(zkevm_call_context());
                }

                virtual void start_transaction(){
                    depth++;
                    pc = 0;
                    caller = tx.from;
                    gas = tx.gas;
                    call_context_value = call_value = tx.value;
                    decrease_gas(21000); // transaction cost
                    current_opcode = opcode_to_number(zkevm_opcode::start_transaction);
                    call_context_address = tx.to;
                    _accounts_current_state[tx.from].balance -= tx.value;
                    _accounts_current_state[tx.from].balance -= tx.gasprice * tx.gas;
                    _accounts_current_state[tx.from].balance -= tx.blob_versioned_hashes.size() * 0x20000;

                    calldata = tx.calldata;
                    std::size_t zeroes = 0;
                    for( auto &c: calldata){
                        if( c == 0 ) zeroes++;
                        decrease_gas(c==0 ? 4: 16); // calldata cost
                    }
                    BOOST_LOG_TRIVIAL(trace) << "Calldata: " << byte_vector_to_sparse_hex_string(calldata);
                    BOOST_LOG_TRIVIAL(trace) << "Calldata zeroes = " << zeroes << " : ";

                    BOOST_LOG_TRIVIAL(trace) << "From balance: 0x" << std::hex << tx.from  << " = " << _accounts_current_state[tx.from].balance << std::dec;
                    BOOST_LOG_TRIVIAL(trace) << "To balance: 0x" << std::hex << tx.to  << " = " << _accounts_current_state[tx.to].balance << std::dec;
                    BOOST_LOG_TRIVIAL(trace) << "Gas: 0x" << std::hex << gas << std::dec;

                    // TODO: fix it
                    if( tx.to == 0 ) {
                        BOOST_LOG_TRIVIAL(debug) << "Deploying contract";
                        decrease_gas(32000); // Deployment cost

                        std::vector<std::uint8_t> sender_bytes;
                        zkevm_word_type mask = (zkevm_word_type(0xFF) << (8 * 19));
                        for( std::size_t i = 0; i < 20; i++){
                            sender_bytes.push_back(std::uint8_t(std::size_t((tx.from & mask) >> (8 * (19 - i))) % 256));
                            mask >>= 8;
                        }

                        std::size_t nonce = _accounts_current_state[tx.from].seq_no;
                        _accounts_current_state[tx.from].seq_no ++;

                        create_hashed_bytes.clear();
                        if(nonce == 0x00) {
                            create_hashed_bytes.push_back(0xd6);
                            create_hashed_bytes.push_back(0x94);
                            create_hashed_bytes.insert(create_hashed_bytes.end(), sender_bytes.begin(), sender_bytes.end());
                            create_hashed_bytes.push_back(0x80);
                        } else if( nonce <= 0x7f ){
                            create_hashed_bytes.push_back(0xd6);
                            create_hashed_bytes.push_back(0x94);
                            create_hashed_bytes.insert(create_hashed_bytes.end(), sender_bytes.begin(), sender_bytes.end());
                            create_hashed_bytes.push_back(std::uint8_t(nonce));
                        } else if( nonce <= 0xff ){
                            create_hashed_bytes.push_back(0xd7);
                            create_hashed_bytes.push_back(0x94);
                            create_hashed_bytes.insert(create_hashed_bytes.end(), sender_bytes.begin(), sender_bytes.end());
                            create_hashed_bytes.push_back(0x81);
                            create_hashed_bytes.push_back(std::uint8_t(nonce));
                        } else if( nonce <= 0xffff ){
                            create_hashed_bytes.push_back(0xd8);
                            create_hashed_bytes.push_back(0x94);
                            create_hashed_bytes.insert(create_hashed_bytes.end(), sender_bytes.begin(), sender_bytes.end());
                            create_hashed_bytes.push_back(0x82);
                            create_hashed_bytes.push_back(std::uint8_t((nonce >> 8)%256));
                            create_hashed_bytes.push_back(std::uint8_t((nonce)%256));
                        }  else if( nonce <= 0xffffff ){
                            create_hashed_bytes.push_back(0xd9);
                            create_hashed_bytes.push_back(0x94);
                            create_hashed_bytes.insert(create_hashed_bytes.end(), sender_bytes.begin(), sender_bytes.end());
                            create_hashed_bytes.push_back(0x83);
                            create_hashed_bytes.push_back(std::uint8_t((nonce >> 16)%256));
                            create_hashed_bytes.push_back(std::uint8_t((nonce >> 8)%256));
                            create_hashed_bytes.push_back(std::uint8_t((nonce)%256));
                        } else {
                            create_hashed_bytes.push_back(0xda);
                            create_hashed_bytes.push_back(0x94);
                            create_hashed_bytes.insert(create_hashed_bytes.end(), sender_bytes.begin(), sender_bytes.end());
                            create_hashed_bytes.push_back(0x84);
                            create_hashed_bytes.push_back(std::uint8_t((nonce >> 24)%256));
                            create_hashed_bytes.push_back(std::uint8_t((nonce >> 16)%256));
                            create_hashed_bytes.push_back(std::uint8_t((nonce >> 8)%256));
                            create_hashed_bytes.push_back(std::uint8_t((nonce)%256));
                        }
                        call_context_address = zkevm_keccak_hash(create_hashed_bytes) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256;
                        _accounts_current_state[call_context_address] = zkevm_account();
                        _accounts_current_state[call_context_address].balance += tx.value;

                        std::size_t calldata_words = (calldata.size() + 31) / 32;
                        decrease_gas(calldata_words * 2);

                        bytecode = tx.calldata;
                        bytecode_hash = zkevm_keccak_hash(bytecode);
                    } else {
                        bytecode = _accounts_current_state[tx.to].bytecode;
                        bytecode_hash = zkevm_keccak_hash(bytecode);
                        _accounts_current_state[tx.to].balance += tx.value;
                    }

                    _call_stack.push_back(zkevm_call_context());
                    _call_stack.back().calldata = calldata;
                    _call_stack.back().bytecode = bytecode;
                    _call_stack.back().caller = caller;
                    _call_stack.back().call_context_address = call_context_address;
                    _call_stack.back().was_accessed.insert({call_context_address, 1, 0});
                    _call_stack.back().was_accessed.insert({tx.from, 1, 0});
                    _call_stack.back().call_value = call_value;
                    _call_stack.back().call_context_value = call_context_value;
                    _call_stack.back().state = _accounts_current_state;

                    // Precompiles are always warm
                    for( std::size_t i = 1; i < 11; i++){
                        _call_stack.back().was_accessed.insert({i, 1, 0});
                    }

                    for( auto address: tx.account_access_list){
                        _call_stack.back().was_accessed.insert({address, 1, 0});
                        decrease_gas(2400); // access_list cost
                    }

                    for( auto [address,key]: tx.storage_access_list){
                        _call_stack.back().was_accessed.insert({address, 0, key});
                        decrease_gas(1900); // access_list cost
                    }

                    _call_stack.back().bytecode = bytecode;
                    memory = {};
                    stack = {};
                    returndata = {};

                    is_end_call = false;
                }

                virtual void execute_transaction(){
                    BOOST_LOG_TRIVIAL(trace) << "Basic execute transaction" << std::endl;

                    while (!is_end_call){
                        zkevm_opcode op = (pc == bytecode.size())? zkevm_opcode::STOP: opcode_from_number(bytecode[pc]);
                        current_opcode = opcode_to_number(op);
                        std::string opcode = opcode_to_string(op);
                        this->execute_opcode(); if( !execution_status ) return;
                    }
                }

                virtual void start_call(){
                    BOOST_LOG_TRIVIAL(trace) << "Basic start call";

                    if (!call_is_create && !call_is_create2) {
                        bytecode = call_is_precompile ?
                                   std::vector<uint8_t>{} :
                                   _accounts_current_state[call_addr].bytecode;
                        bytecode_hash = zkevm_keccak_hash(bytecode);

                        // address access cost
                        if (call_is_precompile ||
                            _call_stack.back().was_accessed.contains({call_addr, 1, 0})) {
                            decrease_gas(100);
                        } else {
                            decrease_gas(2600);
                            _call_stack.back().was_accessed.insert({call_addr, 1, 0});
                        }
                    }

                    _call_stack.push_back(zkevm_call_context());
                    _call_stack.back().call_pc = pc;
                    _call_stack.back().before_call_gas = gas;
                    _call_stack.back().calldata = calldata;
                    _call_stack.back().stack = stack;
                    _call_stack.back().memory = memory;
                    _call_stack.back().caller = caller;
                    _call_stack.back().call_context_address = call_context_address;
                    _call_stack.back().was_accessed = _call_stack[_call_stack.size() - 2].was_accessed;
                    _call_stack.back().transient_storage = _call_stack[_call_stack.size() - 2].transient_storage;
                    _call_stack.back().call_value = call_value;
                    _call_stack.back().call_context_value = call_context_value;
                    _call_stack.back().call_is_create = call_is_create;
                    _call_stack.back().call_is_create2 = call_is_create2;
                    _call_stack.back().state = _accounts_current_state;

                    calldata.clear();
                    for( std::size_t i = 0; i < call_args_length; i++){
                        calldata.push_back(memory[call_args_offset + i]);
                    }
                    _call_stack.back().calldata = calldata;

                    if( call_is_create || call_is_create2 ){
                        bytecode = calldata;
                        bytecode_hash = zkevm_keccak_hash(bytecode);
                    }
                    if( call_is_create) {
                        BOOST_LOG_TRIVIAL(trace) << "Create hashed bytes: " << byte_vector_to_sparse_hex_string(create_hashed_bytes);
                        call_context_address = zkevm_keccak_hash(create_hashed_bytes) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256;
                    }
                    if( call_is_create2 ){
                        zkevm_word_type mask = (zkevm_word_type(0xFF) << (8 *31));
                        for( std::size_t i = 0; i < 32; i++){
                            create_hashed_bytes.push_back(std::uint8_t(std::size_t((bytecode_hash & mask) >> ( 8 * (31 - i))) % 256));
                            mask = mask >> 8;
                        }
                        BOOST_LOG_TRIVIAL(trace) << "Create2 hashed bytes: " << byte_vector_to_sparse_hex_string(create_hashed_bytes);
                        call_context_address = zkevm_keccak_hash(create_hashed_bytes) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256;
                    }
                    _call_stack.back().bytecode = bytecode;
                    _call_stack.back().call_context_address = call_context_address;

                    gas = cap_call_gas(call_gas_sent);
                    if (call_value != 0 && !call_is_create && !call_is_create2)
                        gas += 2300;

                    call_gas = gas;
                    _call_stack.back().call_gas = call_gas;

                    stack = {};
                    memory = {};
                    returndata = {};
                    pc = 0;
                    depth++;
                    is_start_call = false;
                }

                virtual void execute_call(){
                    if (call_is_precompile) {
                        execute_precompile();
                        return;
                    }

                    BOOST_LOG_TRIVIAL(trace) << "Basic execute call";

                    while (!is_end_call){
                        zkevm_opcode op = (pc == bytecode.size())? zkevm_opcode::STOP: opcode_from_number(bytecode[pc]);
                        current_opcode = opcode_to_number(op);
                        std::string opcode = opcode_to_string(op);
                        this->execute_opcode(); if( !execution_status ) return;
                    }
                }

                virtual void end_call(){
                    BOOST_LOG_TRIVIAL(trace) << "Basic end call";

                    if( _call_stack.size() > 2){
                        _call_stack[_call_stack.size()-2].was_accessed.insert(_call_stack.back().was_accessed.begin(), _call_stack.back().was_accessed.end());
                        for( auto & [k,v]: _call_stack.back().transient_storage){
                            _call_stack[_call_stack.size()-2].transient_storage[k] = v;
                        }
                    }

                    pc = _call_stack.back().call_pc + 1;
                    gas = _call_stack.back().before_call_gas - (call_gas - gas);
                    memory = _call_stack.back().memory;
                    stack = _call_stack.back().stack;
                    call_value = _call_stack.back().call_value;
                    if( call_value != 0 ) gas += 2300;

                    BOOST_LOG_TRIVIAL(trace) << "End call gas: " << gas;
                    if( call_is_create || call_is_create2 ){
                        decrease_gas(returndata.size() * 200);
                    }
                    BOOST_LOG_TRIVIAL(trace) << "End call gas: " << gas;

                    _call_stack.pop_back();
                    bytecode = _call_stack.back().bytecode;
                    bytecode_hash = zkevm_keccak_hash(bytecode);
                    calldata = _call_stack.back().calldata;
                    caller = _call_stack.back().caller;
                    call_context_address = _call_stack.back().call_context_address;
                    call_context_value = _call_stack.back().call_context_value;
                    call_value = _call_stack.back().call_value;
                    call_gas = _call_stack.back().call_gas;
                    std::size_t returndata_offset = _call_stack.back().lastcall_returndataoffset;
                    std::size_t returndata_length = _call_stack.back().lastcall_returndatalength;

                    is_end_call = false;
                    std::size_t real_length = std::min(returndata_length, returndata.size());
                    // Memory is resized before CALL
                    for( std::size_t i = 0; i < real_length; i++){
                        memory[returndata_offset + i] = returndata[i];
                    }

                    stack.push_back(call_status);
                    depth--;
                }

                virtual void execute_opcode(){
                    memory_size = memory.size();
                    stack_size = stack.size();

                    std::string opcode = opcode_to_string(opcode_from_number(current_opcode));

                    if(opcode == "STOP") { this->stop();}
                    else if( opcode == "RETURN" ) { this->return_opcode();}
                    else if( opcode == "REVERT" ) { this->revert();}
                    else if( opcode == "INVALID" ) { this->invalid();}
                    else if( opcode == "LT" ) this->lt();
                    else if( opcode == "GT" ) this->gt();
                    else if( opcode == "SLT" ) this->slt();
                    else if( opcode == "SGT" ) this->sgt();
                    else if( opcode == "SHL" ) this->shl();
                    else if( opcode == "SHR" ) this->shr();
                    else if( opcode == "SAR" ) this->sar();
                    else if( opcode == "ADD" ) this->add();
                    else if( opcode == "SUB" ) this->sub();
                    else if( opcode == "MUL" ) this->mul();
                    else if( opcode == "DIV" ) this->div();
                    else if( opcode == "EXP" ) this->exp();
                    else if( opcode == "SIGNEXTEND" ) this->signextend();
                    else if( opcode == "MOD" ) this->mod();
                    else if( opcode == "SDIV" ) this->sdiv();
                    else if( opcode == "SMOD" ) this->smod();
                    else if( opcode == "MULMOD" ) this->mulmod();
                    else if( opcode == "ADDMOD" ) this->addmod();
                    else if( opcode == "AND" ) this->and_opcode();
                    else if( opcode == "OR" ) this->or_opcode();
                    else if( opcode == "XOR" ) this->xor_opcode();
                    else if( opcode == "BYTE" ) this->byte();
                    else if( opcode == "EQ" ) this->eq();
                    else if( opcode == "ISZERO" ) this->iszero();
                    else if( opcode == "NOT" ) this->not_opcode();
                    else if( opcode == "JUMP" ) this->jump();
                    else if( opcode == "JUMPI" ) this->jumpi();
                    else if( opcode == "JUMPDEST" ) this->jumpdest();
                    else if( opcode == "MLOAD" ) this->mload();
                    else if( opcode == "MSTORE" ) this->mstore();
                    else if( opcode == "MSTORE8" ) this->mstore8();
                    else if( opcode == "MCOPY" ) this->mcopy();
                    else if( opcode == "SLOAD" ) this->sload();
                    else if( opcode == "SSTORE" ) this->sstore();
                    else if( opcode == "TLOAD" ) this->tload();
                    else if( opcode == "TSTORE" ) this->tstore();
                    else if( opcode == "KECCAK256" ) this->keccak();
                    else if( opcode == "GAS" ) this->gas_opcode();
                    else if( opcode == "PC" ) this->pc_opcode();
                    else if( opcode == "MSIZE" ) this->msize_opcode();
                    else if( opcode == "RETURNDATASIZE" ) this->returndatasize();
                    else if( opcode == "RETURNDATACOPY" ) this->returndatacopy();
                    else if( opcode == "CODESIZE" ) this->codesize();
                    else if( opcode == "CODECOPY" ) this->codecopy();
                    else if( opcode == "EXTCODESIZE" ) this->extcodesize();
                    else if( opcode == "EXTCODEHASH" ) this->extcodehash();
                    else if( opcode == "BLOCKHASH" ) this->blockhash();
                    else if( opcode == "BLOBHASH" ) this->blobhash();
                    else if( opcode == "BLOBBASEFEE" ) this->blobbasefee();
                    else if( opcode == "COINBASE" ) this->coinbase();
                    else if( opcode == "TIMESTAMP" ) this->timestamp();
                    else if( opcode == "NUMBER" ) this->number();
                    else if( opcode == "DIFFICULTY" ) this->difficulty();
                    else if( opcode == "CHAINID" ) this->chainid();
                    else if( opcode == "GASPRICE" ) this->gasprice();
                    else if(opcode == "PUSH0") this->push_opcode(0);
                    else if(opcode == "PUSH1") this->push_opcode(1);
                    else if(opcode == "PUSH2") this->push_opcode(2);
                    else if(opcode == "PUSH3") this->push_opcode(3);
                    else if(opcode == "PUSH4") this->push_opcode(4);
                    else if(opcode == "PUSH5") this->push_opcode(5);
                    else if(opcode == "PUSH6") this->push_opcode(6);
                    else if(opcode == "PUSH7") this->push_opcode(7);
                    else if(opcode == "PUSH8") this->push_opcode(8);
                    else if(opcode == "PUSH9") this->push_opcode(9);
                    else if(opcode == "PUSH10") this->push_opcode(10);
                    else if(opcode == "PUSH11") this->push_opcode(11);
                    else if(opcode == "PUSH12") this->push_opcode(12);
                    else if(opcode == "PUSH13") this->push_opcode(13);
                    else if(opcode == "PUSH14") this->push_opcode(14);
                    else if(opcode == "PUSH15") this->push_opcode(15);
                    else if(opcode == "PUSH16") this->push_opcode(16);
                    else if(opcode == "PUSH17") this->push_opcode(17);
                    else if(opcode == "PUSH18") this->push_opcode(18);
                    else if(opcode == "PUSH19") this->push_opcode(19);
                    else if(opcode == "PUSH20") this->push_opcode(20);
                    else if(opcode == "PUSH21") this->push_opcode(21);
                    else if(opcode == "PUSH22") this->push_opcode(22);
                    else if(opcode == "PUSH23") this->push_opcode(23);
                    else if(opcode == "PUSH24") this->push_opcode(24);
                    else if(opcode == "PUSH25") this->push_opcode(25);
                    else if(opcode == "PUSH26") this->push_opcode(26);
                    else if(opcode == "PUSH27") this->push_opcode(27);
                    else if(opcode == "PUSH28") this->push_opcode(28);
                    else if(opcode == "PUSH29") this->push_opcode(29);
                    else if(opcode == "PUSH30") this->push_opcode(30);
                    else if(opcode == "PUSH31") this->push_opcode(31);
                    else if(opcode == "PUSH32") this->push_opcode(32);
                    else if(opcode == "DUP1") this->dupx(1);
                    else if(opcode == "DUP2") this->dupx(2);
                    else if(opcode == "DUP3") this->dupx(3);
                    else if(opcode == "DUP4") this->dupx(4);
                    else if(opcode == "DUP5") this->dupx(5);
                    else if(opcode == "DUP6") this->dupx(6);
                    else if(opcode == "DUP7") this->dupx(7);
                    else if(opcode == "DUP8") this->dupx(8);
                    else if(opcode == "DUP9") this->dupx(9);
                    else if(opcode == "DUP10") this->dupx(10);
                    else if(opcode == "DUP11") this->dupx(11);
                    else if(opcode == "DUP12") this->dupx(12);
                    else if(opcode == "DUP13") this->dupx(13);
                    else if(opcode == "DUP14") this->dupx(14);
                    else if(opcode == "DUP15") this->dupx(15);
                    else if(opcode == "DUP16") this->dupx(16);
                    else if(opcode == "SWAP1") this->swapx(1);
                    else if(opcode == "SWAP2") this->swapx(2);
                    else if(opcode == "SWAP3") this->swapx(3);
                    else if(opcode == "SWAP4") this->swapx(4);
                    else if(opcode == "SWAP5") this->swapx(5);
                    else if(opcode == "SWAP6") this->swapx(6);
                    else if(opcode == "SWAP7") this->swapx(7);
                    else if(opcode == "SWAP8") this->swapx(8);
                    else if(opcode == "SWAP9") this->swapx(9);
                    else if(opcode == "SWAP10") this->swapx(10);
                    else if(opcode == "SWAP11") this->swapx(11);
                    else if(opcode == "SWAP12") this->swapx(12);
                    else if(opcode == "SWAP13") this->swapx(13);
                    else if(opcode == "SWAP14") this->swapx(14);
                    else if(opcode == "SWAP15") this->swapx(15);
                    else if(opcode == "SWAP16") this->swapx(16);
                    else if(opcode == "LOG0") logx(0);
                    else if(opcode == "LOG1") logx(1);
                    else if(opcode == "LOG2") logx(2);
                    else if(opcode == "LOG3") logx(3);
                    else if(opcode == "LOG4") logx(4);
                    else if( opcode == "POP" ) this->pop();
                    else if( opcode == "CALLDATALOAD" ) this->calldataload();
                    else if( opcode == "CALLDATASIZE" ) this->calldatasize();
                    else if( opcode == "CALLDATACOPY" ) this->calldatacopy();
                    else if( opcode == "ADDRESS" )   this->address();
                    else if( opcode == "BALANCE" )   this->balance();
                    else if( opcode == "SELFBALANCE" )   this->selfbalance();
                    else if( opcode == "BASEFEE" ) this->basefee();
                    else if( opcode == "ORIGIN" )    this->origin();
                    else if( opcode == "CALLER" )    this->caller_opcode();
                    else if( opcode == "CALLVALUE" ) this->callvalue();
                    else if( opcode == "DELEGATECALL" ) this->delegatecall();
                    else if( opcode == "STATICCALL" ) this->staticcall();
                    else if( opcode == "CALL" ) this->call();
                    else if( opcode == "CREATE" ) this->create();
                    else if( opcode == "CREATE2" ) this->create2();
                    else if( opcode == "SELFDESTRUCT" ) selfdestruct();
                    else{
                        error_message = "Opcode " + opcode + " not supported";
                        BOOST_LOG_TRIVIAL(error) << error_message;
                        execution_status = false;
                        return;
                    }

                    if( !execution_status ) return;
                    if( is_start_call ){
                        this->start_call(); if( !execution_status ) return;
                        this->execute_call(); if( !execution_status ) return;
                        this->end_call(); if( !execution_status ) return;
                    }
                }

                virtual void exp() {
                    auto a = stack.back(); stack.pop_back();
                    auto d = stack.back(); stack.pop_back();
                    zkevm_word_type result = exp_by_squaring(a, d);

                    stack.push_back(result);
                    pc++;
                    decrease_gas(10 + 50 * count_significant_bytes(d));
                }

                virtual void signextend() {
                    zkevm_word_type b = stack.back(); stack.pop_back();
                    zkevm_word_type x = stack.back(); stack.pop_back();
                    int len = (b < 32) ? int(b) + 1 : 32;
                    zkevm_word_type sign = (x << (8 * (32 - len))) >> 255;
                    zkevm_word_type result =
                        zkevm_word_type(
                                (wrapping_sub(zkevm_word_type(1) << 8 * (32 - len), 1)
                                << 8 * len) *
                                sign) +
                        ((x << (8 * (32 - len))) >> (8 * (32 - len)));
                    stack.push_back(result);
                    pc++;
                    decrease_gas(5);
                }

                virtual void mcopy() {
                    std::size_t dst = std::size_t(stack.back()); stack.pop_back();
                    std::size_t src = std::size_t(stack.back()); stack.pop_back();
                    std::size_t length = std::size_t(stack.back()); stack.pop_back();

                    std::size_t minimum_word_size = (length + 31) / 32;
                    std::size_t next_mem = std::max(src + length, std::max(dst + length, memory.size()));
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());
                    std::size_t next_memory_size = (memory_size_word_util(next_mem))*32;

                    if( memory.size() < next_mem) memory.resize(next_mem);
                    std::vector<std::uint8_t> data;
                    for( std::size_t i = 0; i < length; i++){
                        data.push_back(memory[src+i]);
                    }
                    for( std::size_t i = 0; i < length; i++){
                        memory[dst + i] = data[i];
                    }

                    decrease_gas(3); //static gas
                    decrease_gas(3 * minimum_word_size + memory_expansion); //dynamic gas
                    pc++;
                }

                virtual void tload() {
                    auto addr = stack.back(); stack.pop_back();
                    stack.push_back(_call_stack.back().transient_storage[{call_context_address, addr}]);
                    decrease_gas(100);
                    pc++;
                }

                virtual void tstore() {
                    auto key = stack.back();stack.pop_back();
                    auto value = stack.back(); stack.pop_back();
                    _call_stack.back().transient_storage[{call_context_address, key}] = value;
                    decrease_gas(100);
                    pc++;
                }

                virtual void mload(){
                    zkevm_word_type full_offset = stack.back(); stack.pop_back();
                    if( full_offset > (1 << 25) - 32 ) {
                        BOOST_LOG_TRIVIAL(error) << "MLOAD offset too large: " << std::hex << full_offset << std::dec;
                        decrease_gas(gas+1);
                        pc++;
                        return;
                    }
                    // BOOST_LOG_TRIVIAL(trace) << "MLOAD offset: " << std::hex << full_offset << std::dec;
                    zkevm_word_type result = 0;

                    // TODO: process overflows
                    std::size_t offset = std::size_t(full_offset);

                    std::size_t memory_size_word = (memory.size() + 31) / 32;
                    std::size_t last_memory_cost = memory_size_word * memory_size_word / 512 + (3*memory_size_word);

                    if( memory.size() < offset + 32) memory.resize(offset + 32, 0);
                    memory_size_word = (memory.size() + 31) / 32;
                    std::size_t new_memory_cost = memory_size_word * memory_size_word / 512 + (3*memory_size_word);
                    std::size_t memory_expansion = new_memory_cost - last_memory_cost;

                    for( std::size_t i = 0; i < 32; i++){
                        result = (result << 8) + memory[offset + i];
                    }
                    decrease_gas(3 + memory_expansion);

                    stack.push_back(result);
                    pc++;
                }

                virtual void mstore(){
                    auto full_offset = stack.back(); stack.pop_back();
                    auto value = stack.back(); stack.pop_back();
                    if( full_offset > (1 << 25) - 32 ) {
                        decrease_gas(gas+1);
                        pc++;
                        return;
                    }

                    std::size_t offset = std::size_t(full_offset);
                    std::size_t new_mem_size = std::max(offset + 32, memory.size());
                    std::size_t memory_expansion = memory_expansion_cost(new_mem_size, memory.size());

                    if( memory.size() < new_mem_size) {
                        BOOST_LOG_TRIVIAL(trace) << "Memory expansion " << memory.size() << " => " << new_mem_size << std::endl;
                        memory.resize(new_mem_size);
                    }
                    for( std::size_t i = 0; i < 32; i++){
                        memory[offset + 31 - i] = std::uint8_t(std::size_t(value % 256));
                        value = value >> 8;
                    }
                    decrease_gas(3 + memory_expansion);
                    pc++;
                }

                virtual void mstore8(){
                    auto full_offset = stack.back(); stack.pop_back();
                    auto value = stack.back(); stack.pop_back();
                    if( full_offset > (1 << 25) - 1 ) {
                        decrease_gas(gas+1);
                        pc++;
                        return;
                    }

                    std::size_t offset = std::size_t(full_offset);
                    std::size_t memory_size_word = (memory.size() + 31) / 32;
                    std::size_t last_memory_cost = memory_size_word * memory_size_word / 512 + (3*memory_size_word);

                    if( memory.size() < offset + 1) memory.resize(offset + 1);
                    memory[offset] = std::uint8_t(std::size_t(value % 256));

                    memory_size_word = (memory.size() + 31) / 32;
                    std::size_t new_memory_cost = memory_size_word * memory_size_word / 512 + (3*memory_size_word);
                    std::size_t memory_expansion = new_memory_cost - last_memory_cost;
                    decrease_gas(3 + memory_expansion);
                    pc++;
                }

                virtual void sload() {
                    auto addr = stack.back(); stack.pop_back();
                    stack.push_back(_accounts_current_state[call_context_address].storage[addr]);
                    if( _call_stack.back().was_accessed.count({call_context_address, 0, addr}) == 0){
                        _call_stack.back().was_accessed.insert({call_context_address, 0, addr});
                        BOOST_LOG_TRIVIAL(trace) << "COLD {" << std::hex << call_context_address << ", " << addr << "} = " << stack.back()  << std::endl;
                        decrease_gas(2000);
                    } else {
                        BOOST_LOG_TRIVIAL(trace) << "WARM {" << std::hex << call_context_address << ", " << addr << "} = " << stack.back() << std::endl;
                    }
                    decrease_gas(100);
                    pc++;
                }

                virtual void sstore() {
                    auto addr = stack.back(); stack.pop_back();
                    auto value = stack.back(); stack.pop_back();
                    auto previous_value = _accounts_current_state[call_context_address].storage[addr];
                    zkevm_word_type initial_value;
                    if( _accounts_initial_state.count(call_context_address) != 0 ){
                        if( _accounts_initial_state[call_context_address].storage.count(addr) != 0){
                            initial_value = _accounts_initial_state[call_context_address].storage[addr];
                        }
                    }

                    std::size_t is_cold = (_call_stack.back().was_accessed.count({call_context_address, 0, addr}) == 0);
                    std::size_t is_clean = (previous_value == initial_value);
                    std::size_t is_equal = (previous_value == value);
                    std::size_t was_zero = (previous_value == 0);

                    if(is_cold){
                        BOOST_LOG_TRIVIAL(trace) << "COLD {" << std::hex << call_context_address << ", " << addr << "} "
                        << std::hex << previous_value << " => " << value << std::dec;
                    } else {
                        BOOST_LOG_TRIVIAL(trace) << "WARM " << (is_clean?"CLEAN":"DIRTY") << "  {" << std::hex << call_context_address << ", " << addr << "} "
                        << std::hex << previous_value << " => " << value << std::dec;
                    }
                    BOOST_LOG_TRIVIAL(trace) << "is_equal = " << is_equal;
                    BOOST_LOG_TRIVIAL(trace) << "was_zero = " << was_zero;

                    std::size_t cost = 100 + is_cold * 2100
                        + is_clean * (1 - is_equal) * was_zero * 19900
                        + is_clean * (1 - is_equal) * (1 - was_zero) * 2800;

                    BOOST_LOG_TRIVIAL(trace) << "gas_cost = " << cost;

                    _accounts_current_state[call_context_address].storage[addr] = value;
                    _call_stack.back().was_accessed.insert({call_context_address, 0, addr});

                    decrease_gas(cost);
                    pc++;
                }

                virtual void stop(){
                    call_status = 1;
                    returndata.clear();
                    is_end_call = true;
                }

                virtual void return_opcode(){
                    std::size_t offset = std::size_t(stack.back()); stack.pop_back();
                    std::size_t length = std::size_t(stack.back()); stack.pop_back();

                    std::size_t next_mem = std::max(offset + length, memory.size());
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());

                    if( memory.size() < offset + length) memory.resize(offset + length);
                    decrease_gas(memory_expansion);

                    returndata.clear();
                    for( std::size_t i = 0; i < length; i++){
                        returndata.push_back(memory[offset+i]);
                    }

                    if( _call_stack.back().call_is_create || _call_stack.back().call_is_create2 ){
                        call_status = call_context_address;
                        _existing_accounts.insert(call_context_address);
                        _accounts_current_state[call_context_address].bytecode = returndata;
                        _call_stack.back().was_accessed.insert({call_context_address, 1, 0});
                    } else {
                        call_status = 1;
                    }
                    is_end_call = true;
                }

                virtual void revert(){
                    std::size_t offset = std::size_t(stack.back()); stack.pop_back();
                    std::size_t length = std::size_t(stack.back()); stack.pop_back();

                    std::size_t next_mem = std::max(offset + length, memory.size());
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());

                    if( memory.size() < offset + length) memory.resize(offset + length);
                    decrease_gas(memory_expansion);

                    returndata.clear();
                    for( std::size_t i = 0; i < length; i++){
                        returndata.push_back(memory[offset+i]);
                    }

                    _accounts_current_state = _call_stack[_call_stack.size() - 1].state;
                    _call_stack.back().was_accessed = _call_stack[_call_stack.size() - 2].was_accessed;
                    _call_stack.back().transient_storage = _call_stack[_call_stack.size() - 2].transient_storage;
                    call_status = 0;
                    is_end_call = true;
                }

                virtual void invalid(){
                    returndata.clear();
                    call_status = 0;
                    _accounts_current_state = _call_stack[_call_stack.size() - 1].state;
                    _call_stack.back().was_accessed = _call_stack[_call_stack.size() - 2].was_accessed;
                    _call_stack.back().transient_storage = _call_stack[_call_stack.size() - 2].transient_storage;
                    is_end_call = true;
                }

                virtual void push_opcode( std::size_t x) {
                    zkevm_word_type additional_input;
                    for( std::size_t i = 0; i < x; i++ ){
                        additional_input = additional_input << 8;
                        additional_input += bytecode[pc + 1 + i];
                    }
                    stack.push_back(additional_input);
                    pc += 1 + x;
                    decrease_gas(x == 0? 2 : 3);
                }

                virtual void dupx( std::size_t d) {
                    stack.push_back(stack[stack.size()-d]);
                    pc++;
                    decrease_gas(3);
                }

                virtual void swapx( std::size_t s) {
                    auto tmp = stack[stack.size() - s - 1];
                    stack[stack.size() - s - 1] = stack[stack.size()-1];
                    stack[stack.size()-1] = tmp;
                    pc++;
                    decrease_gas(3);
                }

                virtual void calldatasize(){
                    stack.push_back(calldata.size());
                    decrease_gas(2);
                    pc++;
                }

                virtual void calldatacopy(){
                    std::size_t dst = std::size_t(stack.back()); stack.pop_back();
                    std::size_t src = std::size_t(stack.back()); stack.pop_back();
                    std::size_t length = std::size_t(stack.back()); stack.pop_back();

                    std::size_t minimum_word_size = (length + 31) / 32;
                    std::size_t next_mem = std::max(length == 0? 0: dst + length, memory.size());
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());

                    if( memory.size() < next_mem) memory.resize(next_mem, 0);
                    for( std::size_t i = 0; i < length; i++){
                        memory[dst+i] = src + i < calldata.size()? calldata[src+i]: 0;
                    }

                    decrease_gas(3 + 3 * minimum_word_size + memory_expansion); //dynamic gas
                    pc++;
                }

                virtual void calldataload(){
                    zkevm_word_type result;
                    if( stack.back() >= calldata.size() )
                        result = 0;
                    else {
                        std::size_t offset = std::size_t(stack.back());
                        for( std::size_t i = 0; i < 32; i++){
                            result = ((offset + i) < calldata.size())? (result << 8) + calldata[offset+i]: result << 8;
                        }
                    }

                    stack.pop_back();
                    stack.push_back(result);
                    pc++;
                    decrease_gas(3);
                }
                virtual void lt() {
                    auto a = stack.back(); stack.pop_back();
                    auto b = stack.back(); stack.pop_back();
                    zkevm_word_type result = (a < b);

                    stack.push_back(result);
                    decrease_gas(3);
                    pc++;
                }
                virtual void gt(){
                    auto a = stack.back(); stack.pop_back();
                    auto b = stack.back(); stack.pop_back();
                    zkevm_word_type result = (a > b);

                    stack.push_back(result);
                    decrease_gas(3);
                    pc++;
                }
                virtual void slt(){
                    auto a = stack.back(); stack.pop_back();
                    auto b = stack.back(); stack.pop_back();
                    zkevm_word_type result = 0;
                    if( is_negative(a) && !is_negative(b) ){
                        result = 1;
                    } else if( is_negative(a) && is_negative(b) ){
                        result = a < b;
                    } else if( !is_negative(a) && !is_negative(b) ){
                        result = a < b;
                    }
                    stack.push_back(result);
                    decrease_gas(3);
                    pc++;
                }
                virtual void sgt(){
                    auto a = stack.back(); stack.pop_back();
                    auto b = stack.back(); stack.pop_back();
                    zkevm_word_type result;
                    if( !is_negative(a) && is_negative(b) ){
                        result = 1;
                    } else if( is_negative(a) && is_negative(b) ){
                        result = a > b;
                    } else if( !is_negative(a) && !is_negative(b) ){
                        result = a > b;
                    }
                    stack.push_back(result);
                    decrease_gas(3);
                    pc++;
                }
                virtual void shl(){
                    auto b = stack.back(); stack.pop_back();
                    auto a = stack.back(); stack.pop_back();
                    int shift = (b < 256) ? int(b) : 256;
                    zkevm_word_type result = a << shift;

                    stack.push_back(result);
                    decrease_gas(3);
                    pc++;
                }
                virtual void shr(){
                    auto b = stack.back(); stack.pop_back();
                    auto a = stack.back(); stack.pop_back();
                    int shift = (b < 256) ? int(b) : 256;
                    zkevm_word_type result = a >> shift;

                    stack.push_back(result);
                    decrease_gas(3);
                    pc++;
                }
                virtual void sar(){
                    zkevm_word_type b = stack.back();  stack.pop_back();
                    zkevm_word_type input_a = stack.back(); stack.pop_back();
                    zkevm_word_type a = is_negative(input_a)?
                        zkevm_word_type(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256) - input_a :
                        input_a;
                    int shift = (b < 256) ? int(b) : 256;
                    zkevm_word_type r = a >> shift;
                    zkevm_word_type result;
                    if(is_negative(input_a))
                        result =  (((r == 0) ? neg_one : (zkevm_word_type(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256) - r)));
                    else
                        result = r;

                    stack.push_back(result);
                    decrease_gas(3);
                    pc++;
                }
                virtual void add(){
                    auto a = stack.back(); stack.pop_back();
                    auto b = stack.back(); stack.pop_back();
                    zkevm_word_type result = wrapping_add(a, b);
                    stack.push_back(result);
                    decrease_gas(3);
                    pc++;
                }
                virtual void sub(){
                    auto a = stack.back(); stack.pop_back();
                    auto b = stack.back(); stack.pop_back();
                    zkevm_word_type result = wrapping_sub(a, b);
                    stack.push_back(result);
                    decrease_gas(3);
                    pc++;
                }
                virtual void mul() {
                    auto a = stack.back(); stack.pop_back();
                    auto b = stack.back(); stack.pop_back();
                    zkevm_word_type result = wrapping_mul(a, b);
                    stack.push_back(result);
                    decrease_gas(5);
                    pc++;
                }
                virtual void div(){
                    auto a = stack.back(); stack.pop_back();
                    auto b = stack.back(); stack.pop_back();
                    zkevm_word_type result = b != 0u ? a / b : 0u;
                    stack.push_back(result);
                    decrease_gas(5);
                    pc++;
                }
                virtual void mod(){
                    auto a = stack.back(); stack.pop_back();
                    auto b = stack.back(); stack.pop_back();
                    zkevm_word_type q = b != 0u ? a % b : a;
                    zkevm_word_type result =
                        b != 0u ? q : 0u;  // according to EVM spec a % 0 = 0
                    stack.push_back(result);
                    decrease_gas(5);
                    pc++;
                }
                virtual void sdiv() {
                    auto a = stack.back(); stack.pop_back();
                    auto b_input = stack.back(); stack.pop_back();
                    bool overflow = (a == neg_one) && (b_input == min_neg);
                    zkevm_word_type b = overflow ? 1 : b_input;
                    zkevm_word_type a_abs = abs_word(a), b_abs = abs_word(b);
                    zkevm_word_type r_abs = b != 0u ? a_abs / b_abs : 0u;
                    zkevm_word_type result = (is_negative(a) == is_negative(b)) ? r_abs : negate_word(r_abs);
                    stack.push_back(result);
                    decrease_gas(5);
                    pc++;
                }
                virtual void smod() {
                    auto a = stack.back(); stack.pop_back();
                    auto b_input = stack.back(); stack.pop_back();
                    bool overflow = (a == neg_one) && (b_input == min_neg);
                    zkevm_word_type b = overflow ? 1 : b_input;
                    zkevm_word_type a_abs = abs_word(a), b_abs = abs_word(b);
                    zkevm_word_type r_abs = b != 0u ? a_abs / b_abs : 0u;
                    zkevm_word_type q_abs = b != 0u ? a_abs % b_abs : a_abs,
                                    r = (is_negative(a) == is_negative(b))
                                        ? r_abs
                                        : negate_word(r_abs),
                                    q = is_negative(a) ? negate_word(q_abs) : q_abs;
                    zkevm_word_type result = b != 0u ? q : 0u;  // according to EVM spec a % 0 = 0

                    stack.push_back(result);
                    decrease_gas(5);
                    pc++;
                }
                virtual void mulmod(){
                    zkevm_word_type a = stack.back(); stack.pop_back();
                    zkevm_word_type b = stack.back(); stack.pop_back();
                    zkevm_word_type modulus = stack.back(); stack.pop_back();
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

                    stack.push_back(result);
                    decrease_gas(8);
                    pc++;
                }

                virtual void addmod(){
                    zkevm_word_type a = stack.back(); stack.pop_back();
                    zkevm_word_type b = stack.back(); stack.pop_back();
                    zkevm_word_type modulus = stack.back(); stack.pop_back();
                    auto s_full = nil::crypto3::multiprecision::big_uint<257>(a) + b;
                    auto r_full = modulus != 0u ? s_full / modulus : 0u;
                    zkevm_word_type q = wrapping_sub(s_full, wrapping_mul(r_full, modulus)).truncate<256>();
                    zkevm_word_type result = modulus != 0u ? q : 0u;

                    stack.push_back(result);
                    decrease_gas(8);
                    pc++;
                }

                virtual void jump() {
                    pc = std::size_t(stack.back()); stack.pop_back();
                    decrease_gas(8);
                }

                virtual void jumpi() {
                    auto addr = stack.back(); stack.pop_back();
                    auto condition = stack.back(); stack.pop_back();
                    pc = condition == 0? pc+1: std::size_t(addr);
                    decrease_gas(10);
                }

                virtual void pop() {stack.pop_back(); pc++; gas-=2;}
                virtual void jumpdest() {pc++;gas--;}

                virtual void eq() {
                    auto a = stack.back(); stack.pop_back();
                    auto b = stack.back(); stack.pop_back();
                    zkevm_word_type result = a==b? 1: 0;
                    stack.push_back(result);
                    decrease_gas(3);
                    pc++;
                }
                virtual void iszero() {
                    auto a = stack.back(); stack.pop_back();
                    zkevm_word_type result = a == 0? 1: 0;
                    stack.push_back(result);
                    decrease_gas(3);
                    pc++;
                }
                virtual void not_opcode() {
                    auto a = stack.back(); stack.pop_back();
                    zkevm_word_type result =
                        zkevm_word_type(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256) - a;
                    stack.push_back(result);
                    decrease_gas(3);
                    pc++;
                }

                virtual void origin() {
                    stack.push_back(tx.from);
                    pc++;
                    decrease_gas(2);
                }
                virtual void caller_opcode() {
                    stack.push_back(caller);
                    pc++;
                    decrease_gas(2);
                }

                virtual void callvalue() {
                    stack.push_back(call_context_value);
                    pc++;
                    decrease_gas(2);
                }

                virtual void address() {
                    stack.push_back(call_context_address);
                    decrease_gas(2);
                    pc++;
                }

                virtual void balance() {
                    zkevm_word_type addr = stack.back(); stack.pop_back();
                    addr &= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256;
                    BOOST_LOG_TRIVIAL(trace) << "BALANCE for address 0x" << std::hex << addr << std::dec;
                    stack.push_back(_accounts_current_state[addr].balance);
                    if( _call_stack.back().was_accessed.count({addr, 1, 0}) == 0){
                        decrease_gas(2500);
                    }
                    decrease_gas(100);
                    _call_stack.back().was_accessed.insert({addr, 1, 0});
                    pc++;
                }

                void selfbalance() {
                    stack.push_back(_accounts_current_state[call_context_address].balance);
                    decrease_gas(5);
                    pc++;
                }

                virtual void keccak() {
                    std::size_t offset = std::size_t(stack.back()); stack.pop_back();
                    std::size_t length = std::size_t(stack.back()); stack.pop_back();

                    std::size_t memory_size_word = (memory.size() + 31) / 32;
                    std::size_t last_memory_cost = memory_size_word * memory_size_word / 512 + (3*memory_size_word);
                    if( memory.size() < offset + length) memory.resize(offset + length, 0);
                    memory_size_word = (memory.size() + 31) / 32;
                    std::size_t new_memory_cost = memory_size_word * memory_size_word / 512 + (3*memory_size_word);
                    std::size_t memory_expansion = new_memory_cost - last_memory_cost;

                    std::vector<std::uint8_t> data;
                    for( std::size_t i = 0; i < length; i++){
                        data.push_back(memory[offset+i]);
                    };
                    zkevm_word_type result = zkevm_keccak_hash(data);

                    stack.push_back(result);
                    std::size_t cost = 30 + 6 * ((length + 31) / 32) + memory_expansion;

                    decrease_gas(cost);
                    pc++;
                }

                virtual void and_opcode() {
                    auto a = stack.back(); stack.pop_back();
                    auto b = stack.back(); stack.pop_back();
                    zkevm_word_type result = a & b;

                    stack.push_back(result);
                    decrease_gas(3);
                    pc++;
                }

                virtual void or_opcode() {
                    auto a = stack.back(); stack.pop_back();
                    auto b = stack.back(); stack.pop_back();
                    zkevm_word_type result = a | b;

                    stack.push_back(result);
                    decrease_gas(3);
                    pc++;
                }

                virtual void xor_opcode() {
                    auto a = stack.back(); stack.pop_back();
                    auto b = stack.back(); stack.pop_back();
                    zkevm_word_type result = a ^ b;

                    stack.push_back(result);
                    decrease_gas(3);
                    pc++;
                }

                virtual void byte() {
                    auto N = stack.back(); stack.pop_back();
                    auto a = stack.back(); stack.pop_back();
                    auto n = w_to_8(N)[31];
                    zkevm_word_type result = N > 31? 0: w_to_8(a)[n];

                    stack.push_back(result);
                    decrease_gas(3);
                    pc++;
                }

                virtual void logx( std::size_t l) {
                    std::size_t offset = std::size_t(stack.back()); stack.pop_back();
                    std::size_t length = std::size_t(stack.back()); stack.pop_back();
                    for( std::size_t i = 0; i < l; i++ ) stack.pop_back();

                    std::size_t next_mem = std::max(length == 0? 0: offset + length, memory.size());
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());
                    if( memory.size() < next_mem ) memory.resize(next_mem, 0);

                    std::size_t gas_cost = 375 + 375 * l + 8 * length + memory_expansion;
                    decrease_gas(gas_cost);
                    pc++;
                }

                virtual void gas_opcode() {
                    decrease_gas(2);
                    stack.push_back(gas);
                    pc++;
                }
                virtual void pc_opcode() {
                    decrease_gas(2);
                    stack.push_back(pc);
                    pc++;
                }
                virtual void msize_opcode() {
                    decrease_gas(2);
                    stack.push_back(((memory.size() + 31)/32)*32);
                    pc++;
                }

                virtual void extcodesize(){
                    zkevm_word_type addr = stack.back(); stack.pop_back();
                    stack.push_back(_accounts_current_state[addr].bytecode.size());
                    if( _call_stack.back().was_accessed.count({addr, 1, 0}) == 0){
                        decrease_gas(2500);
                    }
                    decrease_gas(100);
                    _call_stack.back().was_accessed.insert({addr, 1, 0});
                    pc++;
                }
                virtual void extcodehash(){
                    zkevm_word_type addr = stack.back(); stack.pop_back();
                    stack.push_back(_accounts_current_state[addr].code_hash);
                    if( _call_stack.back().was_accessed.count({addr, 1, 0}) == 0){
                        decrease_gas(2500);
                    }
                    decrease_gas(100);
                    _call_stack.back().was_accessed.insert({addr, 1, 0});
                    pc++;
                }

                virtual void basefee() {
                    stack.push_back(block.basefee);
                    decrease_gas(2);
                    pc++;
                }

                virtual void blockhash(){
                    // TODO! Load more data!
                    std::size_t n = std::size_t(stack.back()); stack.pop_back();
                    if(n == (block.number - 1)) {
                        stack.push_back(block.parent_hash);
                    } else  {
                        BOOST_LOG_TRIVIAL(trace) << "n = " << n;
                        for( auto & [k,v]: block.old_blocks_hashes){
                            BOOST_LOG_TRIVIAL(trace) << "block number " << k << " : " << std::hex << v << std::dec;
                            if( k == n ) BOOST_LOG_TRIVIAL(trace) << "BINGO!";
                        }
                        BOOST_ASSERT( block.old_blocks_hashes.find(n) != block.old_blocks_hashes.end());
                        // if( block.old_blocks_hashes.find(n) == block.old_blocks_hashes.end()){ {
                        //     BOOST_LOG_TRIVIAL(trace) << " block number " << n << " was not loaded";
                        // }
                        //BOOST_ASSERT(old_blocks_hashes.find(n) == block.old_blocks_hashes.end());
                        stack.push_back(block.old_blocks_hashes[n]);
                    }
                    pc++;
                    decrease_gas(20);
                }

                virtual void blobhash() {
                    std::size_t index = std::size_t(stack.back()); stack.pop_back();
                    if( index >= tx.blob_versioned_hashes.size() ){
                        stack.push_back(0);
                    } else {
                        stack.push_back(tx.blob_versioned_hashes[index]);
                    }
                    decrease_gas(3);
                    pc++;
                }

                virtual void blobbasefee() {
                    // TODO: Understand why!
                    stack.push_back(1);
                    decrease_gas(2);
                    pc++;
                }

                virtual void coinbase(){
                    stack.push_back(block.coinbase);
                    _call_stack.back().was_accessed.insert({block.coinbase, 1, 0});
                    decrease_gas(2);
                    pc++;
                }
                virtual void timestamp(){
                    stack.push_back(block.timestamp);
                    decrease_gas(2);
                    pc++;
                }
                virtual void number(){
                    stack.push_back(block.number);
                    decrease_gas(2);
                    pc++;
                }
                virtual void difficulty(){
                    stack.push_back(block.difficulty);
                    decrease_gas(2);
                    pc++;
                }
                virtual void chainid() {
                    stack.push_back(tx.chain_id);
                    decrease_gas(2);
                    pc++;
                }
                virtual void returndatasize(){
                    stack.push_back(returndata.size());
                    pc++;
                    decrease_gas(2);
                }
                virtual void returndatacopy(){
                    std::size_t dst = std::size_t(stack.back()); stack.pop_back();
                    std::size_t src = std::size_t(stack.back()); stack.pop_back();
                    std::size_t length = std::size_t(stack.back()); stack.pop_back();

                    std::size_t minimum_word_size = (length + 31) / 32;
                    std::size_t next_mem = std::max(dst + length, memory.size());
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());
                    std::size_t next_memory_size = (memory_size_word_util(next_mem))*32;

                    if( memory.size() < dst + length) memory.resize(dst + length);
                    for( std::size_t i = 0; i < length; i++){
                        memory[dst+i] = src + i < returndata.size()? returndata[src+i]: 0;
                    }

                    decrease_gas(3 + 3 * minimum_word_size + memory_expansion); //dynamic gas
                    pc++;
                }

                void gasprice() {
                    stack.push_back(tx.gasprice);
                    decrease_gas(2);
                    pc++;
                }

                void create() {
                    zkevm_word_type value = stack.back(); stack.pop_back();
                    call_args_offset = std::size_t(stack.back()); stack.pop_back();
                    call_args_length = std::size_t(stack.back()); stack.pop_back();
                    BOOST_LOG_TRIVIAL(trace) << "create: " << std::hex << call_context_address  << std::dec;

                    _call_stack.back().lastcall_returndataoffset = 0;
                    _call_stack.back().lastcall_returndatalength = 0;

                    // TODO: Compute address ourselves
                    caller = call_context_address;

                    std::size_t next_mem = std::max(memory.size(), call_args_length == 0? 0: call_args_offset + call_args_length);
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());
                    if( memory.size() < next_mem ){
                        memory.resize(next_mem);
                    }
                    decrease_gas(memory_expansion);
                    // TODO: Add address computation here!
                    decrease_gas(32000);
                    std::size_t call_args_word_size = (call_args_length + 31) / 32;
                    decrease_gas(call_args_word_size * 2);

                    std::vector<std::uint8_t> sender_bytes;
                    zkevm_word_type mask = (zkevm_word_type(0xFF) << (8 * 19));
                    for( std::size_t i = 0; i < 20; i++){
                        sender_bytes.push_back(std::uint8_t(std::size_t((call_context_address & mask) >> (8 * (19 - i))) % 256));
                        mask >>= 8;
                    }

                    std::size_t nonce = _accounts_current_state[call_context_address].seq_no;
                    _accounts_current_state[call_context_address].seq_no ++;
                    nonce += 1;

                    create_hashed_bytes.clear();
                    if(nonce == 0x00) {
                        create_hashed_bytes.push_back(0xd6);
                        create_hashed_bytes.push_back(0x94);
                        create_hashed_bytes.insert(create_hashed_bytes.end(), sender_bytes.begin(), sender_bytes.end());
                        create_hashed_bytes.push_back(0x80);
                    } else if( nonce <= 0x7f ){
                        create_hashed_bytes.push_back(0xd6);
                        create_hashed_bytes.push_back(0x94);
                        create_hashed_bytes.insert(create_hashed_bytes.end(), sender_bytes.begin(), sender_bytes.end());
                        create_hashed_bytes.push_back(std::uint8_t(nonce));
                    } else if( nonce <= 0xff ){
                        create_hashed_bytes.push_back(0xd7);
                        create_hashed_bytes.push_back(0x94);
                        create_hashed_bytes.insert(create_hashed_bytes.end(), sender_bytes.begin(), sender_bytes.end());
                        create_hashed_bytes.push_back(0x81);
                        create_hashed_bytes.push_back(std::uint8_t(nonce));
                    } else if( nonce <= 0xffff ){
                        create_hashed_bytes.push_back(0xd8);
                        create_hashed_bytes.push_back(0x94);
                        create_hashed_bytes.insert(create_hashed_bytes.end(), sender_bytes.begin(), sender_bytes.end());
                        create_hashed_bytes.push_back(0x82);
                        create_hashed_bytes.push_back(std::uint8_t((nonce >> 8)%256));
                        create_hashed_bytes.push_back(std::uint8_t((nonce)%256));
                    }  else if( nonce <= 0xffffff ){
                        create_hashed_bytes.push_back(0xd9);
                        create_hashed_bytes.push_back(0x94);
                        create_hashed_bytes.insert(create_hashed_bytes.end(), sender_bytes.begin(), sender_bytes.end());
                        create_hashed_bytes.push_back(0x83);
                        create_hashed_bytes.push_back(std::uint8_t((nonce >> 16)%256));
                        create_hashed_bytes.push_back(std::uint8_t((nonce >> 8)%256));
                        create_hashed_bytes.push_back(std::uint8_t((nonce)%256));
                    } else {
                        create_hashed_bytes.push_back(0xda);
                        create_hashed_bytes.push_back(0x94);
                        create_hashed_bytes.insert(create_hashed_bytes.end(), sender_bytes.begin(), sender_bytes.end());
                        create_hashed_bytes.push_back(0x84);
                        create_hashed_bytes.push_back(std::uint8_t((nonce >> 24)%256));
                        create_hashed_bytes.push_back(std::uint8_t((nonce >> 16)%256));
                        create_hashed_bytes.push_back(std::uint8_t((nonce >> 8)%256));
                        create_hashed_bytes.push_back(std::uint8_t((nonce)%256));
                    }
                    BOOST_LOG_TRIVIAL(trace) << "create_hashed_bytes: " << byte_vector_to_sparse_hex_string(create_hashed_bytes) << std::dec;

                    call_value = value;
                    call_is_create = true;
                    call_is_create2 = false;
                    call_is_precompile = false;
                    call_gas_sent = gas;
                    is_start_call = true;
                }

                void create2() {
                    zkevm_word_type value = stack.back(); stack.pop_back();
                    call_args_offset = std::size_t(stack.back()); stack.pop_back();
                    call_args_length = std::size_t(stack.back()); stack.pop_back();
                    zkevm_word_type salt = stack.back(); stack.pop_back();

                    _call_stack.back().lastcall_returndataoffset = 0;
                    _call_stack.back().lastcall_returndatalength = 0;

                    BOOST_LOG_TRIVIAL(trace) << "create2: " << std::hex << call_context_address << " " << salt << std::dec;
                    // TODO: Compute address ourselves
                    caller = call_context_address;

                    std::size_t next_mem = std::max(memory.size(), call_args_length == 0? 0: call_args_offset + call_args_length);
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());
                    if( memory.size() < next_mem ){
                        memory.resize(next_mem);
                    }
                    decrease_gas(memory_expansion);
                    decrease_gas(32000);
                    std::size_t call_args_word_size = (call_args_length + 31) / 32;
                    decrease_gas(call_args_word_size * 8);

                    create_hashed_bytes.clear();
                    create_hashed_bytes.push_back(0xff);
                    zkevm_word_type mask = (zkevm_word_type(0xFF) << (8 * 19));
                    for( std::size_t i = 0; i < 20; i++){
                        create_hashed_bytes.push_back(std::uint8_t(std::size_t((call_context_address & mask) >> (8 * (19 - i))) % 256));
                        mask >>= 8;
                    }
                    mask = (zkevm_word_type(0xFF) << (8 * 31));
                    for( std::size_t i = 0; i < 32; i++){
                        create_hashed_bytes.push_back(std::uint8_t(std::size_t((salt & mask) >> (8 * (31 - i))) % 256));
                        mask >>= 8;
                    }

                    call_value = value;
                    call_is_create = false;
                    call_is_create2 = true;
                    call_is_precompile = false;
                    call_gas_sent = gas;
                    call_status = call_context_address;
                    is_start_call = true;
                }

                void selfdestruct() {
                    auto addr = stack.back(); stack.pop_back();
                    decrease_gas(5000);
                    if( _existing_accounts.count(addr) == 0){
                        decrease_gas(25000);
                    }
                    if(_call_stack.back().was_accessed.count({addr, 1, 0}) == 0){
                        decrease_gas(2500);
                    }
                    _existing_accounts.erase(call_context_address);
                    _accounts_current_state[addr].balance += _accounts_current_state[call_context_address].balance;
                    _accounts_current_state[call_context_address].balance = 0;
                    _call_stack[_call_stack.size()-2].was_accessed.insert(_call_stack.back().was_accessed.begin(), _call_stack.back().was_accessed.end());
                    for( auto & [k,v]: _call_stack.back().transient_storage){
                        _call_stack[_call_stack.size()-2].transient_storage[k] = v;
                    }
                    returndata.clear();
                    call_status = call_context_address;
                    is_end_call = true;
                }

                virtual void codesize() {
                    stack.push_back(bytecode.size());
                    decrease_gas(2);
                    pc++;
                }

                virtual void codecopy() {
                    // 6M memory bytes gives 60M+ gas cost
                    // max gas cost is 36M for now, might go up to 60M
                    constexpr static const std::size_t max_dest_offset = 8388608;  // 2^23
                    // max contract size is 24,576 bytes, so offset and length need to fit in
                    // first chunk
                    constexpr static const std::size_t max_offset = 65536;
                    constexpr static const std::size_t max_length = 65536;
                    std::size_t dst = std::size_t(stack.back()); stack.pop_back();
                    std::size_t src = std::size_t(stack.back()); stack.pop_back();
                    std::size_t length = std::size_t(stack.back()); stack.pop_back();

                    bool overflow = (dst > max_dest_offset) ||
                                    (src > max_offset) ||
                                    (length > max_length);

                    std::size_t minimum_word_size = (length + 31) / 32;
                    std::size_t next_mem = std::max(dst + length, memory.size());
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());
                    std::size_t next_memory_size = memory_size_word_util(next_mem) * 32;


                    if (overflow) {
                        memory.resize(memory.size() - 1);
                        increase_gas(1);
                    }
                    else {
                        if( memory.size() < dst + length) memory.resize(next_memory_size);
                        for( std::size_t i = 0; i < length; i++){
                            memory[dst+i] = src + i < bytecode.size()? bytecode[src+i]: 0;
                        }
                        decrease_gas(3 + 3 * minimum_word_size + memory_expansion); //dynamic gas
                    }
                    pc++;
                }

                virtual void delegatecall(){
                    call_is_create = false;
                    call_is_create2 = false;
                    call_is_precompile = false;
                    call_gas_sent = std::size_t(stack.back());  stack.pop_back();
                    call_addr = stack.back()& 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256;;  stack.pop_back();
                    call_value = 0;
                    call_args_offset = std::size_t(stack.back());  stack.pop_back();
                    call_args_length = std::size_t(stack.back());  stack.pop_back();
                    std::size_t ret_offset = std::size_t(stack.back());  stack.pop_back();
                    std::size_t ret_length = std::size_t(stack.back());  stack.pop_back();
                    _call_stack.back().lastcall_returndataoffset = ret_offset;
                    _call_stack.back().lastcall_returndatalength = ret_length;

                    std::size_t next_mem = memory.size();
                    next_mem = std::max(next_mem, ret_length == 0? 0: ret_offset + ret_length);
                    next_mem = std::max(next_mem, call_args_length ==0? 0: call_args_offset + call_args_length);
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());
                    if( memory.size() < next_mem) memory.resize(next_mem, 0);
                    decrease_gas(memory_expansion);
                    is_start_call = true;
                }

                virtual void execute_precompile() {
                    BOOST_LOG_TRIVIAL(trace) << "Precompile "
                                             << std::hex << call_addr << std::dec
                                             << " execute call" << std::endl;

                    auto result = evaluate_precompile(
                            Precompile{size_t(call_addr)}, gas, calldata);

                    decrease_gas(result.gas_used);
                    call_status = result.success;
                    returndata = result.data;
                };

                virtual void staticcall() {
                    call_gas_sent = stack.back();  stack.pop_back();
                    call_addr = stack.back() & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256;  stack.pop_back();
                    call_value = 0;
                    call_context_value = 0;
                    call_args_offset = std::size_t(stack.back());  stack.pop_back();
                    call_args_length = std::size_t(stack.back());  stack.pop_back();
                    caller = call_context_address;
                    std::size_t ret_offset = std::size_t(stack.back());  stack.pop_back();
                    std::size_t ret_length = std::size_t(stack.back());  stack.pop_back();
                    _call_stack.back().lastcall_returndataoffset = ret_offset;
                    _call_stack.back().lastcall_returndatalength = ret_length;

                    call_is_create = false;
                    call_is_create2 = false;
                    call_is_precompile = call_addr >= 0x1 && call_addr <= 0xa;

                    // TODO: check memory expansion
                    std::size_t next_mem = memory.size();
                    next_mem = std::max(next_mem, ret_length == 0? 0: ret_offset + ret_length);
                    next_mem = std::max(next_mem, call_args_length ==0? 0: call_args_offset + call_args_length);
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());
                    if( memory.size() < next_mem) memory.resize(next_mem, 0);
                    decrease_gas(memory_expansion);

                    call_context_address = call_addr;
                    is_start_call = true;
                }

                virtual void transfer_to_eth_account(){
                    BOOST_LOG_TRIVIAL(trace) << "Transfer to eth account" << std::endl;
                    std::size_t transfer_gas = std::size_t(stack.back());  stack.pop_back();
                    zkevm_word_type transfer_addr = stack.back() & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256; stack.pop_back();
                    zkevm_word_type transfer_value = stack.back();  stack.pop_back();
                    std::size_t transfer_args_offset = std::size_t(stack.back());  stack.pop_back();
                    std::size_t transfer_args_length = std::size_t(stack.back());  stack.pop_back();
                    std::size_t ret_offset = std::size_t(stack.back());  stack.pop_back();
                    std::size_t ret_length = std::size_t(stack.back());  stack.pop_back();
                    _call_stack.back().lastcall_returndataoffset = ret_offset;
                    _call_stack.back().lastcall_returndatalength = ret_length;

                    BOOST_LOG_TRIVIAL(trace) << "transfer_gas gas = " << transfer_gas << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "caller = 0x" << std::hex << call_context_address << " balance = " << _accounts_current_state[caller].balance << std::dec << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "transfer_addr = 0x" << std::hex << transfer_addr << " balance = " << _accounts_current_state[call_addr].balance << std::dec << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "transfer_value = 0x" << std::hex << transfer_value << std::dec << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "transfer_args_offset = " << transfer_args_offset << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "transfer_args_length = " << transfer_args_length << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "return offset = " << ret_offset << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "return length = " << ret_length << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "gas = " << gas << std::endl;

                    decrease_gas(100);
                    if( _call_stack.back().was_accessed.count({transfer_addr, 1, 0}) == 0) {
                        decrease_gas(2500);
                        _call_stack.back().was_accessed.insert({transfer_addr, 1, 0});
                    }
                    if( transfer_value != 0 ) { decrease_gas( 9000  - 2300 ); }
                    if( transfer_value != 0 && (_existing_accounts.count(transfer_addr) == 0)) {
                        BOOST_LOG_TRIVIAL(trace) << "Account is not exist" << std::endl;
                        decrease_gas(25000);
                    }
                    // else {
                    //     // TODO! Input problem. We cannot distinguish non-existing account from existing account with zero balance
                    //     if( gas != last_opcode_gas_used){
                    //         BOOST_LOG_TRIVIAL(trace) << "Transfer to empty account error:" << gas << " != " << last_opcode_gas_used << std::endl;
                    //     }
                    //     gas = last_opcode_gas_used;
                    // }

                    stack.push_back(1);
                    BOOST_LOG_TRIVIAL(trace) << "transfer completed" << std::endl;
                    pc++;
                    _accounts_current_state[call_context_address].balance -= transfer_value;
                    _accounts_current_state[transfer_addr].balance += transfer_value;
                    returndata.clear();
                    //returndata.resize(transfer_args_length, 0);
                }

                virtual void call(){
                    call_is_precompile = stack[stack.size() - 2] >= 0x1 && stack[stack.size() - 2] <= 0xa;
                    if (!call_is_precompile &&
                        _accounts_current_state[stack[stack.size() - 2] & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256].bytecode.size() == 0) {
                        this->transfer_to_eth_account();
                        return;
                    }
                    BOOST_LOG_TRIVIAL(trace) << std::hex << "Call opcode args length " << stack[stack.size() - 5] << " value " << stack[stack.size() - 3] << std::endl;

                    call_is_create = false;
                    call_is_create2 = false;
                    call_gas_sent = stack.back();  stack.pop_back();
                    // TODO: add this xor to circuits!
                    call_addr = stack.back() & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256; stack.pop_back();
                    call_context_value = call_value = stack.back();  stack.pop_back();
                    call_args_offset = std::size_t(stack.back());  stack.pop_back();
                    call_args_length = std::size_t(stack.back());  stack.pop_back();
                    caller = call_context_address;
                    std::size_t ret_offset = std::size_t(stack.back());  stack.pop_back();
                    std::size_t ret_length = std::size_t(stack.back());  stack.pop_back();
                    _call_stack.back().lastcall_returndataoffset = ret_offset;
                    _call_stack.back().lastcall_returndatalength = ret_length;
                    _accounts_current_state[caller].balance -= call_value;
                    _accounts_current_state[call_addr].balance += call_value;

                    BOOST_LOG_TRIVIAL(trace) << "call gas = " << call_gas_sent << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "caller = 0x" << std::hex << call_context_address << " balance = " << _accounts_current_state[caller].balance << std::dec << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "callee = 0x" << std::hex << call_addr << " balance = " << _accounts_current_state[call_addr].balance << std::dec << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "value = 0x" << std::hex << call_value << std::dec << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "call args offset = " << call_args_offset << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "call args length = " << call_args_length << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "return offset = " << ret_offset << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "return length = " << ret_length << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "gas = " << gas << std::endl;

                    // TODO: check memory expansion
                    std::size_t next_mem = memory.size();
                    next_mem = std::max(next_mem, call_args_length == 0 ? 0: call_args_offset + call_args_length);
                    next_mem = std::max(next_mem, ret_length == 0 ? 0: ret_offset + ret_length);
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());

                    if( memory.size() < next_mem) {
                        BOOST_LOG_TRIVIAL(trace) << "Memory expansion = " << memory_expansion << std::endl;
                        BOOST_LOG_TRIVIAL(trace) << "Memory size = " << memory.size() << std::endl;
                        BOOST_LOG_TRIVIAL(trace) << "After calldata = " << call_args_offset << " " <<  call_args_length << std::endl;
                        BOOST_LOG_TRIVIAL(trace) << "After return = " << ret_offset << " " <<  ret_length << std::endl;
                        memory.resize(next_mem, 0);
                    }
                    decrease_gas(memory_expansion);

                    if( call_value != 0 ) {
                        BOOST_LOG_TRIVIAL(trace) << "Value is not zero" << std::endl;
                        decrease_gas(9000);
                    }
                    if( call_value != 0 && (_existing_accounts.count(call_addr) == 0)) {
                        BOOST_LOG_TRIVIAL(trace) << "Account is not exist" << std::endl;
                        decrease_gas(25000);
                    }
                    call_context_address = call_addr;
                    is_start_call = true;
                }

                virtual void end_transaction(){
                    BOOST_LOG_TRIVIAL(trace) << "basic_evm::End transaction" << std::endl;
                    auto returned_call = _call_stack.back();
                    _call_stack.pop_back();
                    depth--;
                    current_opcode = opcode_to_number(zkevm_opcode::end_transaction);

                    std::size_t returndataoffset = _call_stack.back().lastcall_returndataoffset; // caller CALL opcode parameters
                    std::size_t returndatalength = _call_stack.back().lastcall_returndatalength; // caller CALL opcode parameters

                    pc = 0;
                    stack.clear();
                    memory.clear();
                    returndata.clear();
                    calldata.clear();
                    // _accounts_current_state.clear();
                    // _accounts_initial_state.clear();
                    // _existing_accounts.clear();
                }

                virtual void end_block(){
                    BOOST_LOG_TRIVIAL(trace) << "basic_evm::End block" << std::endl;
                    depth--;
                    pc = 0;
                    gas = 0;
                    current_opcode = opcode_to_number(zkevm_opcode::end_block);
                    stack.clear();
                    memory.clear();
                    calldata.clear();
                    returndata.clear();
                    _call_stack.pop_back();
                    _accounts_current_state.clear();
                    _existing_accounts.clear();
                    _call_stack.clear();
                    _accounts_initial_state.clear();
                }

                virtual void gas_error(){
                    BOOST_LOG_TRIVIAL(trace) << "Gas error";
                    returndata.clear();
                    // TODO: It's only gas error!
                    gas = 0;
                    call_status = 0;
                    _accounts_current_state = _call_stack[_call_stack.size() - 1].state;
                    _call_stack.back().was_accessed = _call_stack[_call_stack.size() - 2].was_accessed;
                    _call_stack.back().transient_storage = _call_stack[_call_stack.size() - 2].transient_storage;
                    is_end_call = true;
                }

            protected:
                template <typename T>
                bool check_equal(T a, T b, std::string message, bool print_hex = true) {
                    bool condition = (a == b);
                    std::stringstream es;
                    if( !condition ){
                        if( print_hex )
                            es << message << std::hex <<  " "  <<  a <<  " != " << b << std::dec;
                        else
                            es << message <<  " "  <<  a <<  " != " << b;
                        error_message = es.str();
                        execution_status = false;
                        BOOST_LOG_TRIVIAL(error) << error_message;
                    }
                    return condition;
                }

                bool check(bool condition, std::string message) {
                    if( !condition ) {
                        error_message = message;
                        execution_status = false;
                        BOOST_LOG_TRIVIAL(error) << "Error: " << message;
                    }
                    return condition;
                }

                void decrease_gas(std::size_t cost) {
                    if( cost > gas ){
                        BOOST_LOG_TRIVIAL(trace) << "Gas limit exceeded";
                        this->gas_error();
                    } else {
                        gas -= cost;
                    }
                }

                void increase_gas(std::size_t cost) {
                    gas += cost;
                }

                // Should be called *after* memory expansion, address access
                // and transfer fees are deducted.
                size_t cap_call_gas(zkevm_word_type gas_sent) {
                    size_t cap = gas - gas / 64;
                    return gas_sent > cap ? cap : size_t(gas_sent);
                }

                void print_accounts_current_state() {
                    for( auto &[addr, acc]:_accounts_current_state){
                        for( auto &[k,v]: acc.storage){
                            BOOST_LOG_TRIVIAL(trace) << "{" << std::hex <<  addr << ", " << k << "} = " << v << std::dec;
                        }
                    }
                }

            public:
                zkevm_basic_evm(abstract_block_loader *_block_loader):block_loader(_block_loader), pc(0), gas(0) {}
                virtual ~zkevm_basic_evm(){
                    _call_stack.clear();
                    _existing_accounts.clear();
                    _accounts_current_state.clear();
                    _accounts_initial_state.clear();
                    BOOST_LOG_TRIVIAL(trace) << "Destructor of zkevm_basic_evm";
                }
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil
