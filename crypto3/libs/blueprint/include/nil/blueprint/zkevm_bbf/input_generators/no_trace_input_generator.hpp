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
            class zkevm_no_trace_input_generator:zkevm_abstract_input_generator{
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
                zkevm_word_type tx_value;
                zkevm_word_type tx_hash;
                zkevm_word_type call_caller;
                zkevm_word_type block_hash;
                zkevm_word_type transaction_hash;
                zkevm_word_type call_context_address;
                zkevm_word_type block_timestamp;
                std::vector<std::uint8_t> calldata;
                std::vector<std::uint8_t> returndata;

                // internal execution
                std::vector<zkevm_word_type> stack;
                std::vector<std::uint8_t> memory;
                std::vector<std::uint8_t> bytecode;
                std::set<zkevm_word_type> _bytecode_hashes;

                std::map<zkevm_opcode, std::size_t> _unknown_opcodes;
                std::size_t finished_transactions;
                std::size_t failed_transactions;
                std::size_t block_transactions;

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
                zkevm_no_trace_input_generator(
                    const boost::property_tree::ptree &tree
                ){
                    rw_counter = 1;
                    std::cout << "ZKEVM NO_TRACE INPUT GENERATOR loaded" << std::endl;
                    auto pt_block = tree.get_child("block");
                    start_block(pt_block.get_child("hash").data(), pt_block);
                    block_transactions = tree.get_child("transactions").size();

                    std::set<std::string> debugged_txs;
                    debugged_txs.insert("0x56dff2a38ae1493c76541bcaf7e2c58b45789b70329b24a77e22d2d8905eaa15");
                    debugged_txs.insert("0xcddbf962c8b8926b82b3fad38c2cd4e772475858cdb2b3c90d4ff2a25115374a");
                    for( auto &tt: tree.get_child("transactions")){
                        start_transaction(tt.second.get_child("tx_hash").data(), tt.second.get_child("details"));
                        if( debugged_txs.find(std::string(tt.second.get_child("tx_hash").data())) == debugged_txs.end()){
                            load_accounts(tt.second.get_child("execution_trace.prestate_trace"));
                            execute_transaction();
                        } else {
                            std::cout << "DEBUGGING " << tt.second.get_child("tx_hash").data() << std::endl;
                        }
                        end_transaction(tt.second);
                        break;
                    }
                    end_block(pt_block);
                    std::size_t sum_bytecode_rows = 0;
                    for( auto &b: _bytecodes.get_data()){
                        sum_bytecode_rows += b.first.size() + 1;
                    }
                    std::cout << "Bytecode rows: " << sum_bytecode_rows << std::endl;
                    std::cout << "Bytecodes: " << _bytecodes.get_data().size() << std::endl;
                    std::cout << "Read-write operations: " << _rw_operations.size() << std::endl;
                    std::cout << "zkEVM states: " << _zkevm_states.size() << std::endl;
                    std::cout
                        << " Finished: " << finished_transactions
                        << " Failed: " << failed_transactions
                        << " of " << block_transactions << std::endl;
                    std::cout << "Implement opcodes before others: " << std::endl;
                    for( auto [op, v]: _unknown_opcodes){
                        std::cout << "\t" <<  op << " " << v << " transactions" << std::endl;
                    }
                    exit(0);
                }

                void start_block(zkevm_word_type _block_hash, const boost::property_tree::ptree &pt){
                    last_write_rw_counter.clear();
                    finished_transactions = 0;
                    failed_transactions = 0;
                    block_id = rw_counter++;
                    block_hash = block_hash;
                    tx_id = 0;
                    depth = 1;
                    tx_hash = 0;
                    //block_timestamp = zkevm_word_from_string(pt.get_child("timestamp").data());

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
                    tx_to = zkevm_word_from_string(tt.get_child("to").data());
                    tx_from = zkevm_word_from_string(tt.get_child("from").data());
                    call_caller = 0;
                    tx_value = zkevm_word_from_string(tt.get_child("value").data());
                    gas = std::size_t(zkevm_word_from_string(tt.get_child("gas").data()));
                    tx_hash = zkevm_word_from_string(_tx_hash);

                    current_opcode = opcode_to_number(zkevm_opcode::start_transaction);
                    call_context_address = tx_to;
                    calldata = byte_vector_from_hex_string(tt.get_child("input").data(), 2);
                    std::cout << "START TRANSACTION " << tx_id
                        << " to " << std::hex << tx_to
                        << " hash = " << tx_hash << std::dec
                        << std::endl;
                    std::cout << "CALLDATA size = " << calldata.size() << " : ";
                    for( auto &c: calldata){
                        std::cout << std::hex << std::size_t(c) << std::dec << " ";
                    }

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
                void execute_transaction(){
                    stack = {};
                    memory = {};
                    pc = 0;
                    bytecode = _accounts_initial_state[tx_to].bytecode;
                    bytecode_hash = _accounts_initial_state[tx_to].code_hash;
                    if( bytecode.size() == 0) return;
                    while( true ) {
                        BOOST_ASSERT(pc < bytecode.size());
                        current_opcode = bytecode[pc];
                        std::cout << "\t" << pc << ". " << opcode_from_number(current_opcode) << " ";
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH0 ) pushx(0); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH1 ) pushx(1); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH2 ) pushx(2); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH3 ) pushx(3); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH4 ) pushx(4); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH5 ) pushx(5); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH6 ) pushx(6); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH7 ) pushx(7); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH8 ) pushx(8); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH9 ) pushx(9); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH10 ) pushx(10); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH11 ) pushx(11); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH12 ) pushx(12); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH13 ) pushx(13); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH14 ) pushx(14); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH15 ) pushx(15); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH16 ) pushx(16); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH17 ) pushx(17); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH18 ) pushx(18); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH19 ) pushx(19); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH20 ) pushx(20); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH21 ) pushx(21); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH22 ) pushx(22); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH23 ) pushx(23); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH24 ) pushx(24); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH25 ) pushx(25); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH26 ) pushx(26); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH27 ) pushx(27); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH28 ) pushx(28); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH29 ) pushx(29); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH30 ) pushx(30); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH31 ) pushx(31); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::PUSH32 ) pushx(32); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::MSTORE ) mstore(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::MLOAD ) mload(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::DUP1 ) dupx(1); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::DUP2 ) dupx(2); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::DUP3 ) dupx(3); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::DUP4 ) dupx(4); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::DUP5 ) dupx(5); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::DUP6 ) dupx(6); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::DUP7 ) dupx(7); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::DUP8 ) dupx(8); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::DUP9 ) dupx(9); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::DUP10 ) dupx(10); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::DUP11 ) dupx(11); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::DUP12 ) dupx(12); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::DUP13 ) dupx(13); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::DUP14 ) dupx(14); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::DUP15 ) dupx(15); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::DUP16 ) dupx(16); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::SWAP1 ) swapx(1); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::SWAP2 ) swapx(2); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::SWAP3 ) swapx(3); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::SWAP4 ) swapx(4); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::SWAP5 ) swapx(5); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::SWAP6 ) swapx(6); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::SWAP7 ) swapx(7); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::SWAP8 ) swapx(8); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::SWAP9 ) swapx(9); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::SWAP10 ) swapx(10); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::SWAP11 ) swapx(11); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::SWAP12 ) swapx(12); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::SWAP13 ) swapx(13); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::SWAP14 ) swapx(14); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::SWAP15 ) swapx(15); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::SWAP16 ) swapx(16); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::JUMP ) {
                            jump();
                            if(opcode_from_number(bytecode[pc]) != zkevm_opcode::JUMPDEST) { std::cout << "FAILED!!!" << failed_transactions++; return; }
                        } else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::JUMPDEST ) jumpdest(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::ORIGIN ) origin(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::ADDRESS ) address_opcode(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::CALLVALUE ) callvalue(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::CALLDATASIZE ) calldatasize(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::RETURNDATASIZE ) returndatasize(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::CALLER ) caller(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::ISZERO ) iszero(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::LT ) lt(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::GT ) gt(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::SLT ) slt(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::SGT ) sgt(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::BYTE ) byte(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::SHL ) shl(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::SHR ) shr(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::SAR ) sar(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::EQ ) eq(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::JUMPI ) jumpi(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::POP ) pop(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::ADD ) add(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::SUB ) sub(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::MUL ) mul(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::DIV ) div(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::MOD ) mod(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::CALLDATALOAD ) calldataload(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::AND ) and_opcode(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::OR ) or_opcode(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::XOR ) xor_opcode(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::NOT ) not_opcode(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::EXP ) exp(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::KECCAK256 ) keccak256(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::TIMESTAMP ) timestamp(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::GAS ) gas_opcode(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::SLOAD ) sload(); else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::STOP ) {
                            stop();
                            finished_transactions++;
                            return;
                        } else
                        if( opcode_from_number(current_opcode) == zkevm_opcode::INVALID ) {
                            stop();
                            finished_transactions++;
                            return;
                        } else {
                            if( _unknown_opcodes.find(opcode_from_number(current_opcode)) == _unknown_opcodes.end() )
                                _unknown_opcodes[opcode_from_number(current_opcode)] = 1;
                            else
                                _unknown_opcodes[opcode_from_number(current_opcode)]++;
                            std::cout << "Non-implemented opcode " << opcode_from_number(current_opcode) << std::endl;
                            break;
                        }
                        std::cout << std::endl;
                    }
                }

                void end_transaction(const boost::property_tree::ptree &tt){
                    append_modified_items_rw_operations();
                    std::cout << "END TRANSACTION " << tx_id;
                    basic_zkevm_state_part base;
                    base.call_id = tx_id;                // RW counter on start_call
                    base.bytecode_hash = bytecode_hash;
                    base.opcode = opcode_to_number(zkevm_opcode::end_transaction);
                    base.rw_counter = tx_id;

                    auto call_context = get_call_header_state_part();
                    auto returned_call = _call_stack.back();
                    _call_stack.pop_back();
                    depth--;
                    _zkevm_states.push_back(zkevm_state(base, call_context));
                    std::size_t returndataoffset = _call_stack.back().lastcall_returndataoffset; // caller CALL opcode parameters
                    std::size_t returndatalength = _call_stack.back().lastcall_returndatalength; // caller CALL opcode parameters
                    std::size_t subcall_id = call_id;

                    std::cout << "\treturndataoffset = " << std::hex << returndataoffset;
                    std::cout << "\treturndataoffset = " << std::hex << returndatalength;
                    std::cout << "\tsubcall_id = " << std::hex << subcall_id << std::endl;
                    std::cout << std::dec <<std::endl;

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

                void pushx(std::size_t x){
                    zkevm_word_type additional_input;
                    for( std::size_t i = pc+1; i < pc + x + 1; i++){
                        additional_input *= 0x100;
                        additional_input += bytecode[i];
                    }
                    std::cout << "\t" << std::hex << additional_input << std::dec;
                    _zkevm_states.push_back(push_zkevm_state(get_basic_zkevm_state_part(), additional_input));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, additional_input));
                    stack.push_back(additional_input);
                    pc += x+1;
                    gas -= x==0? 2: 3;
                }

                void jump(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                    pc = std::size_t(stack.back());
                    std::cout << " pc = " << pc;
                    stack.pop_back();
                    gas -= 8;
                }

                void jumpdest(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
                    gas -= 1;
                    pc++;
                }

                void pop(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
                    stack.pop_back();
                    gas -= 2;
                    pc++;
                }

                void dupx(std::size_t d){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-d, rw_counter++, false, stack[stack.size()-d]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, stack[stack.size()-d]));
                    stack.push_back(stack[stack.size()-d]);
                    pc++;
                    gas -= 3;
                }

                void swapx(std::size_t s){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, false, stack[stack.size()-1]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size() - s - 1, rw_counter++, false, stack[stack.size() - s - 1]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size() - s - 1, rw_counter++, true, stack[stack.size()-1]));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size()-1, rw_counter++, true, stack[stack.size() - s - 1]));
                    std::swap(stack[stack.size()-1], stack[stack.size() - s - 1]);
                    pc++;
                    gas -= 3;
                }

                void iszero(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size() - 1, rw_counter++, true, stack[stack.size() - 1]));
                    zkevm_word_type a = stack.back();
                    stack.pop_back();
                    zkevm_word_type result = a == 0u? 1u: 0u;
                    stack.push_back(result);
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size() - 1, rw_counter++, true, result));
                    stack.push_back(calldata.size());
                    pc++;
                    gas -= 3;
                }

                void lt(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
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
                }

                void gt(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
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
                }

                void slt(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
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
                }

                void sgt(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
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
                }

                void byte(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
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
                }

                void sub(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
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
                }

                void add(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
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
                }

                void and_opcode(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
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
                }

                void or_opcode(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
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
                }

                void xor_opcode(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
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
                }

                void not_opcode(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
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
                }

                void mul(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
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
                }

                void div(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
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
                }

                void mod(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
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
                }

                void exp(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
                    zkevm_word_type a = stack.back();
                    stack.pop_back();
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, a));
                    zkevm_word_type d = stack.back();
                    stack.pop_back();
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, d));
                    zkevm_word_type result = exp_by_squaring(a, d);
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, result));
                    stack.push_back(result);
                    std::cout << "\tExponentiation: " << a << " ^ " << d << " = " << result;
                    _exponentiations.push_back({a, d});
                    pc++;
                    gas -= 10 + 50 * count_significant_bytes(d);
                }

                void sload(){
                    _zkevm_states.push_back(storage_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part(), get_world_state_state_part()));
                    zkevm_word_type storage_key = stack.back();
                    bool was_item_accessed = _call_stack.back().was_accessed.contains(std::make_tuple(call_context_address, 0, storage_key));
                    stack.pop_back();
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, storage_key));
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
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, _accounts_current_state[call_context_address].storage[storage_key]));
                    stack.push_back(_accounts_current_state[call_context_address].storage[storage_key]);
                    pc++;
                    gas -= was_item_accessed? 100: 2100;
                }

                void keccak256(){
                    _zkevm_states.push_back(memory_zkevm_state(get_basic_zkevm_state_part(), memory));
                    std::size_t offset = std::size_t(stack.back());
                    stack.pop_back();
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, offset));

                    std::size_t length = std::size_t(stack.back());
                    stack.pop_back();
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, length));

                    std::size_t memory_size_before = memory.size();
                    if( offset + length > memory.size()) memory.resize(offset+length, 0);
                    memory_size = memory.size();
                    std::vector<uint8_t> buffer;
                    for( std::size_t i = 0; i < length; i++){
                        buffer.push_back(memory[offset+i]);
                    }
                    zkevm_word_type hash_value = zkevm_keccak_hash(buffer);

                    std::cout << "\tAdd copy event for KECCAK256 length = " << length << std::endl;
                    auto cpy = keccak_copy_event(
                        call_id, offset, rw_counter, hash_value, length
                    );

                    std::size_t offset_small = w_to_16(offset)[15];
                    for( std::size_t i = 0; i < length; i++){
                        _rw_operations.push_back(memory_rw_operation(call_id, offset+i, rw_counter++, false, buffer[i]));
                        cpy.push_byte(buffer[i]);
                    }
                    _copy_events.push_back(cpy);
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, hash_value));
                    stack.push_back(hash_value);
                    _keccaks.new_buffer(buffer);

                    std::size_t minimum_word_size = (length + 31) / 32;
                    std::size_t next_mem = memory.size();
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory_size_before);
                    std::size_t next_memory_size = (memory_size_word_util(next_mem))*32;

                    gas -= (30 + 6 * minimum_word_size + memory_expansion);
                    // TODO: implement keccak256 gas
                    pc++;
                }

                void shr(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
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
                }

                void sar(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
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
                }

                void shl(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
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
                }

                void eq(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
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
                }

                void jumpi(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
                    auto addr = std::size_t(stack.back());
                    stack.pop_back();
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, addr));
                    auto condition = stack.back();
                    stack.pop_back();
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, condition));
                    gas -= 10;
                    pc = condition == 0? pc+1: addr;
                    std::cout << "condition = " << condition << " pc = " << pc;
                }

                void calldatasize(){
                    _zkevm_states.push_back(call_header_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part()));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, calldata.size()));
                    std::cout << "calldatasize = " << calldata.size();
                    stack.push_back(calldata.size());
                    pc++;
                    gas -= 2;
                }

                void address_opcode(){
                    _zkevm_states.push_back(call_header_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part()));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, call_context_address));
                    stack.push_back(call_context_address);
                    pc++;
                    gas -= 2;
                }

                void calldataload(){
                    _zkevm_states.push_back(call_header_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part()));
                    std::size_t offset = std::size_t(stack[stack.size()-1]);
                    stack.pop_back();
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, offset));
                    zkevm_word_type result;
                    for( std::size_t i = 0; i < 32; i++){
                        auto byte = offset+i < calldata.size()? std::size_t(calldata[offset+i]) : 0;
                        _rw_operations.push_back(calldata_rw_operation(
                            call_id, offset + i, rw_counter++, byte
                        ));
                        result <<= 8;
                        result += byte;
                    }
                    std::cout << std::hex << result << std::dec;
                    _rw_operations.push_back(stack_rw_operation(call_id, stack.size() , rw_counter++, true, result));
                    stack.push_back(result);
                    pc++;
                    gas -= 3;
                }

                void calldatacopy(){
                    _zkevm_states.push_back(call_header_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part()));
                }
                void returndatasize(){
                    _zkevm_states.push_back(returndata_zkevm_state(
                        get_basic_zkevm_state_part(),
                        memory,
                        get_call_context_state_part()
                    ));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, returndata.size()));
                    stack.push_back(returndata.size());
                    pc++;
                    gas -= 2;
                }

                void origin(){
                    _zkevm_states.push_back(call_header_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part()));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, tx_from));
                    stack.push_back(tx_from);
                    pc++;
                    gas -= 2;
                }

                void timestamp(){
                    _zkevm_states.push_back(call_header_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part()));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, block_timestamp));
                    stack.push_back(block_timestamp);
                    pc++;
                    gas -= 2;
                }

                void gas_opcode(){
                    _zkevm_states.push_back(simple_zkevm_state(get_basic_zkevm_state_part()));
                    gas -= 2;
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, gas));
                    stack.push_back(gas);
                    pc++;
                }

                void caller(){
                    _zkevm_states.push_back(call_header_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part()));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, call_caller));
                    stack.push_back(call_caller);
                    std::cout << " CALLER = 0x" << std::hex << call_caller << std::dec;
                    pc++;
                    gas -= 2;
                }

                void callvalue(){
                    _zkevm_states.push_back(call_header_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part()));
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, true, tx_value));
                    stack.push_back(tx_value);
                    std::cout << std::hex << tx_value << std::dec;
                    pc++;
                    gas -= 2;
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

                void mstore(){
                    _zkevm_states.push_back(memory_zkevm_state(get_basic_zkevm_state_part(), memory));
                    zkevm_word_type addr = stack.back();
                    std::cout << " addr = " << std::hex << addr << std::dec;
                    stack.pop_back();
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, addr));

                    zkevm_word_type data = stack.back();
                    std::cout << " value = " << std::hex << data << std::dec;
                    stack.pop_back();
                    _rw_operations.push_back(stack_rw_operation(call_id,  stack.size(), rw_counter++, false, data));


                    auto bytes = w_to_8(data);
                    auto addr1 = w_to_16(addr)[15];

                    if( addr1 + 31 >= memory.size() ) memory.resize(addr1 + 31, 0);

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
                }

                void mload(){
                    _zkevm_states.push_back(memory_zkevm_state(get_basic_zkevm_state_part(), memory));
                    zkevm_word_type addr = stack.back();
                    stack.pop_back();
                    BOOST_ASSERT_MSG(addr < 65536, "Cannot process so large memory address"); // for bigger memory operations use hardhat input generator
                    std::size_t addr1 = std::size_t(addr);
                    if( addr1 + 31 >= memory.size() ) memory.resize(addr1 + 31, 0);
                    std::cout << " addr = " << std::hex << addr << std::dec;
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
                    std::cout << " value = 0x" << std::hex << result << std::dec << result;
                    stack.push_back(result);
                    pc++;
                    gas -= 3 + memory_expansion;
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
//                    std::cout << "Update cold access RW operations depth = " << _call_stack.size() << std::endl;
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
//                    std::cout << "Append cold access RW operations depth = " << _call_stack.size()
//                        << " call_id = " << call_context.call_id << std::endl;;
                    _rw_operations.push_back(
                        call_context_rw_operation(
                            call_context.call_id,
                            call_context_field::modified_items,
                            call_context.cold_write_list.size()
                        )
                    );
//                    std::cout << _rw_operations.back() << std::endl;
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

                void load_accounts(const boost::property_tree::ptree &prestate){
                    for( auto &[account_address, account]: prestate){
                        //std::cout << "\t" << account_address.data() << std::endl;
                        zkevm_account acc;
                        acc.address = zkevm_word_from_string(account_address.data());
                        acc.balance = zkevm_word_from_string(account.get_child("balance").data());
                        if( account.get_child_optional("nonce") ){
                            acc.seq_no = acc.ext_seq_no = std::size_t(zkevm_word_from_string(account.get_child("nonce").data()));
                        }
                        if( account.get_child_optional("storage") ){
                            acc.storage = key_value_storage_from_ptree(account.get_child("storage"));
                        }
                        if( account.get_child_optional("code") ){
                            acc.bytecode = byte_vector_from_hex_string(account.get_child("code").data(), 2);
                        }
                        acc.code_hash = zkevm_keccak_hash(acc.bytecode);
                        if( _bytecode_hashes.find(acc.code_hash) == _bytecode_hashes.end() ){
                            _bytecode_hashes.insert(acc.code_hash);
                            _keccaks.new_buffer(acc.bytecode);
                            _bytecodes.new_buffer(acc.bytecode);
                        }
                        _accounts_initial_state[acc.address] = acc ;
                        _accounts_current_state = _accounts_initial_state;
                    }
                }
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil
