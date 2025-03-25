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

#include <nil/blueprint/zkevm_bbf/opcodes/zkevm_opcodes.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            class zkevm_alchemy_input_generator:zkevm_abstract_input_generator{
            protected:
                std::map<zkevm_word_type, zkevm_account>                 _accounts_initial_state; // Initial state; Update it after block.
                std::map<zkevm_word_type, zkevm_account>                 _accounts_current_state; // Initial state; Update it after block.
                std::vector<zkevm_call_context>                          _call_stack;

                zkevm_keccak_buffers                                     _keccaks;
                zkevm_keccak_buffers                                     _bytecodes;
                rw_operations_vector                                     _rw_operations;
                std::vector<copy_event>                                  _copy_events;
                std::vector<zkevm_state>                                 _zkevm_states;
                std::vector<std::pair<zkevm_word_type, zkevm_word_type>> _exponentiations;
                std::map<std::size_t,zkevm_call_commit>                  _call_commits;
                zkevm_word_type                                          _value_from_create;
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
                std::vector<zkevm_word_type> last_opcode_push;

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
                zkevm_alchemy_input_generator(
                    std::string path
                ){
                    opcode_sum = 0;
                    executed_opcodes = 0;
                    stack_rw_operations = 0;
                    memory_rw_operations = 0;
                    calldata_rw_operations = 0;
                    returndata_rw_operations = 0;
                    state_rw_operations = 0;

                    boost::property_tree::ptree tree = load_json_input(path + std::string("block.json"));
                    std::cout << "ZKEVM ALCHEMY INPUT GENERATOR loaded" << std::endl;
                    auto pt_block = tree.get_child("block");
                    start_block(pt_block.get_child("hash").data(), pt_block);
                    block_transactions = tree.get_child("transactions").size();
                    std::size_t tx_order = 0;
                    rw_counter = 0;
                    for( auto &tt: tree.get_child("transactions")){
                        std::string tx_hash_string = tt.second.get_child("tx_hash").data();
                        std::cout << tx_order++ << "." << tx_hash_string << std::endl;
                        auto initial_context = start_transaction(tx_hash_string, tt.second.get_child("details"));
                    //    if( tt.second.get_child("details.type").data() != "0x3") {
                            load_accounts(tt.second.get_child("execution_trace.prestate_trace"));
                            boost::property_tree::ptree tx_trace_tree = load_json_input(path + std::string("tx_" + tx_hash_string + ".json"));
                            // Another RPC bug:( for too big transactions it doesn't produce the trace
                            if (tx_trace_tree.empty())
                                continue;
                            // We must update the bytecode of initial call here
                            bytecode = byte_vector_from_hex_string(tx_trace_tree.get_child("vmTrace.code").data(), 2);
                            initial_context.bytecode = bytecode;
                            _call_stack.push_back(initial_context);
                            bytecode_hash = zkevm_keccak_hash(bytecode);
                            if( _bytecode_hashes.find(bytecode_hash) == _bytecode_hashes.end() ){
                                _bytecode_hashes.insert(bytecode_hash);
                                _keccaks.new_buffer(bytecode);
                                _bytecodes.new_buffer(bytecode);
                            }
                            execute_transaction(tx_trace_tree);
                            end_transaction(tt.second.get_child("details"));
                            std::cout << "Total opcodes amount = " << opcode_sum << std::endl;
                        // } else {
                        //     std::cout << "Type 3 transaction not supported yet" << std::endl;
                        // }
                    }
                    end_block(pt_block);


                    using FieldType = typename nil::crypto3::algebra::curves::pallas::base_field_type;
                    auto opcode_implementations = get_opcode_implementations<FieldType>();
                    std::size_t zkevm_circuit_usable_rows = 0;
                    std::size_t zkevm_circuit_real_rows = 0;
                    for( auto [k,v]: opcode_distribution){
                        std::cout << "\t" << k << " " << v << std::endl;
                        if( opcode_implementations.find(k) != opcode_implementations.end() ){
                            zkevm_circuit_real_rows += v * opcode_implementations.at(k)->rows_amount();
                            zkevm_circuit_usable_rows += v * (opcode_implementations.at(k)->rows_amount() + opcode_implementations.at(k)->rows_amount()%2);
                        }else{
                            zkevm_circuit_real_rows += v * 2;
                            zkevm_circuit_usable_rows += v * 2;
                        }
                    }
                    std::cout << "Total opcodes amount = " << opcode_sum << std::endl;
                    std::cout << "Executed opcodes (without start_call, end_call) = " << opcode_sum << std::endl;
                    std::cout << "zkEVM circuit real rows amount = " << zkevm_circuit_real_rows << std::endl;
                    std::cout << "zkEVM circuit rows amount = " << zkevm_circuit_usable_rows << std::endl;

                    std::cout << "Bytecodes amount = " << _bytecodes.get_data().size() << std::endl;
                    BOOST_ASSERT(_bytecode_hashes.size() == _bytecodes.get_data().size());
                    std::size_t bytecode_rows_amount = 0;
                    for( const auto &pair :_bytecodes.get_data()){
                        bytecode_rows_amount++;
                        bytecode_rows_amount += pair.first.size();
                    }
                    std::cout << "Bytecode rows amount = " << bytecode_rows_amount << std::endl;
                    std::cout << "Counted rw_operations amount = "
                        << (stack_rw_operations + memory_rw_operations + calldata_rw_operations + state_rw_operations)
                        << std::endl;
                    std::cout << "\tstack: "  << stack_rw_operations << std::endl;
                    std::cout << "\tmemory: "  << memory_rw_operations << std::endl;
                    std::cout << "\tcalldata: "  << calldata_rw_operations << std::endl;
                    std::cout << "\tstate_rw_operations: "  << state_rw_operations << std::endl;
                    std::cout << "\tcall_context_rw_operations: "  << call_context_rw_operations << std::endl;
                }

                void start_block(zkevm_word_type _block_hash, const boost::property_tree::ptree &pt){
                    last_write_rw_counter.clear();
                    finished_transactions = 0;
                    failed_transactions = 0;
                    block_id = tx_id = call_id = rw_counter++;
                    block_hash = _block_hash;
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
                    opcode_sum ++;
                    if (opcode_distribution.count(zkevm_opcode::start_block))
                        opcode_distribution[zkevm_opcode::start_block]++;
                    else
                        opcode_distribution[zkevm_opcode::start_block] = 1;

                    call_context_rw_operations += block_context_field_amount - 1;
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
                    opcode_sum ++;
                    if (opcode_distribution.count(zkevm_opcode::end_block))
                        opcode_distribution[zkevm_opcode::end_block]++;
                    else
                        opcode_distribution[zkevm_opcode::end_block] = 1;
                }

                zkevm_call_context start_transaction(std::string _tx_hash, const boost::property_tree::ptree &tt){
                    depth++;
                    tx_id = call_id = rw_counter;
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
                    std::cout << std::endl;

                    auto base = get_basic_zkevm_state_part();
                    auto call_context = get_call_header_state_part();

                    // bytecode must be overriden later
                    zkevm_call_context initial_context = {_zkevm_states.back(),call_id, 0, 0, 0, calldata, bytecode};

                    // _call_stack.push_back();

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
                    opcode_sum ++;
                    if (opcode_distribution.count(zkevm_opcode::start_transaction))
                        opcode_distribution[zkevm_opcode::start_transaction]++;
                    else
                        opcode_distribution[zkevm_opcode::start_transaction] = 1;

                    calldata_rw_operations += calldata.size();
                    call_context_rw_operations += call_context_readonly_field_amount;
                    return initial_context;
                }

                void end_transaction(const boost::property_tree::ptree &tt){
                    append_modified_items_rw_operations();
                    std::cout << "END TRANSACTION " << tx_id;
                    basic_zkevm_state_part base;
                    base.call_id = tx_id;                // RW counter on start_call
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
                    if (opcode_distribution.count(zkevm_opcode::end_transaction))
                        opcode_distribution[zkevm_opcode::end_transaction]++;
                    else
                        opcode_distribution[zkevm_opcode::end_transaction] = 1;
                    opcode_sum++;
                }

                void execute_transaction(const boost::property_tree::ptree &tx_trace){
                    std::cout << "Execute transaction" << std::endl;
                    if( tx_trace.get_child_optional("vmTrace") ){
                        std::vector<std::uint8_t> proposed_bytecode = byte_vector_from_hex_string(tx_trace.get_child("vmTrace.code").data(), 2);
                        if( proposed_bytecode != bytecode ) std::cout << "Bytecode is not equal" << std::endl;
                    }
                    if( !tx_trace.get_child_optional("vmTrace.ops") ) return;
                    for( const auto &opcode_description: tx_trace.get_child("vmTrace.ops")){
                        execute_opcode(opcode_description.second);
                        opcode_sum++;
                        std::cout << "2.addr = 0x" << std::hex << call_context_address << std::dec << std::endl;
                        if( opcode_description.second.get_child("sub").data() != "null"){
                            std::cout<<"as inja"<<std::endl;
                            start_call(opcode_description.second.get_child("sub"));
                            execute_call(opcode_description.second.get_child("sub"));
                            end_call(opcode_description.second.get_child("sub"));
                            std::cout<< "it's the first level " <<bytecode.size()<<std::endl;
                        }
                    }
                }
                std::string hexStr(std::uint8_t data)
                {
                    std::stringstream ss;
                    ss << std::hex;
                    ss << std::setw(2) << std::setfill('0') << (int)data;
                    return ss.str();
                }

                void start_call(const boost::property_tree::ptree &tx_trace){
                    std::cout << "START CALL " << std::endl;

                    //exit(1);
                    call_id = rw_counter;
                    std::cout << "3.addr = 0x" << std::hex << call_context_address << std::dec << std::endl;
                    // if (_accounts_current_state.find( call_context_address ) == _accounts_current_state.end()) {
                        // in case where opcode is CREATE or CREATE2 bytecode is generated now
                        if ( "0x" != tx_trace.get_child("code").data()) {
                                zkevm_account acc;
                                acc.bytecode = byte_vector_from_hex_string(tx_trace.get_child("code").data(), 2);
                                acc.code_hash = zkevm_keccak_hash(acc.bytecode);
                                // acc.balance = _value_from_create;
                                // acc.initialized = false;
                                _accounts_current_state[call_context_address] = acc;
                                std::cout<< "we must load bytecode: " << acc.bytecode.size() << "_" << hexStr(acc.bytecode[0]) << "_"<< std::endl;
                    }
                    // } else if (!_accounts_current_state[call_context_address].initialized) {
                        // the contract bytecode must have changed after initialization
                        // _accounts_current_state[call_context_address].initialized = true;
                        // _accounts_current_state[call_context_address].bytecode = byte_vector_from_hex_string(tx_trace.get_child("code").data(), 2);
                        // _accounts_current_state[call_context_address].code_hash = zkevm_keccak_hash(_accounts_current_state[call_context_address].bytecode);
                    // }
                    bytecode = _accounts_current_state[call_context_address].bytecode;
                    std::cout<< "be inja ham nemirese! " << bytecode.size() << std::endl;
                    bytecode_hash = zkevm_keccak_hash(bytecode);
                    if( _bytecode_hashes.find(bytecode_hash) == _bytecode_hashes.end() ){
                        _bytecode_hashes.insert(bytecode_hash);
                        _keccaks.new_buffer(bytecode);
                        _bytecodes.new_buffer(bytecode);
                    }
                    if (opcode_distribution.count(zkevm_opcode::start_call))
                        opcode_distribution[zkevm_opcode::start_call]++;
                    else
                        opcode_distribution[zkevm_opcode::start_call] = 1;


                    _call_stack.push_back({_zkevm_states.back(), call_id, 0, 0, 0, calldata, {}, bytecode});

                    opcode_sum++;
                    depth++;
                }

                void execute_call(const boost::property_tree::ptree &call_trace){
                    std::cout << "we're executing call! " << bytecode.size() << " " << call_trace.get_child("ops").size() << std::endl;
                    for( const auto &opcode_description: call_trace.get_child("ops")){
                    std::cout << "in the for " << bytecode.size() << std::endl;
                        //for( std::size_t i = 0; i < depth; i++) std::cout << "\t";
                        //std::cout << opcode_description.second.get_child("op").data() << std::endl;
                        zkevm_opcode op = opcode_from_number(opcode_number_from_str(opcode_description.second.get_child("op").data()));
                        execute_opcode(opcode_description.second);
                        opcode_sum++;
                        if( opcode_description.second.get_child("sub").data() != "null"){
                            std::cout << "\tSUBOPCODE " << op << opcode_description.second.get_child("sub").data() << std::endl;
                            start_call(opcode_description.second.get_child("sub"));
                            std::cout << "after start call " << bytecode.size() << std::endl;
                            execute_call(opcode_description.second.get_child("sub"));
                            std::cout << "continueing  " << bytecode.size() << std::endl;
                            end_call(opcode_description.second.get_child("sub"));
                        }
                    }
                    std::cout << "did it jumb? " << bytecode.size() << std::endl;
                }
                void end_call(const boost::property_tree::ptree &tx_trace){
                    //std::cout << "END CALL " << std::endl;
                    _call_stack.pop_back();
                    bytecode = _call_stack.back().bytecode;

                    depth--;
                    if (opcode_distribution.count(zkevm_opcode::end_call))
                        opcode_distribution[zkevm_opcode::end_call]++;
                    else
                        opcode_distribution[zkevm_opcode::end_call] = 1;
                    opcode_sum++;
                }
                void execute_opcode(const boost::property_tree::ptree &opcode_description){
                    zkevm_opcode op = opcode_from_number(opcode_number_from_str(opcode_description.get_child("op").data()));
                    current_opcode = opcode_to_number(op);
                    pc = atoi(opcode_description.get_child("pc").data().c_str());
                    if (opcode_description.get_child("ex").data() != "null") {
                        gas = atoi(opcode_description.get_child("ex.used").data().c_str());
                        if( opcode_description.get_child("ex.mem").data() != "null"){
                            memory_size = atoi(opcode_description.get_child("ex.mem.off").data().c_str());
                        } else {
                            memory_size = 0;
                        }
                        last_opcode_push = zkevm_word_vector_from_ptree(opcode_description.get_child("ex.push"));
                    } else {
                        // it sounds to be a bug in the RPC. For last opcode in a call "ex" may be empty!
                        last_opcode_push = {};
                        memory_size = 0;
                        return;
                    }
                    stack_size = stack.size();
                    for( std::size_t i = 1; i < depth; i++) std::cout << "\t";
                    std::cout << op << "=0x" << std::hex<< current_opcode << std::dec << " call_id = " << call_id << " pc = " << pc << std::endl;

                    executed_opcodes++;
                    std::string opcode = opcode_to_string(op);

                    // This does not work :(( bytecode should be loaded somehow in another way
                    if( pc > bytecode.size() || (pc == bytecode.size() && current_opcode != 0)){
                        std::cout << "Bytecode size = " << bytecode.size()<< " pc=" << pc << std::endl;
                        std::cout << "20.addr = 0x" << std::hex << call_context_address << std::dec << std::endl;
                        std::cout << "in the errorrrr";
                        exit(10);
                    } else if (pc < bytecode.size() && bytecode[pc] != current_opcode){
                        std::cout << std::hex << std::size_t(bytecode[pc]) << " != " << current_opcode << std::dec <<  std::endl;
                        // std::cout << "0x";
                        // for( auto b: bytecode ){
                        //     std::cout << std::hex << std::size_t(b) << std::dec << " ";
                        // }
                        std::cout << std::endl;
                        exit(10);
                    }
                    // BOOST_ASSERT(bytecode[pc] == current_opcode);
                    if(opcode == "STOP") { stop();}
                    else if(
                        opcode == "ADD" || opcode == "MUL" || opcode == "SUB" || opcode == "DIV" ||
                        opcode == "SDIV" || opcode == "MOD" || opcode == "SMOD" ||  opcode == "SIGNEXTEND" ||
                        opcode == "LT" || opcode == "GT"   || opcode == "SLT" || opcode == "SGT" ||
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
                    } 
                    else if( opcode == "EXP" )     exp();
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
                    else if( opcode == "EXTCODECOPY" ) extcodecopy();
                    else if( opcode == "EXTCODEHASH" ) extcodehash();
                    else if( opcode == "BLOCKHASH" ) blockhash();
                    else if( opcode == "COINBASE" ) coinbase();
                    else if( opcode == "TIMESTAMP" ) timestamp();
                    else if( opcode == "NUMBER" ) number();
                    else if( opcode == "DIFFICULTY" ) difficulty();
                    else if( opcode == "GASLIMIT" ) gaslimit();
                    else if( opcode == "CHAINID" ) chaindid();
                    else if( opcode == "SELFBALANCE" ) selfbalance();
                    else if( opcode == "BASEFEE" ) basefee();
                    else if( opcode == "BLOBHASH" ) blobhash();
                    else if( opcode == "BLOBBASEFEE" ) blobbasefee();
                    else if( opcode == "TLOAD" ) tload();
                    else if( opcode == "TSTORE" ) tstore();
                    else if( opcode == "MCOPY" ) mcopy();
                    else if( opcode == "CREATE" ) create();
                    else if( opcode == "CREATE2" ) create2();
                    else if( opcode == "SELFDESTRUCT" ) selfdestruct();
                    else if( opcode == "CALLCODE" ) callcode();
                    else if( opcode == "STATICCALL" ) staticcall();
                    else if( opcode == "JUMPDEST" ) simple_dummy();
                    else if( opcode == "POP" ) pop();
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
                    else if(opcode == "PUSH0") push_opcode(0);
                    else if(opcode == "PUSH1") push_opcode(1);
                    else if(opcode == "PUSH2") push_opcode(2);
                    else if(opcode == "PUSH3") push_opcode(3);
                    else if(opcode == "PUSH4") push_opcode(4);
                    else if(opcode == "PUSH5") push_opcode(5);
                    else if(opcode == "PUSH6") push_opcode(6);
                    else if(opcode == "PUSH7") push_opcode(7);
                    else if(opcode == "PUSH8") push_opcode(8);
                    else if(opcode == "PUSH9") push_opcode(9);
                    else if(opcode == "PUSH10") push_opcode(10);
                    else if(opcode == "PUSH11") push_opcode(11);
                    else if(opcode == "PUSH12") push_opcode(12);
                    else if(opcode == "PUSH13") push_opcode(13);
                    else if(opcode == "PUSH14") push_opcode(14);
                    else if(opcode == "PUSH15") push_opcode(15);
                    else if(opcode == "PUSH16") push_opcode(16);
                    else if(opcode == "PUSH17") push_opcode(17);
                    else if(opcode == "PUSH18") push_opcode(18);
                    else if(opcode == "PUSH19") push_opcode(19);
                    else if(opcode == "PUSH20") push_opcode(20);
                    else if(opcode == "PUSH21") push_opcode(21);
                    else if(opcode == "PUSH22") push_opcode(22);
                    else if(opcode == "PUSH23") push_opcode(23);
                    else if(opcode == "PUSH24") push_opcode(24);
                    else if(opcode == "PUSH25") push_opcode(25);
                    else if(opcode == "PUSH26") push_opcode(26);
                    else if(opcode == "PUSH27") push_opcode(27);
                    else if(opcode == "PUSH28") push_opcode(28);
                    else if(opcode == "PUSH29") push_opcode(29);
                    else if(opcode == "PUSH30") push_opcode(30);
                    else if(opcode == "PUSH31") push_opcode(31);
                    else if(opcode == "PUSH32") push_opcode(32);
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
                    else if(opcode == "CALL") { call();}
                    else if(opcode == "RETURN"){ return_opcode();}
                    else if(opcode == "DELEGATECALL") { delegatecall();}
                    else if (opcode == "REVERT"){ revert(); }
                    else {
                        std::cout << "Input generator does not support " << opcode << std::endl;
                        exit(2);
                    }

                    // Calculate statistics
                    if( !opcode_distribution.count(op) )
                        opcode_distribution[op] = 1;
                    else
                        opcode_distribution[op]++;
                }

                void stop() {
                }
                void one_operand_arithmetic() {
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 2;
                }
                void two_operands_arithmetic() {
                    stack.pop_back();
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 3;
                }
                void three_operands_arithmetic() {
                    stack.pop_back();
                    stack.pop_back();
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 4;
                }
                void exp() {
                    stack.pop_back();
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 3;
                }
                void keccak() {
                    stack.pop_back();
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 3;
                }
                void address() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                }
                void balance() {
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 2;
                }
                void origin() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                }
                void caller() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                }
                void callvalue() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                }
                void calldataload() {
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 2;
                    calldata_rw_operations += 32;
                }
                void calldatasize() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                }
                void calldatacopy() {
                    stack.pop_back();
                    stack.pop_back();
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 0);
                    stack_rw_operations += 3;
                }
                void codesize() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                }
                void codecopy() {
                    stack.pop_back();
                    stack.pop_back();
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 0);
                    stack_rw_operations += 3;
                }
                void gasprice() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                }
                void returndatasize() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                }
                void returndatacopy() {
                    stack.pop_back();
                    stack.pop_back();
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 0);
                    stack_rw_operations += 3;
                }
                void extcodesize() {
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 2;
                }
                void extcodecopy() {
                    stack.pop_back();
                    stack.pop_back();
                    stack.pop_back();
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack_rw_operations += 4;
                }
                void extcodehash() {
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 2;
                }
                void blockhash() {
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 2;
                }
                void coinbase() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                }
                void timestamp() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                }
                void number() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                }
                void difficulty() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                }
                void gaslimit() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                }
                void chaindid() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                }
                void selfbalance() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                }
                void basefee() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                }
                void blobhash() {
                    stack.pop_back();
                    // RPC bug
                    // BOOST_ASSERT(last_opcode_push.size() == 1);
                    // stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 2;
                }
                void blobbasefee() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                }
                void tload() {
                    stack.pop_back();
                    // Bug in RPC provider
                    // BOOST_ASSERT(last_opcode_push.size() == 1);
                    if (last_opcode_push.size() == 1)
                        stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 2;  
                }
                void tstore() {
                    stack.pop_back();
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 0);
                    stack_rw_operations += 2;
                }
                void mcopy() {
                    stack.pop_back();
                    stack.pop_back();
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 0);
                    memory_rw_operations += 1;
                    stack_rw_operations += 3;
                }
                void create() {
                    _value_from_create = stack.back();
                    stack.pop_back();
                    stack.pop_back();
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    call_context_address = stack.back();
                    stack_rw_operations += 4;
                }
                void create2() {
                    _value_from_create = stack.back();
                    stack.pop_back();
                    stack.pop_back();
                    stack.pop_back();
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    call_context_address = stack.back();
                    stack_rw_operations += 5;
                }
                void selfdestruct() {
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 0);
                    stack_rw_operations += 1;
                }
                void callcode() {
                    zkevm_word_type gas = stack.back(); stack.pop_back();
                    zkevm_word_type addr = stack.back(); stack.pop_back();
                    zkevm_word_type value = stack.back(); stack.pop_back();
                    zkevm_word_type args_offset = stack.back(); stack.pop_back();
                    zkevm_word_type args_length = stack.back(); stack.pop_back();
                    zkevm_word_type ret_offset = stack.back(); stack.pop_back();
                    zkevm_word_type ret_length = stack.back(); stack.pop_back();
                    call_context_address = addr;
                    std::cout << "addr = 0x" << std::hex << addr << std::dec << std::endl;
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 8;
                }
                void call() {
                    zkevm_word_type gas = stack.back(); stack.pop_back();
                    zkevm_word_type addr = stack.back(); stack.pop_back();
                    zkevm_word_type value = stack.back(); stack.pop_back();
                    zkevm_word_type args_offset = stack.back(); stack.pop_back();
                    zkevm_word_type args_length = stack.back(); stack.pop_back();
                    zkevm_word_type ret_offset = stack.back(); stack.pop_back();
                    zkevm_word_type ret_length = stack.back(); stack.pop_back();
                    call_context_address = addr;
                    std::cout <<
                        "gas = 0x" << std::hex << gas << std::dec << std::endl <<
                        "addr = 0x" << std::hex << addr << std::dec << std::endl <<
                        "value = 0x" << std::hex << value << std::dec << std::endl <<
                        "args_offset = 0x" << std::hex << args_offset << std::dec << std::endl <<
                        "args_length = 0x" << std::hex << args_length << std::dec << std::endl <<
                        "ret_offset = 0x" << std::hex << ret_offset << std::dec << std::endl <<
                        "ret_length = 0x" << std::hex << ret_length << std::dec << std::endl;
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 8;
                }
                void staticcall() {
                    zkevm_word_type gas = stack.back(); stack.pop_back();
                    zkevm_word_type addr = stack.back(); stack.pop_back();
                    zkevm_word_type args_offset = stack.back(); stack.pop_back();
                    zkevm_word_type args_length = stack.back(); stack.pop_back();
                    zkevm_word_type ret_offset = stack.back(); stack.pop_back();
                    zkevm_word_type ret_length = stack.back(); stack.pop_back();
                    call_context_address = addr;
                    std::cout << "addr = 0x" << std::hex << addr << std::dec << std::endl;
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 7;
                }
                void pop() {
                    stack.pop_back();
                    stack_rw_operations += 1;
                }
                void simple_dummy() {}
                void mload() {
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 2; 
                    memory_rw_operations += 32;
                }
                void mstore() {
                    stack.pop_back();
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 0);
                    stack_rw_operations += 2; 
                    memory_rw_operations += 32;
                }
                void mstore8() {
                    stack.pop_back();
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 0);
                    stack_rw_operations += 2; 
                    memory_rw_operations += 1;
                }
                void sload() {
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 2; 
                    state_rw_operations += 1;
                }
                void sstore() {
                    stack.pop_back();
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 0);
                    stack_rw_operations += 2;  
                    state_rw_operations += 1;
                }
                void jump() {
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 0);
                    stack_rw_operations += 1;
                }
                void jumpi() {
                    stack.pop_back();
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 0);
                    stack_rw_operations += 2;
                }
                void one_push_to_stack() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                }
                void push_opcode( std::size_t x) {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                }
                void dupx( std::size_t d) {
                    BOOST_ASSERT(last_opcode_push.size() == d+1);
                    stack.push_back(stack[stack.size()-d]);
                    stack_rw_operations += 2;
                }
                void swapx( std::size_t s) {
                    BOOST_ASSERT(last_opcode_push.size() == s + 1);
                    auto tmp = stack[stack.size() - s - 1];
                    stack[stack.size() - s - 1] = stack[stack.size()-1];
                    stack[stack.size()-1] = tmp;
                    stack_rw_operations += 4;
                }
                void logx( std::size_t l) {
                    stack.pop_back();
                    stack.pop_back();
                    for( std::size_t i = 0; i < l; i++ ) stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 0);
                    stack_rw_operations += 2 + l;
                }
                void return_opcode(){
                    stack.pop_back();
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 0);
                    stack_rw_operations += 2;
                }
                void delegatecall(){
                    zkevm_word_type gas = stack.back(); stack.pop_back();
                    zkevm_word_type addr = stack.back(); stack.pop_back();
                    zkevm_word_type args_offset = stack.back(); stack.pop_back();
                    zkevm_word_type args_length = stack.back(); stack.pop_back();
                    zkevm_word_type ret_offset = stack.back(); stack.pop_back();
                    zkevm_word_type ret_length = stack.back(); stack.pop_back();

                    call_context_address = addr;
                    std::cout << "addr = 0x" << std::hex << addr << std::dec << "injas?" << std::endl;
                    std::cout << call_context_address << std::endl;
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 7;
                }
                void revert(){
                    stack.pop_back();
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 0);
                    stack_rw_operations += 2;
                }

                std::size_t opcode_sum;
                std::size_t executed_opcodes;
                std::size_t stack_rw_operations;
                std::size_t memory_rw_operations;
                std::size_t calldata_rw_operations;
                std::size_t returndata_rw_operations;
                std::size_t call_context_rw_operations;
                std::size_t state_rw_operations;
                std::map<zkevm_opcode, std::size_t> opcode_distribution;
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
                        std::cout << "\t" << account_address.data() << std::endl;
                        zkevm_account acc;
                        acc.address = zkevm_word_from_string(account_address.data());
                        acc.balance = zkevm_word_from_string(account.get_child("balance").data());
                        if( account.get_child_optional("nonce") ){
                            acc.seq_no = acc.ext_seq_no = std::size_t(zkevm_word_from_string(account.get_child("nonce").data()));
                        }
                        if( account.get_child_optional("storage") ){
                            acc.storage = key_value_storage_from_ptree(account.get_child("storage"));
                        }
                        if( account.get_child_optional("code") )
                            acc.bytecode = byte_vector_from_hex_string(account.get_child("code").data(), 2);
                        acc.code_hash = zkevm_keccak_hash(acc.bytecode);
                        acc.initialized = true;
                        _accounts_initial_state[acc.address] = acc ;
                        _accounts_current_state = _accounts_initial_state;
                    }
                }

                boost::property_tree::ptree load_json_input(std::string path){
                    std::ifstream ss;
                    std::string ab_path = "/Users/amirhossein/Desktop/room/nil/placeholder/crypto3/libs/blueprint/test/zkevm_bbf/data/"+path;
                    std::cout << "Open file " << ab_path << std::endl;
                    std::cout << "Loading data from " << path << std::endl;
                    // ss.open(std::string(TEST_DATA_DIR) + path);

                    ss.open(std::string(ab_path));
                    boost::property_tree::ptree pt;
                    boost::property_tree::read_json(ss, pt);
                    ss.close();
                    return pt;
                }
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil
