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

#include <nil/blueprint/zkevm_bbf/types/hashed_buffers.hpp>
#include <nil/blueprint/zkevm_bbf/types/rw_operation.hpp>
#include <nil/blueprint/zkevm_bbf/types/copy_event.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_state.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_account.hpp>
#include <nil/blueprint/zkevm_bbf/types/call_context.hpp>

#include <nil/blueprint/zkevm_bbf/types/zkevm_input_generator.hpp>
#include <nil/blueprint/zkevm_bbf/opcodes/zkevm_opcodes.hpp>

#include <nil/blueprint/zkevm_bbf/opcodes/zkevm_opcodes.hpp>
#include <nil/blueprint/zkevm_bbf/input_generators/basic_input_generator.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            class zkevm_alchemy_input_generator:public zkevm_basic_input_generator{
                using extended_integral_type = nil::crypto3::multiprecision::big_uint<512>;

            protected:
                std::vector<std::uint8_t>    proposed_bytecode;
                std::vector<zkevm_word_type> last_opcode_push;
                std::vector<std::uint8_t> last_opcode_memory;
                std::size_t last_opcode_mem_offset;
                std::size_t last_opcode_gas_cost;
                std::size_t last_opcode_gas_used;

                std::map<zkevm_opcode, std::size_t> _unknown_opcodes;
            public:
                zkevm_alchemy_input_generator(
                    std::string path
                ) : zkevm_basic_input_generator() {
                    opcode_sum = 0;
                    executed_opcodes = 0;
                    stack_rw_operations = 0;
                    memory_rw_operations = 0;
                    calldata_rw_operations = 0;
                    returndata_rw_operations = 0;
                    state_rw_operations = 0;
                    call_context_rw_operations = 0;

                    boost::property_tree::ptree tree = load_json_input(path + std::string("block.json"));
                    BOOST_LOG_TRIVIAL(trace) << "ZKEVM ALCHEMY INPUT GENERATOR loaded";
                    auto pt_block = tree.get_child("block");
                    load_block(pt_block.get_child("hash").data(), pt_block);
                    start_block();
                    std::size_t tx_order = 0;
                    BOOST_LOG_TRIVIAL(trace) << "Transactions amount = " << tree.get_child("transactions").size();
                    for( auto &tt: tree.get_child("transactions")){
                        std::string tx_hash_string = tt.second.get_child("tx_hash").data();
                        BOOST_LOG_TRIVIAL(trace) << tx_order++ << "." << tx_hash_string << " " ;

                        boost::property_tree::ptree tx_trace_tree = load_json_input(path + std::string("tx_" + tx_hash_string + ".json"));
                        load_accounts(tt.second.get_child("execution_trace.prestate_trace"));
                        if( tt.second.get_child_optional("execution_trace.call_trace")) load_call_trace(tt.second.get_child("execution_trace.call_trace"));
                        if( tx_trace_tree.get_child_optional("stateDiff") ) load_state_diff(tx_trace_tree.get_child("stateDiff"));
                        load_transaction(tx_hash_string, tt.second.get_child("details"));

                        if( tx.to == 0 ) BOOST_LOG_TRIVIAL(trace) << "DEPLOY TRANSACTION" << std::endl;
                        start_transaction();
                        execute_transaction(tx_trace_tree);
                        end_transaction();
                        BOOST_LOG_TRIVIAL(trace) << "Total opcodes amount = " << opcode_sum << std::endl << std::endl;
                    }
                    end_block();

                    using FieldType = typename nil::crypto3::algebra::curves::pallas::base_field_type;
                    auto opcode_implementations = get_opcode_implementations<FieldType>();
                    std::size_t zkevm_circuit_usable_rows = 0;
                    std::size_t zkevm_circuit_real_rows = 0;
                    for( auto [k,v]: opcode_distribution){
                        BOOST_LOG_TRIVIAL(trace) << "\t" << k << " " << v ;
                        if( opcode_implementations.find(k) != opcode_implementations.end() ){
                            zkevm_circuit_real_rows += v * opcode_implementations.at(k)->rows_amount();
                            zkevm_circuit_usable_rows += v * (opcode_implementations.at(k)->rows_amount() + opcode_implementations.at(k)->rows_amount()%2);
                        }else{
                            zkevm_circuit_real_rows += v * 2;
                            zkevm_circuit_usable_rows += v * 2;
                        }
                    }
                    BOOST_LOG_TRIVIAL(trace) << "Total opcodes amount = " << opcode_sum ;
                    BOOST_LOG_TRIVIAL(trace) << "Executed opcodes (without start_call, end_call) = " << opcode_sum ;
                    BOOST_LOG_TRIVIAL(trace) << "zkEVM circuit real rows amount = " << zkevm_circuit_real_rows ;
                    BOOST_LOG_TRIVIAL(trace) << "zkEVM circuit rows amount = " << zkevm_circuit_usable_rows ;

                    BOOST_LOG_TRIVIAL(trace) << "Bytecodes amount = " << _bytecodes.get_data().size() ;
                    BOOST_ASSERT(_bytecode_hashes.size() == _bytecodes.get_data().size());
                    std::size_t bytecode_rows_amount = 0;
                    for( const auto &pair :_bytecodes.get_data()){
                        bytecode_rows_amount++;
                        bytecode_rows_amount += pair.first.size();
                    }
                    BOOST_LOG_TRIVIAL(trace) << "Bytecode rows amount = " << bytecode_rows_amount ;
                    BOOST_LOG_TRIVIAL(trace) << "Counted rw_operations amount = "
                        << (stack_rw_operations + memory_rw_operations + calldata_rw_operations + state_rw_operations)
                        ;
                    BOOST_LOG_TRIVIAL(trace) << "\tstack: "  << stack_rw_operations ;
                    BOOST_LOG_TRIVIAL(trace) << "\tmemory: "  << memory_rw_operations ;
                    BOOST_LOG_TRIVIAL(trace) << "\tcalldata: "  << calldata_rw_operations ;
                    BOOST_LOG_TRIVIAL(trace) << "\tstate_rw_operations: "  << state_rw_operations ;
                    BOOST_LOG_TRIVIAL(trace) << "\tcall_context_rw_operations: "  << call_context_rw_operations ;
                }

                void start_block() override {
                    BOOST_LOG_TRIVIAL(trace) << "START BLOCK " << block_id ;
                    zkevm_basic_input_generator::start_block();
                    opcode_sum ++;
                    if (opcode_distribution.count(zkevm_opcode::start_block))
                        opcode_distribution[zkevm_opcode::start_block]++;
                    else
                        opcode_distribution[zkevm_opcode::start_block] = 1;
                    call_context_rw_operations += block_context_field_amount - 1;
                }

                void end_block() override{
                    zkevm_basic_input_generator::end_block();
                    opcode_sum ++;
                    if (opcode_distribution.count(zkevm_opcode::end_block))
                        opcode_distribution[zkevm_opcode::end_block]++;
                    else
                        opcode_distribution[zkevm_opcode::end_block] = 1;
                    BOOST_LOG_TRIVIAL(trace) << "END BLOCK " << block_id ;
                }

                void start_transaction() override{
                    BOOST_LOG_TRIVIAL(trace) << "START TRANSACTION " << tx_id << std::endl
                        << "\tfrom " << std::hex << tx.from << std::endl
                        << "\tto " << std::hex << tx.to << std::endl
                        << "\tvalue  = " << std::hex << tx.value << std::endl
                        << "\thash = " << tx.hash << std::dec << std::endl
                        << "\tgas = " << std::dec << tx.gas
                        ;

                    zkevm_basic_input_generator::start_transaction();

                    // statistics
                    opcode_sum ++;
                    if (opcode_distribution.count(zkevm_opcode::start_transaction))
                        opcode_distribution[zkevm_opcode::start_transaction]++;
                    else
                        opcode_distribution[zkevm_opcode::start_transaction] = 1;
                    calldata_rw_operations += calldata.size();
                    call_context_rw_operations += call_context_readonly_field_amount;
                }

                void end_transaction(){
                    BOOST_LOG_TRIVIAL(trace) << "END TRANSACTION " << tx_id;
                    zkevm_basic_input_generator::end_transaction();

                    if (opcode_distribution.count(zkevm_opcode::end_transaction))
                        opcode_distribution[zkevm_opcode::end_transaction]++;
                    else
                        opcode_distribution[zkevm_opcode::end_transaction] = 1;

                    opcode_sum++;
                }

                void execute_transaction(const boost::property_tree::ptree &tx_trace){
                    BOOST_LOG_TRIVIAL(trace) << "Execute transaction";

                    // Double check that the bytecode is correct
                    if( tx_trace.get_child_optional("vmTrace.code") ){
                        std::vector<std::uint8_t> proposed_bytecode = byte_vector_from_hex_string(tx_trace.get_child("vmTrace.code").data(), 2);
                        if( proposed_bytecode != bytecode ) {
                            BOOST_LOG_TRIVIAL(trace) << "Bytecode is not equal" ;
                            BOOST_LOG_TRIVIAL(trace) << "Proposed bytecode " <<  byte_vector_to_hex_string(proposed_bytecode) << std::endl << std::endl;
                            BOOST_LOG_TRIVIAL(trace) << "Bytecode          " <<  byte_vector_to_hex_string(bytecode);
                            BOOST_ASSERT(false);
                        }
                    } else {
                        BOOST_LOG_TRIVIAL(trace) << "TRANSFER TRANSACTION" << std::endl;
                    }

                    if( !tx_trace.get_child_optional("vmTrace.ops") ) return;
                    // std::size_t op_counter = 0;
                    // while( !is_end_call ){
                    //     auto opcode_description = load_opcode()
                    //     execute_opcode(opcode_description.second);
                    //     oc_counter++;
                    // }
                    for( const auto &opcode_description: tx_trace.get_child("vmTrace.ops")){
                        execute_opcode(opcode_description.second);
                        opcode_sum++;
                        if( opcode_description.second.get_child("sub").data() != "null" &&
                            opcode_description.second.get_child("sub.ops").size() != 0
                        ){
                            start_call(opcode_description.second.get_child("sub"));
                            execute_call(opcode_description.second.get_child("sub"));
                            end_call(opcode_description.second.get_child("sub"));
                        }
                        if( !opcode_description.second.get_child_optional("ex.used") ) continue;
                        if( gas != atoi(opcode_description.second.get_child("ex.used").data().c_str())){
                            BOOST_LOG_TRIVIAL(trace) << "Gas error: Our " << gas << " != " << atoi(opcode_description.second.get_child("ex.used").data().c_str()) ;
                        }
                        BOOST_ASSERT( gas == atoi(opcode_description.second.get_child("ex.used").data().c_str()) );
                    }
                }

                void start_call(const boost::property_tree::ptree &tx_trace){
                    BOOST_LOG_TRIVIAL(trace) << "START CALL " ;
                    // BOOST_LOG_TRIVIAL(trace) << "Memory: " << std::hex;
                    // for( auto c:memory) BOOST_LOG_TRIVIAL(trace) << std::size_t(c) << " ";
                    // BOOST_LOG_TRIVIAL(trace) << std::dec ;

                    call_id = rw_counter;

                    bytecode = byte_vector_from_hex_string(tx_trace.get_child("code").data(),2);//_accounts_current_state[call_context_address].bytecode;
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

                    if( !call_is_create &&  !call_is_create2 ){
                        gas -= 100; // call cost
                        if( _call_stack.back().was_accessed.count({call_addr, 1, 0}) == 0 ) {
                            BOOST_LOG_TRIVIAL(trace) << "Was not accessed " << std::hex << call_addr << std::dec ;
                            gas -= 2500; // call cost
                        } else {
                            BOOST_LOG_TRIVIAL(trace) << "Was accessed " << std::hex << call_addr << std::dec ;
                        }
                    }
                    _call_stack.back().was_accessed.insert({call_addr, 1, 0});

                    // BOOST_LOG_TRIVIAL(trace) << "Memory size = " << memory.size() << ": " << std::hex;
                    // for(auto c:memory){
                    //     BOOST_LOG_TRIVIAL(trace) << std::size_t(c) << " ";
                    // }
                    // BOOST_LOG_TRIVIAL(trace) << std::dec ;
                    // _zkevm_states.push_back(call_header_zkevm_state(get_basic_zkevm_state_part(), get_call_header_state_part()));
                    _call_stack.push_back(zkevm_call_context());
                    _call_stack.back().call_pc = pc;
                    _call_stack.back().before_call_gas = gas;
                    _call_stack.back().call_id = call_id;
                    _call_stack.back().calldata = calldata;
                    _call_stack.back().bytecode = bytecode;
                    _call_stack.back().stack = stack;
                    _call_stack.back().memory = memory;
                    _call_stack.back().caller = caller;
                    _call_stack.back().call_context_address = call_context_address;
                    _call_stack.back().was_accessed = _call_stack[_call_stack.size() - 2].was_accessed;
                    _call_stack.back().was_written = _call_stack[_call_stack.size() - 2].was_written;
                    _call_stack.back().transient_storage = _call_stack[_call_stack.size() - 2].transient_storage;
                    _call_stack.back().call_value = call_value;
                    _call_stack.back().call_context_value = call_context_value;
                    _call_stack.back().call_is_create = call_is_create;
                    _call_stack.back().call_is_create2 = call_is_create2;
                    BOOST_LOG_TRIVIAL(trace) << "call_value = " << std::hex << call_value << std::dec ;
                    BOOST_LOG_TRIVIAL(trace) << "call_context_value = " << std::hex << call_context_value << std::dec ;

                    calldata.clear();
                    BOOST_LOG_TRIVIAL(trace) << "calldata size = " << call_args_length <<  " : " << std::hex;
                    for( std::size_t i = 0; i < call_args_length; i++){
                        calldata.push_back(memory[call_args_offset + i]);
                    }
                    BOOST_LOG_TRIVIAL(trace) << byte_vector_to_sparse_hex_string(calldata);
                    _call_stack.back().calldata = calldata;

                    if(call_gas >= gas - (gas / 64)) {
                        BOOST_LOG_TRIVIAL(trace) << "gas - gas/64" ;
                        gas = gas - (gas / 64);
                    } else {
                        BOOST_LOG_TRIVIAL(trace) << "call_gas is valid" ;
                        gas = call_gas;
                    }
                    if( !call_is_create && !call_is_create2 ){
                        if( call_value != 0 ) {
                            gas += 2300;
                        }
                    }
                    call_gas = gas;
                    _call_stack.back().call_gas = call_gas;

                    stack = {};
                    memory = {};
                    returndata = {};
                    pc = 0;
                    opcode_sum++;
                    depth++;
                }

                void execute_call(const boost::property_tree::ptree &call_trace){
                    for( const auto &opcode_description: call_trace.get_child("ops")){
                        //for( std::size_t i = 0; i < depth; i++) BOOST_LOG_TRIVIAL(trace) << "\t";
                        //BOOST_LOG_TRIVIAL(trace) << opcode_description.second.get_child("op").data() ;
                        zkevm_opcode op = opcode_from_number(opcode_number_from_str(opcode_description.second.get_child("op").data()));
                        execute_opcode(opcode_description.second);
                        opcode_sum++;
                        if( opcode_description.second.get_child("sub").data() != "null"&&
                            opcode_description.second.get_child("sub.ops").size() != 0
                        ){
                            start_call(opcode_description.second.get_child("sub"));
                            execute_call(opcode_description.second.get_child("sub"));
                            end_call(opcode_description.second.get_child("sub"));
                        }
                        if( !opcode_description.second.get_child_optional("ex.used") ) continue;
                        if( gas != atoi(opcode_description.second.get_child("ex.used").data().c_str())){
                            BOOST_LOG_TRIVIAL(trace) << "Gas error: Our " << gas << " != " << atoi(opcode_description.second.get_child("ex.used").data().c_str()) ;
                        }
                        BOOST_ASSERT( gas == atoi(opcode_description.second.get_child("ex.used").data().c_str()) );
                    }
                }
                void end_call(const boost::property_tree::ptree &tx_trace){
                    BOOST_LOG_TRIVIAL(trace) << "END CALL" ;
                    pc = _call_stack.back().call_pc + 1;
                    gas = _call_stack.back().before_call_gas - (call_gas - gas);
                    memory = _call_stack.back().memory;
                    stack = _call_stack.back().stack;
                    call_value = _call_stack.back().call_value;
                    if( call_value != 0 ) gas += 2300;

                    if( call_is_create || call_is_create2 ){
                        gas -= returndata.size() * 200;
                    }

                    _call_stack.pop_back();
                    call_id = _call_stack.back().call_id;
                    bytecode = _call_stack.back().bytecode;
                    calldata = _call_stack.back().calldata;
                    caller = _call_stack.back().caller;
                    call_context_address = _call_stack.back().call_context_address;
                    call_context_value = _call_stack.back().call_context_value;
                    call_value = _call_stack.back().call_value;
                    call_gas = _call_stack.back().call_gas;
                    std::size_t returndata_offset = _call_stack.back().lastcall_returndataoffset;
                    std::size_t returndata_length = _call_stack.back().lastcall_returndatalength;

                    BOOST_LOG_TRIVIAL(trace) << "returndata_offset = " << _call_stack.back().lastcall_returndataoffset ;
                    BOOST_LOG_TRIVIAL(trace) << "returndata_length = " << _call_stack.back().lastcall_returndatalength ;
                    BOOST_LOG_TRIVIAL(trace) << "returndata size  = " << returndata.size() ;

                    std::size_t real_length = std::min(returndata_length, returndata.size());
                    // Memory is resized before CALL
                    for( std::size_t i = 0; i < real_length; i++){
                        memory[returndata_offset + i] = returndata[i];
                    }

                    // BOOST_LOG_TRIVIAL(trace) << "Memory: " << std::hex;
                    // for( auto c:memory) BOOST_LOG_TRIVIAL(trace) << std::size_t(c) << " ";
                    // BOOST_LOG_TRIVIAL(trace) << std::dec ;

                    stack.push_back(call_status);
                    BOOST_LOG_TRIVIAL(trace) << "call_status = " << std::hex << call_status << std::dec ;

                    depth--;
                    if (opcode_distribution.count(zkevm_opcode::end_call))
                        opcode_distribution[zkevm_opcode::end_call]++;
                    else
                        opcode_distribution[zkevm_opcode::end_call] = 1;
                    opcode_sum++;

                    BOOST_LOG_TRIVIAL(trace) << "call_value = " << std::hex << call_value << std::dec ;
                    BOOST_LOG_TRIVIAL(trace) << "call_context_value = " << std::hex << call_context_value << std::dec ;
                }
                void execute_opcode(const boost::property_tree::ptree &opcode_description){
                    rw_counter++;
                    zkevm_opcode op = opcode_from_number(opcode_number_from_str(opcode_description.get_child("op").data()));
                    current_opcode = opcode_to_number(op);
                    BOOST_ASSERT( pc == atoi(opcode_description.get_child("pc").data().c_str()) );

                    memory_size = memory.size();
                    stack_size = stack.size();

                    std::string indent;
                    for( std::size_t i = 2; i < depth; i++) indent += "\t";
                    BOOST_LOG_TRIVIAL(trace)
                        << indent
                        << op << "=0x" << std::hex<< current_opcode << std::dec
                        << " tx_id = " << tx_id
                        << " call_id = " << call_id
                        << " pc = " << pc
                        << " gas = " << gas ;

                    if( opcode_description.get_child("ex").data() == "null" ){
                        BOOST_LOG_TRIVIAL(trace) << "Execution error!!!" ;
                        error();
                        return;
                    }

                    last_opcode_push.clear();
                    if( opcode_description.get_child_optional("ex.push") )
                        last_opcode_push = zkevm_word_vector_from_ptree(opcode_description.get_child("ex.push"));

                    last_opcode_memory.clear();
                    if( opcode_description.get_child_optional("ex.mem.data") ){
                        last_opcode_memory = byte_vector_from_hex_string(opcode_description.get_child("ex.mem.data").data(), 2);
                    }
                    if( opcode_description.get_child_optional("ex.mem.off") )
                        last_opcode_mem_offset = atoi(opcode_description.get_child("ex.mem.off").data().c_str());

                    if(opcode_description.get_child_optional("cost")) last_opcode_gas_cost = atoi(opcode_description.get_child("cost").data().c_str());
                    if(opcode_description.get_child_optional("ex.used")) last_opcode_gas_used = atoi(opcode_description.get_child("ex.used").data().c_str());

                    executed_opcodes++;
                    std::string opcode = opcode_to_string(op);

                    // This does not work :(( bytecode should be loaded somehow in another way
                    if( pc >= bytecode.size()){
                        BOOST_LOG_TRIVIAL(trace) << "Bytecode size = " << bytecode.size();
                    }
                    BOOST_ASSERT((pc < bytecode.size()) || (pc == bytecode.size() && opcode == "STOP" ));
                    if( pc < bytecode.size() && bytecode[pc] != current_opcode){
                        BOOST_LOG_TRIVIAL(trace) << std::hex << std::size_t(bytecode[pc]) << " != " << current_opcode << std::dec <<  std::endl;
                    }
                    BOOST_ASSERT((pc == bytecode.size() && opcode == "STOP" ) || (bytecode[pc] == current_opcode));
                    if(opcode == "STOP") { stop();}
                    else if( opcode == "LT" ) lt();
                    else if( opcode == "GT" ) gt();
                    else if( opcode == "SLT" ) slt();
                    else if( opcode == "SGT" ) sgt();
                    else if( opcode == "SHL" ) shl();
                    else if( opcode == "SHR" ) shr();
                    else if( opcode == "SAR" ) sar();
                    else if( opcode == "ADD" ) add();
                    else if( opcode == "SUB" ) sub();
                    else if( opcode == "DIV" ) div();
                    else if( opcode == "MOD" ) mod();
                    else if( opcode == "SDIV" ) sdiv();
                    else if( opcode == "SMOD" ) smod();
                    else if( opcode == "MULMOD" ) mulmod();
                    else if( opcode == "ADDMOD" ) addmod();
                    else if( opcode == "MUL" ) mul();
                    else if( opcode == "EXP" ) exp();
                    else if( opcode == "SIGNEXTEND" ) signextend();
                    else if( opcode == "AND" ) and_opcode();
                    else if( opcode == "OR" ) or_opcode();
                    else if( opcode == "XOR" ) xor_opcode();
                    else if( opcode == "BYTE" ) byte();
                    else if( opcode == "EQ" ) eq();
                    else if( opcode == "ISZERO" ) iszero();
                    else if( opcode == "NOT" ) not_opcode();
                    else if( opcode == "KECCAK256" ) keccak();
                    else if( opcode == "ADDRESS" )   address();
                    else if( opcode == "BALANCE" )   balance();
                    else if( opcode == "ORIGIN" )    origin();
                    else if( opcode == "CALLER" )    caller_opcode();
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
                    // else if( opcode == "EXTCODECOPY" ) extcodecopy();
                    else if( opcode == "EXTCODEHASH" ) extcodehash();
                    else if( opcode == "BLOCKHASH" ) blockhash();
                    else if( opcode == "COINBASE" ) coinbase();
                    else if( opcode == "TIMESTAMP" ) timestamp();
                    else if( opcode == "NUMBER" ) number();
                    else if( opcode == "DIFFICULTY" ) difficulty();
                    // else if( opcode == "GASLIMIT" ) gaslimit();
                    else if( opcode == "CHAINID" ) chainid();
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
                    // else if( opcode == "CALLCODE" ) callcode();
                    else if( opcode == "STATICCALL" ) staticcall();
                    else if( opcode == "JUMPDEST" ) jumpdest();
                    else if( opcode == "POP" ) pop();
                    else if( opcode == "MLOAD" ) mload();
                    else if( opcode == "MSTORE" ) mstore();
                    else if( opcode == "MSTORE8" ) mstore8();
                    else if( opcode == "SLOAD" ) sload();
                    else if( opcode == "SSTORE" ) sstore();
                    else if( opcode == "JUMP" ) jump();
                    else if( opcode == "JUMPI" ) jumpi();
                    else if( opcode == "GAS" ) gas_opcode();
                    else if( opcode == "PC" ) pc_opcode();
                    else if( opcode == "MSIZE" ) msize_opcode();
                    // else if(
                    //     opcode == "PC" ||
                    //     opcode == "MSIZE" ||
                    // ) one_push_to_stack();
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
                    else if(opcode == "CALL") { call(opcode_description.get_child("sub.ops").size() == 0);}
                    else if(opcode == "RETURN"){ return_opcode();}
                    else if(opcode == "DELEGATECALL") { delegatecall();}
                    else if(opcode == "REVERT"){ revert(); }
                    else {
                        BOOST_LOG_TRIVIAL(trace) << "Input generator does not support " << opcode ;
                        exit(2);
                    }

                    // Calculate statistics
                    if( !opcode_distribution.count(op) )
                        opcode_distribution[op] = 1;
                    else
                        opcode_distribution[op]++;
                }

                void stop() {
                    call_status = 1;
                    if( _call_stack.size() > 2){
                        _call_stack[_call_stack.size()-2].was_accessed.insert(_call_stack.back().was_accessed.begin(), _call_stack.back().was_accessed.end());
                        _call_stack[_call_stack.size()-2].was_written.insert(_call_stack.back().was_written.begin(), _call_stack.back().was_written.end());
                        for( auto & [k,v]: _call_stack.back().transient_storage){
                            _call_stack[_call_stack.size()-2].transient_storage[k] = v;
                        }
                    }
                    returndata.clear();
                }
                void one_operand_arithmetic() {
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 2;
                    pc++;
                }
                void iszero() {
                    auto a = stack.back(); stack.pop_back();
                    zkevm_word_type result = a == 0? 1: 0;
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == result);
                    stack.push_back(result);
                    stack_rw_operations += 2;
                    gas -= 3;
                    pc++;
                }
                void not_opcode() {
                    auto a = stack.back(); stack.pop_back();
                    zkevm_word_type result =
                        zkevm_word_type(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256) - a;
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == result);
                    stack.push_back(result);
                    stack_rw_operations += 2;
                    gas -= 3;
                    pc++;
                }
                void two_operands_arithmetic() {
                    stack.pop_back();
                    stack.pop_back();
                    if( last_opcode_push.size() == 1)
                        stack.push_back(last_opcode_push.back());
                    else
                        stack.push_back(0);
                    stack_rw_operations += 3;
                    pc++;
                }
                void shl() {
                    auto b = stack.back(); stack.pop_back();
                    auto a = stack.back(); stack.pop_back();
                    int shift = (b < 256) ? int(b) : 256;
                    zkevm_word_type result = a << shift;

                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == result);
                    stack.push_back(result);
                    stack_rw_operations += 3;
                    gas -= 3;
                    pc++;
                }
                void shr() {
                    auto b = stack.back(); stack.pop_back();
                    auto a = stack.back(); stack.pop_back();
                    int shift = (b < 256) ? int(b) : 256;
                    zkevm_word_type result = a >> shift;

                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == result);
                    stack.push_back(result);
                    stack_rw_operations += 3;
                    gas -= 3;
                    pc++;
                }
                void lt() {
                    auto a = stack.back(); stack.pop_back();
                    auto b = stack.back(); stack.pop_back();
                    zkevm_word_type result = (a < b);

                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == result);
                    stack.push_back(result);
                    stack_rw_operations += 3;
                    gas -= 3;
                    pc++;
                }
                void gt() {
                    auto a = stack.back(); stack.pop_back();
                    auto b = stack.back(); stack.pop_back();
                    zkevm_word_type result = (a > b);

                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == result);
                    stack.push_back(result);
                    stack_rw_operations += 3;
                    gas -= 3;
                    pc++;
                }
                void slt() {
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

                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    if( last_opcode_push.back() != result ){
                        BOOST_LOG_TRIVIAL(trace) << std::hex
                            << "Opcode SLT error " << std::endl
                            << "a = " << a  << std::endl
                            << "b = " << b  << std::endl
                            << "result = " << result  << std::endl
                            << "real_result = " << last_opcode_push.back()  << std::endl
                            << "is_negative(a) = " << is_negative(a)   << std::endl
                            << "is_negative(b) = " << is_negative(b)   << std::endl
                            << std::dec ;
                    }
                    BOOST_ASSERT(last_opcode_push.back() == result);
                    //TODO: our SLT is not compatible with our opcodes
                    stack.push_back(result);
                    stack_rw_operations += 3;
                    gas -= 3;
                    pc++;
                }
                void sgt() {
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

                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == result);
                    stack.push_back(result);
                    stack_rw_operations += 3;
                    gas -= 3;
                    pc++;
                }
                void sub() {
                    auto a = stack.back(); stack.pop_back();
                    auto b = stack.back(); stack.pop_back();
                    zkevm_word_type result = wrapping_sub(a, b);
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    //! Trace subtraction is not correct:
                    //! 1 - 6e38d4999fdb6fac24973e508cde9397e369c5af = ffffffffffffffffffffffff91c72b6660249053db68c1af73216c681c963a52 != ffffffffffffffffffffffffffffffffffffffff
                    // if( last_opcode_push.back() != result){
                    //     BOOST_LOG_TRIVIAL(trace) << "Subtraction error: " << std::hex << a << " - " << b << " = " << result << " != " << last_opcode_push.back() << std::dec ;
                    // }
                    // BOOST_ASSERT(last_opcode_push.back() == result);
                    stack.push_back(result);
                    stack_rw_operations += 3;
                    gas -= 3;
                    pc++;
                }
                void add() {
                    auto a = stack.back(); stack.pop_back();
                    auto b = stack.back(); stack.pop_back();
                    zkevm_word_type result = wrapping_add(a, b);
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == result);
                    stack.push_back(result);
                    stack_rw_operations += 3;
                    gas -= 3;
                    pc++;
                }
                void div() {
                    auto a = stack.back(); stack.pop_back();
                    auto b = stack.back(); stack.pop_back();
                    zkevm_word_type result = b != 0u ? a / b : 0u;
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == result);
                    stack.push_back(result);
                    stack_rw_operations += 3;
                    gas -= 5;
                    pc++;
                }
                void mod() {
                    auto a = stack.back(); stack.pop_back();
                    auto b = stack.back(); stack.pop_back();
                    zkevm_word_type q = b != 0u ? a % b : a;
                    zkevm_word_type result =
                        b != 0u ? q : 0u;  // according to EVM spec a % 0 = 0                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == result);
                    stack.push_back(result);
                    stack_rw_operations += 3;
                    gas -= 5;
                    pc++;
                }
                void sdiv() {
                    auto a = stack.back(); stack.pop_back();
                    auto b_input = stack.back(); stack.pop_back();
                    bool overflow = (a == neg_one) && (b_input == min_neg);
                    zkevm_word_type b = overflow ? 1 : b_input;
                    zkevm_word_type a_abs = abs_word(a), b_abs = abs_word(b);
                    zkevm_word_type r_abs = b != 0u ? a_abs / b_abs : 0u;
                    zkevm_word_type result = (is_negative(a) == is_negative(b)) ? r_abs : negate_word(r_abs);
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == result);
                    stack.push_back(result);
                    stack_rw_operations += 3;
                    gas -= 5;
                    pc++;
                }
                void smod() {
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

                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == result);
                    stack.push_back(result);
                    stack_rw_operations += 3;
                    gas -= 5;
                    pc++;
                }
                void sar() {
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

                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    if( last_opcode_push.back() != result ){
                        BOOST_LOG_TRIVIAL(trace) << std::hex
                            << "SAR error b = " << b << std::endl
                            << " input_a = " << input_a << std::endl
                            << " result = " << result << std::endl
                            << " real_result = " << last_opcode_push.back() << std::endl
                            << " shift = " << shift << std::endl
                            << " r = " << r << std::endl
                            << " a = " << a << std::endl
                            << " is_negative(input_a) = " << is_negative(input_a)  << std::endl
                            << std::dec ;
                    }
                    BOOST_ASSERT(last_opcode_push.back() == result);
                    stack.push_back(result);
                    stack_rw_operations += 3;
                    gas -= 3;
                    pc++;
                }
                void mulmod(){
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

                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == result);
                    stack.push_back(result);
                    stack_rw_operations += 3;
                    gas -= 8;
                    pc++;
                }

                void addmod(){
                    zkevm_word_type a = stack.back(); stack.pop_back();
                    zkevm_word_type b = stack.back(); stack.pop_back();
                    zkevm_word_type modulus = stack.back(); stack.pop_back();
                    auto s_full = nil::crypto3::multiprecision::big_uint<257>(a) + b;
                    auto r_full = modulus != 0u ? s_full / modulus : 0u;
                    zkevm_word_type q = wrapping_sub(s_full, wrapping_mul(r_full, modulus)).truncate<256>();
                    zkevm_word_type result = modulus != 0u ? q : 0u;

                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == result);
                    stack.push_back(result);
                    stack_rw_operations += 3;
                    gas -= 8;
                    pc++;
                }

                void mul() {
                    auto a = stack.back(); stack.pop_back();
                    auto b = stack.back(); stack.pop_back();
                    zkevm_word_type result = wrapping_mul(a, b);
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == result);
                    stack.push_back(result);
                    stack_rw_operations += 3;
                    gas -= 5;
                    pc++;
                }
                void eq() {
                    auto a = stack.back(); stack.pop_back();
                    auto b = stack.back(); stack.pop_back();
                    zkevm_word_type result = a==b? 1: 0;
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    if( last_opcode_push.back() != result){
                        BOOST_LOG_TRIVIAL(trace) << "Equality error: " << std::hex << a << " ==s " << b << " = " << result << " != " << last_opcode_push.back() << std::dec ;
                    }
                    BOOST_ASSERT(last_opcode_push.back() == result);
                    stack.push_back(result);
                    stack_rw_operations += 3;
                    gas -= 3;
                    pc++;
                }
                void and_opcode() {
                    auto a = stack.back(); stack.pop_back();
                    auto b = stack.back(); stack.pop_back();
                    zkevm_word_type result = a & b;
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == result);
                    stack.push_back(result);
                    stack_rw_operations += 3;
                    gas -= 3;
                    pc++;
                }
                void or_opcode() {
                    auto a = stack.back(); stack.pop_back();
                    auto b = stack.back(); stack.pop_back();
                    zkevm_word_type result = a | b;
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == result);
                    stack.push_back(result);
                    stack_rw_operations += 3;
                    gas -= 3;
                    pc++;
                }
                void xor_opcode() {
                    auto a = stack.back(); stack.pop_back();
                    auto b = stack.back(); stack.pop_back();
                    zkevm_word_type result = a ^ b;
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == result);
                    stack.push_back(result);
                    stack_rw_operations += 3;
                    gas -= 3;
                    pc++;
                }
                void byte() {
                    auto N = stack.back(); stack.pop_back();
                    auto a = stack.back(); stack.pop_back();
                    auto n = w_to_8(N)[31];
                    zkevm_word_type result = N > 31? 0: w_to_8(a)[n];
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == result);
                    stack.push_back(result);
                    stack_rw_operations += 3;
                    gas -= 3;
                    pc++;
                }
                void three_operands_arithmetic() {
                    stack.pop_back();
                    stack.pop_back();
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 4;
                    pc++;
                }
                void exp() {
                    auto a = stack.back(); stack.pop_back();
                    auto d = stack.back(); stack.pop_back();
                    zkevm_word_type result = exp_by_squaring(a, d);

                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == result);
                    BOOST_ASSERT(last_opcode_gas_cost == 10 + 50 * count_significant_bytes(d));

                    stack.push_back(result);
                    stack_rw_operations += 3;
                    pc++;
                    gas -= 10 + 50 * count_significant_bytes(d);
                }
                void signextend() {
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

                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == result);
                    stack.push_back(result);

                    stack_rw_operations += 3;
                    pc++;
                    gas -= 5;
                }
                void keccak() {
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

                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == result);
                    stack.push_back(result);

                    std::size_t cost = 30 + 6 * ((length + 31) / 32) + memory_expansion;
                    BOOST_ASSERT(last_opcode_gas_cost == cost);
                    gas -= cost;
                    stack_rw_operations += 3;
                    memory_rw_operations += length;
                    pc++;
                }
                void address() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    if( last_opcode_push.back() != call_context_address){
                        BOOST_LOG_TRIVIAL(trace) << "Address opcode error: our " << std::hex
                            << call_context_address << " != "
                            << last_opcode_push.back() << std::dec ;
                    }
                    BOOST_ASSERT(last_opcode_push.back() == call_context_address);
                    stack.push_back(call_context_address);
                    stack_rw_operations += 1;
                    gas -= 2;
                    pc++;
                }
                void balance() {
                    zkevm_word_type addr = stack.back(); stack.pop_back();
                    BOOST_LOG_TRIVIAL(trace) << "addr = " << std::hex << addr << std::dec ;
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    if( last_opcode_push.back() != _accounts_current_state[addr].balance){
                        BOOST_LOG_TRIVIAL(trace) << "Balance opcode error. Our result : " << std::hex
                            << _accounts_current_state[addr].balance << " != "
                            << last_opcode_push.back() << std::dec ;
                    }
                    //BOOST_ASSERT(last_opcode_push.back() == _accounts_current_state[addr].balance);
                    // TODO: Not clear logic! Fix!
                    stack.push_back(last_opcode_push.back());
                    if( _call_stack.back().was_accessed.count({addr, 1, 0}) == 0){
                        gas -= 2500;
                    }
                    gas -= 100;
                    _call_stack.back().was_accessed.insert({addr, 1, 0});
                    BOOST_LOG_TRIVIAL(trace) << "Touch addr 0x" << std::hex << addr << std::dec ;
                    stack_rw_operations += 2;
                    state_rw_operations += 2;
                    pc++;
                }
                void origin() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == tx.from);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                    pc++;
                    gas -= 2;
                }
                void caller_opcode() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    if( last_opcode_push.back() != caller){
                        BOOST_LOG_TRIVIAL(trace) << "Caller opcode error: " << std::hex
                            << last_opcode_push.back() << " != "
                            << caller << " tx_from = "
                            << tx.from << std::dec ;
                    }
                    BOOST_ASSERT(last_opcode_push.back() == caller);
                    stack.push_back(caller);
                    stack_rw_operations += 1;
                    pc++;
                    gas -= 2;
                }
                void callvalue() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    if( last_opcode_push.back() != call_context_value){
                        BOOST_LOG_TRIVIAL(trace) << "Callvalue opcode error: " << std::hex
                            << last_opcode_push.back() << " != "
                            << call_context_value << std::dec ;
                    }
                    BOOST_ASSERT(last_opcode_push.back() == call_context_value);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                    pc++;
                    gas -= 2;
                }
                void calldataload() {
                    std::size_t offset = std::size_t(stack.back()); stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    zkevm_word_type result;
                    for( std::size_t i = 0; i < 32; i++){
                        result = ((offset + i) < calldata.size())? (result << 8) + calldata[offset+i]: result << 8;
                    }
                    BOOST_ASSERT(last_opcode_push.back() == result);
                    stack.push_back(result);
                    stack_rw_operations += 2;
                    calldata_rw_operations += 32;
                    pc++;
                    gas -= 3;
                }
                void calldatasize() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == calldata.size());
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                    gas -= 2;
                    pc++;
                }
                void calldatacopy() {
                    std::size_t dst = std::size_t(stack.back()); stack.pop_back();
                    std::size_t src = std::size_t(stack.back()); stack.pop_back();
                    std::size_t length = std::size_t(stack.back()); stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 0);
                    //BOOST_ASSERT(last_opcode_mem_offset == dst);

                    std::size_t minimum_word_size = (length + 31) / 32;
                    std::size_t next_mem = std::max(length == 0? 0: dst + length, memory.size());
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());

                    // BOOST_LOG_TRIVIAL(trace) << "DstOffset = " << dst ;
                    // BOOST_LOG_TRIVIAL(trace) << "Length = " << length ;
                    // BOOST_LOG_TRIVIAL(trace) << "CallDataSize = " << calldata.size() ;
                    if( memory.size() < next_mem) memory.resize(next_mem);
                    for( std::size_t i = 0; i < length; i++){
                        memory[dst+i] = src + i < calldata.size()? calldata[src+i]: 0;
                    }
                    BOOST_LOG_TRIVIAL(trace) << byte_vector_to_sparse_hex_string(memory, dst, length);


                    // BOOST_LOG_TRIVIAL(trace) << "Memory: " << std::hex;
                    // for( auto c:memory) BOOST_LOG_TRIVIAL(trace) << std::size_t(c) << " ";
                    // BOOST_LOG_TRIVIAL(trace) << std::dec ;

                    bool is_equal = true;
                    for( std::size_t i = 0; i < last_opcode_memory.size(); i++){
                        is_equal = (memory[last_opcode_mem_offset+i] == last_opcode_memory[i]);
                        if( !is_equal ) break;
                    }
                    if(!is_equal){
                        BOOST_LOG_TRIVIAL(trace) << "last_opcode_mem offset = " << last_opcode_mem_offset << " :" << std::hex;
                        for( std::size_t i = 0; i < last_opcode_memory.size(); i++ ) BOOST_LOG_TRIVIAL(trace) << std::size_t(last_opcode_memory[i]) << " ";
                        BOOST_LOG_TRIVIAL(trace) << std::dec ;
                        BOOST_LOG_TRIVIAL(trace) << "real memory     offset = " << last_opcode_mem_offset << " :" << std::hex;
                        for( std::size_t i = 0; i < last_opcode_memory.size(); i++ ) BOOST_LOG_TRIVIAL(trace) << std::size_t(memory[last_opcode_mem_offset + i]) << " ";
                        BOOST_LOG_TRIVIAL(trace) << std::dec ;
                    }
                    BOOST_ASSERT(is_equal);

                    gas -=3; //static gas
                    gas -= 3 * minimum_word_size + memory_expansion; //dynamic gas
                    stack_rw_operations += 3;
                    memory_rw_operations += length;
                    calldata_rw_operations += length;
                    pc++;
                }
                void codesize() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == bytecode.size());
                    stack.push_back(bytecode.size());
                    gas -= 2;
                    stack_rw_operations += 1;
                    pc++;
                }
                void codecopy() {
                    std::size_t dst = std::size_t(stack.back()); stack.pop_back();
                    std::size_t src = std::size_t(stack.back()); stack.pop_back();
                    std::size_t length = std::size_t(stack.back()); stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 0);
                    BOOST_ASSERT(last_opcode_mem_offset == dst);

                    std::size_t minimum_word_size = (length + 31) / 32;
                    std::size_t next_mem = std::max(dst + length, memory.size());
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());
                    std::size_t next_memory_size = (memory_size_word_util(next_mem))*32;

                    if( memory.size() < dst + length) memory.resize(dst + length);
                    for( std::size_t i = 0; i < length; i++){
                        memory[dst+i] = src + i < bytecode.size()? bytecode[src+i]: 0;
                    }
                    for( std::size_t i = 0; i < last_opcode_memory.size(); i++){
                        BOOST_ASSERT(memory[dst+i] == last_opcode_memory[i]);
                    }
                    BOOST_ASSERT(last_opcode_gas_cost == 3 + 3 * minimum_word_size + memory_expansion);

                    gas -=3; //static gas
                    gas -= 3 * minimum_word_size + memory_expansion; //dynamic gas
                    stack_rw_operations += 3;
                    memory_rw_operations += length;
                    pc++;
                }
                void gasprice() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == tx.gasprice);
                    stack.push_back(last_opcode_push.back());
                    gas -= 2;
                    stack_rw_operations += 1;
                    pc++;
                }
                void returndatasize() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    if( last_opcode_push.back() != returndata.size() ) {
                        BOOST_LOG_TRIVIAL(trace) << "Our returndatasize = " << returndata.size() << " != " << last_opcode_push.back()  ;
                    }
                    BOOST_ASSERT(last_opcode_push.back() == returndata.size());
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                    pc++;
                    gas -= 2;
                }
                void returndatacopy() {
                    std::size_t dst = std::size_t(stack.back()); stack.pop_back();
                    std::size_t src = std::size_t(stack.back()); stack.pop_back();
                    std::size_t length = std::size_t(stack.back()); stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 0);
                    //BOOST_ASSERT(last_opcode_mem_offset == dst);

                    std::size_t minimum_word_size = (length + 31) / 32;
                    std::size_t next_mem = std::max(dst + length, memory.size());
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());
                    std::size_t next_memory_size = (memory_size_word_util(next_mem))*32;

                    if( memory.size() < dst + length) memory.resize(dst + length);
                    for( std::size_t i = 0; i < length; i++){
                        memory[dst+i] = src + i < returndata.size()? returndata[src+i]: 0;
                    }

                    for( std::size_t i = 0; i < last_opcode_memory.size(); i++){
                        BOOST_ASSERT(memory[dst+i] == last_opcode_memory[dst + i - last_opcode_mem_offset]);
                    }
                    BOOST_ASSERT(last_opcode_gas_cost == 3 + 3 * minimum_word_size + memory_expansion);

                    gas -=3; //static gas
                    gas -= 3 * minimum_word_size + memory_expansion; //dynamic gas
                    stack_rw_operations += 3;
                    memory_rw_operations += length;
                    calldata_rw_operations += length;
                    pc++;
                }

                void extcodesize() {
                    zkevm_word_type addr = stack.back(); stack.pop_back();
                    BOOST_LOG_TRIVIAL(trace) << "addr = " << std::hex << addr << std::dec ;
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == _accounts_current_state[addr].bytecode.size());
                    stack.push_back(last_opcode_push.back());
                    // TODO: change 1 maybe
                    if( _call_stack.back().was_accessed.count({addr, 1, 0}) == 0){
                        gas -= 2500;
                    }
                    gas -= 100;
                    _call_stack.back().was_accessed.insert({addr, 1, 0});
                    BOOST_LOG_TRIVIAL(trace) << "Touch addr 0x" << std::hex << addr << std::dec ;
                    stack_rw_operations += 2;
                    state_rw_operations += 2;
                    pc++;
                }
                void extcodecopy() {
                    stack.pop_back();
                    stack.pop_back();
                    stack.pop_back();
                    stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 4;
                    pc++;
                }
                void extcodehash() {
                    zkevm_word_type addr = stack.back(); stack.pop_back();
                    BOOST_LOG_TRIVIAL(trace) << "addr = " << std::hex << addr << std::dec ;
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == _accounts_current_state[addr].code_hash);
                    stack.push_back(last_opcode_push.back());
                    // TODO: change 1 maybe
                    if( _call_stack.back().was_accessed.count({addr, 1, 0}) == 0){
                        gas -= 2500;
                    }
                    gas -= 100;
                    _call_stack.back().was_accessed.insert({addr, 1, 0});
                    BOOST_LOG_TRIVIAL(trace) << "Touch addr 0x" << std::hex << addr << std::dec ;
                    stack_rw_operations += 2;
                    state_rw_operations += 2;
                    pc++;
                }
                void blockhash() {
                    // TODO! Load more data!
                    std::size_t n = std::size_t(stack.back()); stack.pop_back();
                    BOOST_LOG_TRIVIAL(trace) << "Block number = " << n ;
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    if(n == (block.number - 1)) {
                        BOOST_ASSERT(last_opcode_push.back() == block.parent_hash);
                    } else {
                        BOOST_LOG_TRIVIAL(trace) << "Unknown hash for block number = " << n ;
                    }
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                    pc++;
                    gas -= 20;
                }
                void coinbase() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == block.coinbase);
                    stack.push_back(last_opcode_push.back());
                    BOOST_LOG_TRIVIAL(trace) << "Touch address 0x " << std::hex << block.coinbase << std::dec ;
                    _call_stack.back().was_accessed.insert({block.coinbase, 1, 0});
                    gas -= 2;
                    stack_rw_operations += 1;
                    pc++;
                }
                void timestamp() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    if( last_opcode_push.back() != block.timestamp){
                        BOOST_LOG_TRIVIAL(trace) << "Timestamp error: " << last_opcode_push.back() << " != " << block.timestamp ;
                    }
                    BOOST_ASSERT(last_opcode_push.back() == block.timestamp);
                    stack.push_back(block.timestamp);
                    gas -= 2;
                    stack_rw_operations += 1;
                    pc++;
                }
                void number() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == block.number);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                    pc++;
                    gas -= 2;
                }
                void difficulty() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == block.difficulty);
                    stack.push_back(last_opcode_push.back());
                    gas -= 2;
                    stack_rw_operations += 1;
                    pc++;
                }
                void gaslimit() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                    pc++;
                }
                void chainid() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == tx.chain_id);
                    stack.push_back(tx.chain_id);
                    gas -= 2;
                    stack_rw_operations += 1;
                    pc++;
                }
                void selfbalance() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    if(last_opcode_push.back() != _accounts_current_state[call_context_address].balance){
                        BOOST_LOG_TRIVIAL(trace)
                            << "Selfbalance error " << std::hex << _accounts_current_state[call_context_address].balance << " != "
                            << last_opcode_push.back()
                            << std::dec ;
                        BOOST_LOG_TRIVIAL(trace) << " address =  " << std::hex
                            << call_context_address
                            << std::dec ;
                    }
                    BOOST_ASSERT(last_opcode_push.back() == _accounts_current_state[call_context_address].balance);
                    stack.push_back(last_opcode_push.back());
                    gas -= 5;
                    stack_rw_operations += 1;
                    pc++;
                }
                void basefee() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == block.basefee);
                    stack.push_back(last_opcode_push.back());
                    gas -= 2;
                    stack_rw_operations += 1;
                    pc++;
                }
                void blobhash() {
                    std::size_t index = std::size_t(stack.back()); stack.pop_back();
                    //BOOST_ASSERT(last_opcode_push.size() == 1);
                    //BOOST_ASSERT(last_opcode_push.back() == tx_hash);
                    if( index >= tx.blob_versioned_hashes.size() ){
                        stack.push_back(0);
                        BOOST_LOG_TRIVIAL(trace) << "Index = " << index << " >= " << tx.blob_versioned_hashes.size() ;
                    } else {
                        stack.push_back(tx.blob_versioned_hashes[index]);
                        BOOST_LOG_TRIVIAL(trace) << "Index = " << index  << " hash = 0x" << std::hex << tx.blob_versioned_hashes[index] << std::dec ;
                    }
                    gas -= 3;
                    stack_rw_operations += 2;
                    pc++;
                }
                void blobbasefee() {
                    // BOOST_ASSERT(last_opcode_push.size() == 1);
                    //BOOST_ASSERT(last_opcode_push.back() == tx_hash);
                    // TODO: Understand why!
                    stack.push_back(1);
                    gas -= 2;
                    stack_rw_operations += 2;
                    pc++;
                }
                void tload() {
                    auto addr = stack.back(); stack.pop_back();
                    // ! Trace doesn't contain last_opcode_push
                    //BOOST_ASSERT(last_opcode_push.size() == 1);
                    if( _call_stack.back().transient_storage.count({call_context_address, addr}) == 0){
                        _call_stack.back().transient_storage[{call_context_address, addr}] = 0;
                    }
                    stack.push_back(_call_stack.back().transient_storage[{call_context_address, addr}]);
                    gas -= 100;
                    stack_rw_operations += 2;  state_rw_operations += 2;
                    pc++;
                }
                void tstore() {
                    auto key = stack.back();stack.pop_back();
                    auto value = stack.back(); stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 0);
                    _call_stack.back().transient_storage[{call_context_address, key}] = value;
                    gas -= 100;
                    stack_rw_operations += 2;  state_rw_operations += 2;
                    pc++;
                }
                void mcopy() {
                    std::size_t dst = std::size_t(stack.back()); stack.pop_back();
                    std::size_t src = std::size_t(stack.back()); stack.pop_back();
                    std::size_t length = std::size_t(stack.back()); stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 0);
                    //BOOST_ASSERT(last_opcode_mem_offset == dst);

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

                    bool is_equal = true;
                    for( std::size_t i = 0; i < last_opcode_memory.size(); i++){
                        is_equal = (memory[last_opcode_mem_offset+i] == last_opcode_memory[i]);
                        if( !is_equal ) break;
                    }
                    if(!is_equal){
                        BOOST_LOG_TRIVIAL(trace) << "last_opcode_mem offset = " << last_opcode_mem_offset << " :" << std::hex;
                        BOOST_LOG_TRIVIAL(trace) << byte_vector_to_sparse_hex_string(last_opcode_memory) << std::dec;
                        BOOST_LOG_TRIVIAL(trace) << "real memory     offset = " << last_opcode_mem_offset << " :" << std::hex;
                        BOOST_LOG_TRIVIAL(trace) << byte_vector_to_sparse_hex_string(memory, last_opcode_mem_offset, last_opcode_memory.size()) << std::dec;
                    }
                    BOOST_ASSERT(is_equal);

                    gas -=3; //static gas
                    gas -= 3 * minimum_word_size + memory_expansion; //dynamic gas
                    stack_rw_operations += 3;
                    memory_rw_operations += 2 * length;
                    pc++;
                }
                void create() {
                    zkevm_word_type value = stack.back(); stack.pop_back();
                    call_args_offset = std::size_t(stack.back()); stack.pop_back();
                    call_args_length = std::size_t(stack.back()); stack.pop_back();

                    // TODO: Compute address ourselves
                    caller = call_context_address;
                    call_context_address = last_opcode_push.back();
                    BOOST_LOG_TRIVIAL(trace) << "Value = 0x" << std::hex << value << std::dec ;
                    BOOST_LOG_TRIVIAL(trace) << "call_args_offset = " << call_args_offset ;
                    BOOST_LOG_TRIVIAL(trace) << "call_args_length = " << call_args_length ;

                    std::size_t next_mem = std::max(memory.size(), call_args_length == 0? 0: call_args_offset + call_args_length);
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());
                    if( memory.size() < next_mem ){
                        BOOST_LOG_TRIVIAL(trace) << "Memory expansion " << memory.size() << " => " << next_mem ;
                        memory.resize(next_mem);
                    }
                    gas -= memory_expansion;

                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    // TODO: Add address computation here!
                    gas -= 32000;
                    std::size_t call_args_word_size = (call_args_length + 31) / 32;
                    gas -= (call_args_word_size * 2);
                    stack_rw_operations += 4;

                    call_value = value;
                    call_is_create = true;
                    call_is_create2 = false;
                    call_gas = gas;
                }

                void create2() {
                    zkevm_word_type value = stack.back(); stack.pop_back();
                    call_args_offset = std::size_t(stack.back()); stack.pop_back();
                    call_args_length = std::size_t(stack.back()); stack.pop_back();
                    zkevm_word_type salt = stack.back(); stack.pop_back();

                    // TODO: Compute address ourselves
                    caller = call_context_address;
                    call_context_address = last_opcode_push.back();
                    BOOST_LOG_TRIVIAL(trace) << "Value = 0x" << std::hex << value << std::dec ;
                    BOOST_LOG_TRIVIAL(trace) << "call_args_offset = " << call_args_offset ;
                    BOOST_LOG_TRIVIAL(trace) << "call_args_length = " << call_args_length ;

                    std::size_t next_mem = std::max(memory.size(), call_args_length == 0? 0: call_args_offset + call_args_length);
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());
                    if( memory.size() < next_mem ){
                        BOOST_LOG_TRIVIAL(trace) << "Memory expansion " << memory.size() << " => " << next_mem ;
                        memory.resize(next_mem);
                    }
                    gas -= memory_expansion;

                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    // TODO: Add address computation here!
                    gas -= 32000;
                    std::size_t call_args_word_size = (call_args_length + 31) / 32;
                    gas -= (call_args_word_size * 8);
                    stack_rw_operations += 4;

                    call_value = value;
                    call_is_create = false;
                    call_is_create2 = true;
                    call_gas = gas;
                }
                void selfdestruct() {
                    auto addr = stack.back(); stack.pop_back();
                    BOOST_LOG_TRIVIAL(trace) << "addr = 0x" << std::hex << addr << std::dec ;
                    gas -= 5000;
                    if( _existing_accounts.count(addr) == 0){
                        gas -= 25000;
                    }
                    if(_call_stack.back().was_accessed.count({addr, 1, 0}) == 0){
                        gas -= 2500;
                    }
                    _existing_accounts.erase(call_context_address);
                    _accounts_current_state[addr].balance += _accounts_current_state[call_context_address].balance;
                    _accounts_current_state[call_context_address].balance = 0;
                    _call_stack[_call_stack.size()-2].was_accessed.insert(_call_stack.back().was_accessed.begin(), _call_stack.back().was_accessed.end());
                    _call_stack[_call_stack.size()-2].was_written.insert(_call_stack.back().was_written.begin(), _call_stack.back().was_written.end());
                    for( auto & [k,v]: _call_stack.back().transient_storage){
                        _call_stack[_call_stack.size()-2].transient_storage[k] = v;
                    }
                    returndata.clear();
                    call_status = call_context_address;
                    stack_rw_operations += 1;
                }
                void callcode() {
                    zkevm_word_type gas = stack.back();  stack.pop_back();
                    zkevm_word_type addr = stack.back();  stack.pop_back();
                    zkevm_word_type value = stack.back();  stack.pop_back();
                    zkevm_word_type args_offset = stack.back();  stack.pop_back();
                    zkevm_word_type args_length = stack.back();  stack.pop_back();
                    zkevm_word_type ret_offset = stack.back();  stack.pop_back();
                    zkevm_word_type ret_length = stack.back();  stack.pop_back();
                    call_context_address = addr;
                    BOOST_LOG_TRIVIAL(trace) << "addr = 0x" << std::hex << addr << std::dec ;
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 8;
                }
                void transfer_to_eth_account(){
                    std::size_t transfer_gas = std::size_t(stack.back());  stack.pop_back();
                    zkevm_word_type transfer_addr = stack.back() & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256; stack.pop_back();
                    zkevm_word_type transfer_value = stack.back();  stack.pop_back();
                    std::size_t transfer_args_offset = std::size_t(stack.back());  stack.pop_back();
                    std::size_t transfer_args_length = std::size_t(stack.back());  stack.pop_back();
                    std::size_t ret_offset = std::size_t(stack.back());  stack.pop_back();
                    std::size_t ret_length = std::size_t(stack.back());  stack.pop_back();
                    _call_stack.back().lastcall_returndataoffset = ret_offset;
                    _call_stack.back().lastcall_returndatalength = ret_length;

                    BOOST_LOG_TRIVIAL(trace) << "Transfer to ethereum account " << std::hex <<  transfer_addr << std::dec  ;
                    BOOST_LOG_TRIVIAL(trace) << "value = " << std::hex << transfer_value << std::dec ;

                    gas -= 100;
                    if( _call_stack.back().was_accessed.count({transfer_addr, 1, 0}) == 0) {
                        BOOST_LOG_TRIVIAL(trace) << "Was not accessed" ;
                        gas -= 2500;
                        _call_stack.back().was_accessed.insert({transfer_addr, 1, 0});
                    } else {
                        BOOST_LOG_TRIVIAL(trace) << "Was accessed" ;
                    }
                    if( transfer_value != 0 ) { gas -= 9000; gas += 2300; }
                    if( transfer_value != 0 && (_existing_accounts.count(transfer_addr) == 0)) {
                        BOOST_LOG_TRIVIAL(trace) << "Account is not exist" ;
                        gas -= 25000;
                    } else {
                        // TODO! Input problem. We cannot distinguish non-existing account from existing account with zero balance
                        if( gas != last_opcode_gas_used){
                            BOOST_LOG_TRIVIAL(trace) << "Transfer to empty account error:" << gas << " != " << last_opcode_gas_used ;
                        }
                        gas = last_opcode_gas_used;
                    }

                    stack.push_back(1);
                    stack_rw_operations += 8;
                    BOOST_LOG_TRIVIAL(trace) << "transfer completed" ;
                    pc++;
                    _accounts_current_state[call_context_address].balance -= transfer_value;
                    _accounts_current_state[transfer_addr].balance += transfer_value;
                    returndata.clear();
                    //TODO! Understand this logic, not just use results
                    returndata.resize(transfer_args_length, 0);
                }
                void call(bool transfer) {
                    if( stack[stack.size() - 2] >= 0x1 && stack[stack.size() - 2] <= 0xa){
                        dummycallprecompile();
                        return;
                    }
                    if( transfer ){
                        transfer_to_eth_account();
                        return;
                    }
                    call_is_create = false;
                    call_is_create2 = false;
                    call_gas = std::size_t(stack.back());  stack.pop_back();
                    // TODO: add this xor to circuits!
                    call_addr = stack.back() & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256; stack.pop_back();
                    caller = call_context_address;
                    call_context_value = call_value = stack.back();  stack.pop_back();
                    call_args_offset = std::size_t(stack.back());  stack.pop_back();
                    call_args_length = std::size_t(stack.back());  stack.pop_back();
                    std::size_t ret_offset = std::size_t(stack.back());  stack.pop_back();
                    std::size_t ret_length = std::size_t(stack.back());  stack.pop_back();
                    _call_stack.back().lastcall_returndataoffset = ret_offset;
                    _call_stack.back().lastcall_returndatalength = ret_length;
                    _accounts_current_state[caller].balance -= call_value;
                    _accounts_current_state[call_addr].balance += call_value;

                    BOOST_LOG_TRIVIAL(trace) << "caller = 0x" << std::hex << call_context_address << " balance = " << _accounts_current_state[caller].balance << std::dec ;
                    BOOST_LOG_TRIVIAL(trace) << "callee = 0x" << std::hex << call_addr << " balance = " << _accounts_current_state[call_addr].balance << std::dec ;
                    BOOST_LOG_TRIVIAL(trace) << "gas = " << gas ;
                    BOOST_LOG_TRIVIAL(trace) << "call_gas = " << call_gas ;
                    BOOST_LOG_TRIVIAL(trace) << "value = 0x" << std::hex << call_value << std::dec ;

                    // BOOST_LOG_TRIVIAL(trace) <<
                    //     "gas = 0x" << std::hex << gas << std::dec << std::endl <<
                    //     "addr = 0x" << std::hex << addr << std::dec << std::endl <<
                    //     "value = 0x" << std::hex << value << std::dec << std::endl <<
                    //     "args_offset = 0x" << std::hex << args_offset << std::dec << std::endl <<
                    //     "args_length = 0x" << std::hex << args_length << std::dec << std::endl <<
                    //     "ret_offset = 0x" << std::hex << ret_offset << std::dec << std::endl <<
                    //     "ret_length = 0x" << std::hex << ret_length << std::dec ;
                    // BOOST_ASSERT(last_opcode_push.size() == 1);
                    //stack.push_back(last_opcode_push.back());

                    // TODO: check memory expansion
                    std::size_t next_mem = memory.size();
                    next_mem = std::max(next_mem, call_args_length == 0 ? 0: call_args_offset + call_args_length);
                    next_mem = std::max(next_mem, ret_length == 0 ? 0: ret_offset + ret_length);
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());

                    if( memory.size() < next_mem) {
                        BOOST_LOG_TRIVIAL(trace) << "Memory expansion = " << memory_expansion ;
                        BOOST_LOG_TRIVIAL(trace) << "Memory size = " << memory.size() ;
                        BOOST_LOG_TRIVIAL(trace) << "After calldata = " << call_args_offset << " " <<  call_args_length ;
                        BOOST_LOG_TRIVIAL(trace) << "After return = " << ret_offset << " " <<  ret_length ;
                        memory.resize(next_mem, 0);
                    }
                    gas -= memory_expansion;

                    if( call_value != 0 ) gas -= 9000;
                    if( call_value != 0 && (_existing_accounts.count(call_addr) == 0)) {
                        BOOST_LOG_TRIVIAL(trace) << "Account is not exist" ;
                        gas -= 25000;
                    }
                    stack_rw_operations += 8;
                    call_context_address = call_addr;
                }
                void precomp_ecrecover(){
                    //! TODO implement precompile
                    BOOST_LOG_TRIVIAL(trace) << "ecRecover precompile" ;
                    BOOST_LOG_TRIVIAL(trace) << "last_mem_offset = " << last_opcode_mem_offset ;
                    BOOST_LOG_TRIVIAL(trace) << "last_mem_size = " << last_opcode_memory.size() ;

                    std::size_t precomp_gas = std::size_t(stack.back()); stack.pop_back(); // gas
                    zkevm_word_type precomp_addr = stack.back(); stack.pop_back(); // addr
                    std::size_t precomp_args_offset = std::size_t(stack.back()); stack.pop_back(); // args_offset
                    std::size_t precomp_args_length = std::size_t(stack.back()); stack.pop_back(); // args_length
                    std::size_t precomp_ret_offset = std::size_t(stack.back()); stack.pop_back(); // ret_offset
                    std::size_t precomp_ret_length = std::size_t(stack.back()); stack.pop_back(); // ret_length
                    BOOST_ASSERT( precomp_addr == 0x1 );

                    // BOOST_LOG_TRIVIAL(trace) << "precomp_gas = " << precomp_gas ;
                    // BOOST_LOG_TRIVIAL(trace) << "precomp_addr = 0x" << std::hex << precomp_addr << std::dec ;
                    // BOOST_LOG_TRIVIAL(trace) << "precomp_args_offset = " << precomp_args_offset ;
                    // BOOST_LOG_TRIVIAL(trace) << "precomp_args_length = " << precomp_args_length ;
                    // BOOST_LOG_TRIVIAL(trace) << "precomp_ret_offset = " << precomp_ret_offset ;
                    // BOOST_LOG_TRIVIAL(trace) << "precomp_ret_length = " << precomp_ret_length ;

                    if(memory.size() < precomp_ret_offset + precomp_ret_length) memory.resize(precomp_ret_offset + precomp_ret_length, 0);
                    returndata.clear();
                    for( std::size_t i = 0; i < precomp_ret_length; i++){
                        memory[precomp_ret_offset + i] = last_opcode_memory[precomp_ret_offset + i - last_opcode_mem_offset];
                        returndata.push_back(memory[precomp_ret_offset + i]);
                    }

                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 7;
                    gas -= 3100;
                    pc++;
                    _call_stack.back().lastcall_returndataoffset = precomp_ret_offset;
                    _call_stack.back().lastcall_returndatalength = precomp_ret_length;
                }
                void precomp_identity(){
                    // TODO: implement precompile
                    BOOST_LOG_TRIVIAL(trace) << "Identity precompile" ;
                    std::size_t precomp_gas = std::size_t(stack.back()); stack.pop_back(); // gas
                    zkevm_word_type precomp_addr = stack.back(); stack.pop_back(); // addr
                    std::size_t precomp_args_offset = std::size_t(stack.back()); stack.pop_back(); // args_offset
                    std::size_t precomp_args_length = std::size_t(stack.back()); stack.pop_back(); // args_length
                    std::size_t precomp_ret_offset = std::size_t(stack.back()); stack.pop_back(); // ret_offset
                    std::size_t precomp_ret_length = std::size_t(stack.back()); stack.pop_back(); // ret_length
                    BOOST_ASSERT( precomp_addr == 0x4 );
                    std::size_t data_word_size = (precomp_args_length + 31) / 32;

                    BOOST_LOG_TRIVIAL(trace) << "precomp_gas = " << precomp_gas ;
                    BOOST_LOG_TRIVIAL(trace) << "precomp_addr = 0x" << std::hex << precomp_addr << std::dec ;
                    BOOST_LOG_TRIVIAL(trace) << "precomp_args_offset = " << precomp_args_offset ;
                    BOOST_LOG_TRIVIAL(trace) << "precomp_args_length = " << precomp_args_length ;
                    BOOST_LOG_TRIVIAL(trace) << "precomp_ret_offset = " << precomp_ret_offset ;
                    BOOST_LOG_TRIVIAL(trace) << "precomp_ret_length = " << precomp_ret_length ;

                    // TODO: memory expansion gas cost
                    std::size_t next_mem = memory.size();
                    next_mem = std::max(next_mem, precomp_args_length == 0? 0: precomp_args_offset + precomp_args_length);
                    next_mem = std::max(next_mem, precomp_ret_length == 0? 0: precomp_ret_offset + precomp_ret_length);
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());
                    gas -= memory_expansion;
                    gas -= 100;
                    if( next_mem > memory.size()){
                        BOOST_LOG_TRIVIAL(trace) << "Memory expansion " << memory.size() << "=>" << next_mem ;
                        memory.resize(next_mem, 0);
                    }

                    returndata.clear();
                    for( std::size_t i = 0; i < precomp_args_length; i++){
                        returndata.push_back(memory[precomp_args_offset + i]);
                    }
                    std::size_t real_ret_length = std::min(precomp_args_length, precomp_ret_length);
                    for( std::size_t i = 0; i < real_ret_length; i++){
                        memory[precomp_ret_offset + i] = returndata[i];
                    }
                    for( std::size_t i = 0; i < last_opcode_memory.size(); i++){
                        BOOST_ASSERT(memory[last_opcode_mem_offset + i] == last_opcode_memory[i]);
                    }

                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 7;
                    gas -= (15 + data_word_size * 3);
                    pc++;
                    _call_stack.back().lastcall_returndataoffset = precomp_ret_offset;
                    _call_stack.back().lastcall_returndatalength = precomp_ret_length;
                }

                void dummyprecompile() {
                    // TODO: implement all precompiles. This function should never be called
                    zkevm_word_type precomp_gas = stack.back(); stack.pop_back(); // gas sometimes is -1. It's strange but it's not used after
                    zkevm_word_type precomp_addr = stack.back(); stack.pop_back(); // addr
                    std::size_t precomp_args_offset = std::size_t(stack.back()); stack.pop_back(); // args_offset
                    std::size_t precomp_args_length = std::size_t(stack.back()); stack.pop_back(); // args_length
                    std::size_t precomp_ret_offset = std::size_t(stack.back()); stack.pop_back(); // ret_offset
                    std::size_t precomp_ret_length = std::size_t(stack.back()); stack.pop_back(); // ret_length
                    std::size_t data_word_size = (precomp_args_length + 31) / 32;

                    BOOST_LOG_TRIVIAL(trace) << "precomp_gas = 0x" << precomp_gas ;
                    BOOST_LOG_TRIVIAL(trace) << "precomp_addr = 0x" << std::hex << precomp_addr << std::dec ;
                    BOOST_LOG_TRIVIAL(trace) << "precomp_args_offset = " << precomp_args_offset ;
                    BOOST_LOG_TRIVIAL(trace) << "precomp_args_length = " << precomp_args_length ;
                    BOOST_LOG_TRIVIAL(trace) << "precomp_ret_offset = " << precomp_ret_offset ;
                    BOOST_LOG_TRIVIAL(trace) << "precomp_ret_length = " << precomp_ret_length ;

                    // TODO: memory expansion gas cost
                    std::size_t next_mem = memory.size();
                    next_mem = std::max(next_mem, precomp_args_length == 0? 0: precomp_args_offset + precomp_args_length);
                    next_mem = std::max(next_mem, precomp_ret_length == 0? 0: precomp_ret_offset + precomp_ret_length);
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());
                    // gas -= memory_expansion;
                    // gas -= 100;
                    if( next_mem > memory.size()){
                        BOOST_LOG_TRIVIAL(trace) << "Memory expansion " << memory.size() << "=>" << next_mem ;
                        memory.resize(next_mem, 0);
                    }
                    gas = last_opcode_gas_used;

                    std::vector<std::uint8_t> precomp_input;
                    for( std::size_t i = 0; i < precomp_args_length; i++){
                        precomp_input.push_back(memory[precomp_args_offset+i]);
                    }
                    returndata = precompiles_cache[{std::size_t(precomp_addr), precomp_input}];

                    std::size_t real_ret_length = std::min(returndata.size(), precomp_ret_length);
                    for( std::size_t i = 0; i < real_ret_length; i++){
                        memory[precomp_ret_offset + i] = returndata[i];
                    }
                    for( std::size_t i = 0; i < last_opcode_memory.size(); i++){
                        BOOST_ASSERT(memory[last_opcode_mem_offset + i] == last_opcode_memory[i]);
                    }

                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 7;
                    pc++;
                    _call_stack.back().lastcall_returndataoffset = precomp_ret_offset;
                    _call_stack.back().lastcall_returndatalength = precomp_ret_length;
                }

                void dummycallprecompile() {
                    BOOST_LOG_TRIVIAL(trace) << "Dummy call Precompile" ;
                    // TODO: implement all precompiles. This function should never be called
                    std::size_t precomp_gas = std::size_t(stack.back()); stack.pop_back(); // gas
                    zkevm_word_type precomp_addr = stack.back(); stack.pop_back(); // addr
                    zkevm_word_type precomp_value = stack.back(); stack.pop_back(); // value
                    std::size_t precomp_args_offset = std::size_t(stack.back()); stack.pop_back(); // args_offset
                    std::size_t precomp_args_length = std::size_t(stack.back()); stack.pop_back(); // args_length
                    std::size_t precomp_ret_offset = std::size_t(stack.back()); stack.pop_back(); // ret_offset
                    std::size_t precomp_ret_length = std::size_t(stack.back()); stack.pop_back(); // ret_length
                    std::size_t data_word_size = (precomp_args_length + 31) / 32;

                    BOOST_ASSERT( precomp_value == 0 );

                    BOOST_LOG_TRIVIAL(trace) << "precomp_gas = " << precomp_gas ;
                    BOOST_LOG_TRIVIAL(trace) << "precomp_addr = 0x" << std::hex << precomp_addr << std::dec ;
                    BOOST_LOG_TRIVIAL(trace) << "precomp_args_offset = " << precomp_args_offset ;
                    BOOST_LOG_TRIVIAL(trace) << "precomp_args_length = " << precomp_args_length ;
                    BOOST_LOG_TRIVIAL(trace) << "precomp_ret_offset = " << precomp_ret_offset ;
                    BOOST_LOG_TRIVIAL(trace) << "precomp_ret_length = " << precomp_ret_length ;

                    // TODO: memory expansion gas cost
                    std::size_t next_mem = memory.size();
                    next_mem = std::max(next_mem, precomp_args_length == 0? 0: precomp_args_offset + precomp_args_length);
                    next_mem = std::max(next_mem, precomp_ret_length == 0? 0: precomp_ret_offset + precomp_ret_length);
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());
                    // gas -= memory_expansion;
                    // gas -= 100;
                    if( next_mem > memory.size()){
                        BOOST_LOG_TRIVIAL(trace) << "Memory expansion " << memory.size() << "=>" << next_mem ;
                        memory.resize(next_mem, 0);
                    }
                    gas = last_opcode_gas_used;

                    BOOST_LOG_TRIVIAL(trace) << "Input data:" << std::hex;
                    std::vector<std::uint8_t> precomp_input;
                    for( std::size_t i = 0; i < precomp_args_length; i++){
                        precomp_input.push_back(memory[precomp_args_offset+i]);
                    }
                    BOOST_LOG_TRIVIAL(trace) << byte_vector_to_sparse_hex_string(precomp_input) << std::dec;

                    BOOST_LOG_TRIVIAL(trace) << "Output data:" << std::hex;
                    returndata = precompiles_cache[{std::size_t(precomp_addr), precomp_input}];
                    for( std::size_t i = 0; i < returndata.size(); i++){
                        memory[precomp_ret_offset + i] = returndata[i];
                    }
                    BOOST_LOG_TRIVIAL(trace) << byte_vector_to_sparse_hex_string(returndata) << std::dec;

                    std::size_t real_ret_length = std::min(returndata.size(), precomp_ret_length);
                    for( std::size_t i = 0; i < real_ret_length; i++){
                        memory[precomp_ret_offset + i] = returndata[i];
                    }
                    bool is_equal = true;;
                    for( std::size_t i = 0; i < last_opcode_memory.size(); i++){
                        auto c = last_opcode_mem_offset+i < memory.size()? memory[last_opcode_mem_offset + i]: 0;
                        if (c != last_opcode_memory[i]){
                            is_equal = false;
                            break;
                        }
                    }

                    if( !is_equal ) {
                        BOOST_LOG_TRIVIAL(trace) << "Our memory piece:" << std::hex;
                        BOOST_LOG_TRIVIAL(trace) << byte_vector_to_sparse_hex_string(memory, last_opcode_mem_offset, last_opcode_memory.size()) << std::dec;
                        BOOST_LOG_TRIVIAL(trace) << "Trace memo piece:" << std::hex;
                        BOOST_LOG_TRIVIAL(trace) << byte_vector_to_sparse_hex_string(last_opcode_memory) << std::dec;
                    }
                    BOOST_ASSERT(is_equal);
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 7;
                    pc++;
                    _call_stack.back().lastcall_returndataoffset = precomp_ret_offset;
                    _call_stack.back().lastcall_returndatalength = precomp_ret_length;
                }

                void staticcall() {
                    if( stack[stack.size() - 2] == 0x1){
                        precomp_ecrecover();
                        return;
                    }
                    if( stack[stack.size() - 2] == 0x2){
                        BOOST_LOG_TRIVIAL(trace) << "sha256 precompile" ;
                        dummyprecompile();
                        return;
                    }
                    if( stack[stack.size() - 2] == 0x3){
                        BOOST_LOG_TRIVIAL(trace) << "RIPEmd precompile" ;
                        dummyprecompile();
                        return;
                    }
                    if( stack[stack.size() - 2] == 0x4){
                        precomp_identity();
                        return;
                    }
                    if( stack[stack.size() - 2] == 0x5){
                        BOOST_LOG_TRIVIAL(trace) << "Modexp precompile" ;
                        dummyprecompile();
                        return;
                    }
                    if( stack[stack.size() - 2] == 0x6){
                        BOOST_LOG_TRIVIAL(trace) << "ecAdd precompile" ;
                        dummyprecompile();
                        return;
                    }
                    if( stack[stack.size() - 2] == 0x7){
                        BOOST_LOG_TRIVIAL(trace) << "ecMul precompile" ;
                        dummyprecompile();
                        return;
                    }
                    if( stack[stack.size() - 2] == 0x8){
                        BOOST_LOG_TRIVIAL(trace) << "ecPairing precompile" ;
                        dummyprecompile();
                        return;
                    }
                    if( stack[stack.size() - 2] == 0x9){
                        BOOST_LOG_TRIVIAL(trace) << "blake2f precompile" ;
                        dummyprecompile();
                        return;
                    }
                    if( stack[stack.size() - 2] == 0xa){
                        BOOST_LOG_TRIVIAL(trace) << "point evaluation precompile" ;
                        dummyprecompile();
                        return;
                    }

                    call_gas = std::size_t(stack.back());  stack.pop_back();
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


                    BOOST_LOG_TRIVIAL(trace) << "call_gas = " << call_gas ;
                    BOOST_LOG_TRIVIAL(trace) << "call_addr = 0x" << std::hex << call_addr << std::dec ;
                    // BOOST_LOG_TRIVIAL(trace) << "call_args_offset = " << call_args_offset ;
                    // BOOST_LOG_TRIVIAL(trace) << "call_args_length = " << call_args_length ;
                    // BOOST_LOG_TRIVIAL(trace) << "ret_offset = " << ret_offset ;
                    // BOOST_LOG_TRIVIAL(trace) << "ret_length = " << ret_length ;
                    // BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack_rw_operations += 7;

                    // TODO: check meemory expansion
                    std::size_t next_mem = memory.size();
                    next_mem = std::max(next_mem, ret_length == 0? 0: ret_offset + ret_length);
                    next_mem = std::max(next_mem, call_args_length ==0? 0: call_args_offset + call_args_length);
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());
                    if( memory.size() < next_mem) memory.resize(next_mem, 0);
                    gas -= memory_expansion;

                    call_context_address = call_addr;
                }

                void pop() {stack.pop_back(); pc++; gas-=2;}
                void jumpdest() {pc++;gas--;}
                void mload() {
                    std::size_t offset = std::size_t(stack.back()); stack.pop_back();

                    std::size_t memory_size_word = (memory.size() + 31) / 32;
                    std::size_t last_memory_cost = memory_size_word * memory_size_word / 512 + (3*memory_size_word);

                    if( memory.size() < offset + 32) memory.resize(offset + 32, 0);
                    memory_size_word = (memory.size() + 31) / 32;
                    std::size_t new_memory_cost = memory_size_word * memory_size_word / 512 + (3*memory_size_word);
                    std::size_t memory_expansion = new_memory_cost - last_memory_cost;

                    zkevm_word_type result = 0;
                    for( std::size_t i = 0; i < 32; i++){
                        result = (result << 8) + memory[offset + i];
                    }
                    bool is_equal = true;
                    for( std::size_t i = 0; i < last_opcode_memory.size(); i++){
                        is_equal = (memory[last_opcode_mem_offset+i] == last_opcode_memory[i]);
                        if(!is_equal) break;
                    }

                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    if( !is_equal || last_opcode_push.back() != result){
                        BOOST_LOG_TRIVIAL(trace) << "Offset = " << offset ;
                        BOOST_LOG_TRIVIAL(trace) << "Mload error our result: " << std::endl
                            << std::hex << result << " != " << std::endl
                            << last_opcode_push.back() << std::dec ;
                    }
                    BOOST_ASSERT(last_opcode_push.back() == result);
                    BOOST_ASSERT(is_equal);
                    BOOST_ASSERT(last_opcode_gas_cost == 3 + memory_expansion);

                    stack.push_back(result);
                    stack_rw_operations += 2; memory_rw_operations += 32;
                    gas -= 3 + memory_expansion;
                    pc++;
                }
                void mstore() {
                    std::size_t offset = std::size_t(stack.back()); stack.pop_back();
                    auto value = stack.back(); stack.pop_back();

                    std::size_t new_mem_size = std::max(offset + 32, memory.size());
                    std::size_t memory_expansion = memory_expansion_cost(new_mem_size, memory.size());

                    if( memory.size() < new_mem_size) {
                        BOOST_LOG_TRIVIAL(trace) << "Memory expansion " << memory.size() << " => " << new_mem_size ;
                        memory.resize(new_mem_size);
                    }
                    for( std::size_t i = 0; i < 32; i++){
                        memory[offset + 31 - i] = std::uint8_t(std::size_t(value % 256));
                        value = value >> 8;
                    }

                    if( last_opcode_gas_cost != 3 + memory_expansion){
                        BOOST_LOG_TRIVIAL(trace) << "Gas error: " << last_opcode_gas_cost << " != " << 3 + memory_expansion ;
                    }
                    BOOST_ASSERT(last_opcode_gas_cost == 3 + memory_expansion);
                    gas -= 3 + memory_expansion;

                    BOOST_ASSERT(last_opcode_push.size() == 0);
                    BOOST_ASSERT(last_opcode_mem_offset == offset);

                    for( std::size_t i = 0; i < last_opcode_memory.size(); i++){
                        BOOST_ASSERT(memory[offset+i] == last_opcode_memory[i]);
                    }

                    stack_rw_operations += 2; memory_rw_operations += 32;
                    pc++;
                }

                void mstore8() {
                    std::size_t offset = std::size_t(stack.back()); stack.pop_back();
                    auto value = stack.back(); stack.pop_back();

                    std::size_t memory_size_word = (memory.size() + 31) / 32;
                    std::size_t last_memory_cost = memory_size_word * memory_size_word / 512 + (3*memory_size_word);

                    if( memory.size() < offset + 1) memory.resize(offset + 1);
                        memory[offset] = std::uint8_t(std::size_t(value % 256));

                    memory_size_word = (memory.size() + 31) / 32;
                    std::size_t new_memory_cost = memory_size_word * memory_size_word / 512 + (3*memory_size_word);
                    std::size_t memory_expansion = new_memory_cost - last_memory_cost;
                    if( last_opcode_gas_cost != 3 + memory_expansion){
                        BOOST_LOG_TRIVIAL(trace) << "Gas error: " << last_opcode_gas_cost << " != " << 3 + memory_expansion ;
                    }
                    BOOST_ASSERT(last_opcode_gas_cost == 3 + memory_expansion);
                    gas -= 3 + memory_expansion;

                    BOOST_ASSERT(last_opcode_push.size() == 0);
                    BOOST_ASSERT(last_opcode_mem_offset == offset);

                    for( std::size_t i = 0; i < last_opcode_memory.size(); i++){
                        BOOST_ASSERT(memory[offset+i] == last_opcode_memory[i]);
                    }

                    stack_rw_operations += 2; memory_rw_operations += 1;
                    pc++;
                }

                void sload() {
                    auto addr = stack.back(); stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    BOOST_ASSERT(last_opcode_push.back() == _accounts_current_state[call_context_address].storage[addr]);
                    stack.push_back(last_opcode_push.back());
                    if( _call_stack.back().was_accessed.count({call_context_address, 0, addr}) == 0){
                        _call_stack.back().was_accessed.insert({call_context_address, 0, addr});
                        BOOST_LOG_TRIVIAL(trace) << "COLD {" << std::hex << call_context_address << ", " << addr << "}"  ;
                        gas -= 2000;
                    } else {
                        BOOST_LOG_TRIVIAL(trace) << "WARM {" << std::hex << call_context_address << ", " << addr << "}"  ;
                    }
                    gas -= 100;
                    // TODO: was_written and was_accessed processing
                    stack_rw_operations += 2; state_rw_operations += 2;
                    pc++;
                }
                void sstore() {
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
                        BOOST_LOG_TRIVIAL(trace) << "COLD {" << std::hex << call_context_address << ", " << addr << "}"  << std::dec ;
                    } else {
                        BOOST_LOG_TRIVIAL(trace) << "WARM " << (is_clean?"CLEAN":"DIRTY") << "  {" << std::hex << call_context_address << ", " << addr << "}"  << std::dec  ;
                    }

                    std::size_t cost = 100 + is_cold * 2100
                        + is_clean * (1 - is_equal) * was_zero * 19900
                        + is_clean * (1 - is_equal) * (1 - was_zero) * 2800;

                    _accounts_current_state[call_context_address].storage[addr] = value;
                    _call_stack.back().was_accessed.insert({call_context_address, 0, addr});
                    _call_stack.back().was_written.insert({call_context_address, 0, addr});

                    BOOST_ASSERT(last_opcode_push.size() == 0);
                    if( last_opcode_gas_cost != cost ){
                        BOOST_LOG_TRIVIAL(trace) << "Our cost = " << std::dec << cost << " != " << last_opcode_gas_cost ;
                        BOOST_LOG_TRIVIAL(trace) << "is_clean = " << is_clean ;
                        BOOST_LOG_TRIVIAL(trace) << "was_zero = " << was_zero ;
                        BOOST_LOG_TRIVIAL(trace) << "is_equal = " << is_equal ;
                    }
                    BOOST_LOG_TRIVIAL(trace) << "Our cost = " << std::dec << cost << " != " << last_opcode_gas_cost ;
                    BOOST_LOG_TRIVIAL(trace) << "is_clean = " << is_clean ;
                    BOOST_LOG_TRIVIAL(trace) << "was_zero = " << was_zero ;
                    BOOST_LOG_TRIVIAL(trace) << "is_equal = " << is_equal ;
                    BOOST_ASSERT(last_opcode_gas_cost == cost);

                    gas -= cost;
                    stack_rw_operations += 2;  state_rw_operations += 2;
                    pc++;
                }
                void jump() {
                    pc = std::size_t(stack.back()); stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 0);
                    stack_rw_operations += 1;
                    gas -= 8;
                }
                void jumpi() {
                    auto addr = stack.back(); stack.pop_back();
                    auto condition = stack.back(); stack.pop_back();
                    pc = condition == 0? pc+1: std::size_t(addr);
                    BOOST_ASSERT(last_opcode_push.size() == 0);
                    stack_rw_operations += 2;
                    gas -= 10;
                }
                void one_push_to_stack() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                    pc++;
                }
                void gas_opcode() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    gas -= 2;
                    BOOST_ASSERT(last_opcode_push.back() == gas);
                    stack.push_back(gas);
                    stack_rw_operations += 1;
                    pc++;
                }
                void pc_opcode() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    gas -= 2;
                    BOOST_ASSERT(last_opcode_push.back() == pc);
                    stack.push_back(pc);
                    stack_rw_operations += 1;
                    pc++;
                }
                void msize_opcode() {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    gas -= 2;
                    BOOST_ASSERT(last_opcode_push.back() == memory.size());
                    stack.push_back(memory.size());
                    stack_rw_operations += 1;
                    pc++;
                }
                void push_opcode( std::size_t x) {
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    zkevm_word_type additional_input;
                    for( std::size_t i = 0; i < x; i++ ){
                        additional_input = additional_input << 8;
                        additional_input += bytecode[pc + 1 + i];
                    }
                    BOOST_ASSERT(last_opcode_push.back() == additional_input);
                    stack.push_back(last_opcode_push.back());
                    stack_rw_operations += 1;
                    pc += 1 + x;
                    gas -= (x == 0? 2 : 3);
                }
                void dupx( std::size_t d) {
                    stack.push_back(stack[stack.size()-d]);
                    BOOST_ASSERT(last_opcode_push.size() == d+1);
                    bool is_equal = true;
                    for( std::size_t i = 0; i < d+1; i++ ){
                        is_equal = (last_opcode_push[i] == stack[stack.size()-d-1+i]);
                        if( !is_equal ) break;
                    }
                    if( !is_equal ){
                        BOOST_LOG_TRIVIAL(trace) << "Dup error: " ;
                        for( std::size_t i = 0; i < d+1; i++ ){
                            BOOST_LOG_TRIVIAL(trace) << "\t" << std::hex << last_opcode_push[i] << " " << stack[stack.size()-d-1+i] ;
                        }
                    }
                    BOOST_ASSERT(is_equal);
                    stack_rw_operations += 2;
                    pc++;
                    gas -= 3;
                }
                void swapx( std::size_t s) {
                    auto tmp = stack[stack.size() - s - 1];
                    stack[stack.size() - s - 1] = stack[stack.size()-1];
                    stack[stack.size()-1] = tmp;
                    BOOST_ASSERT(last_opcode_push.size() == s+1);
                    bool is_equal = true;
                    for( std::size_t i = 0; i < s+1; i++ ){
                        if( last_opcode_push[i] != stack[stack.size()-s-1+i] ){
                            is_equal = false;
                            break;
                        }
                    }
                    if( !is_equal ){
                        BOOST_LOG_TRIVIAL(trace) << "Swap error: " ;
                        for( std::size_t i = 0; i < s+1; i++ ){
                            BOOST_LOG_TRIVIAL(trace) << "\t" << std::hex << last_opcode_push[i] << " " << stack[stack.size()-s-1+i] ;
                        }
                    }
                    BOOST_ASSERT(is_equal);
                    stack_rw_operations += 4;
                    pc++;
                    gas -= 3;
                }
                void logx( std::size_t l) {
                    std::size_t offset = std::size_t(stack.back()); stack.pop_back();
                    std::size_t length = std::size_t(stack.back()); stack.pop_back();
                    for( std::size_t i = 0; i < l; i++ ) stack.pop_back();

                    std::size_t next_mem = std::max(length == 0? 0: offset + length, memory.size());
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());
                    if( memory.size() < next_mem ) memory.resize(next_mem, 0);

                    BOOST_ASSERT(last_opcode_push.size() == 0);
                    stack_rw_operations += 2 + l;
                    memory_rw_operations += length;
                    std::size_t gas_cost = 375 + 375 * l + 8 * length + memory_expansion;
                    gas -= gas_cost;
                    pc++;
                }
                void return_opcode(){
                    std::size_t offset = std::size_t(stack.back()); stack.pop_back();
                    std::size_t length = std::size_t(stack.back()); stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 0);

                    std::size_t next_mem = std::max(offset + length, memory.size());
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());

                    if( memory.size() < offset + length) memory.resize(offset + length);
                    for( std::size_t i = 0; i < last_opcode_memory.size(); i++){
                        BOOST_ASSERT(memory[offset+i] == last_opcode_memory[i]);
                    }
                    BOOST_ASSERT(last_opcode_gas_cost == memory_expansion);
                    gas -= memory_expansion;

                    returndata.clear();
                    BOOST_LOG_TRIVIAL(trace) << "Return data length = " << length << ": " << std::hex;
                    for( std::size_t i = 0; i < length; i++){
                        returndata.push_back(memory[offset+i]);
                    }
                    BOOST_LOG_TRIVIAL(trace) << byte_vector_to_sparse_hex_string(returndata) << std::dec ;

                    if( _call_stack.back().call_is_create || _call_stack.back().call_is_create2){
                        BOOST_LOG_TRIVIAL(trace) << "Create call" ;
                        call_status = call_context_address;
                        _existing_accounts.insert(call_context_address);
                        _accounts_current_state[call_context_address].bytecode = returndata;
                        _call_stack.back().was_accessed.insert({call_context_address, 1, 0});
                    } else {
                        call_status = 1;
                    }

                    if( _call_stack.size() > 2){
                        _call_stack[_call_stack.size()-2].was_accessed.insert(_call_stack.back().was_accessed.begin(), _call_stack.back().was_accessed.end());
                        _call_stack[_call_stack.size()-2].was_written.insert(_call_stack.back().was_written.begin(), _call_stack.back().was_written.end());
                        for( auto & [k,v]: _call_stack.back().transient_storage){
                            _call_stack[_call_stack.size()-2].transient_storage[k] = v;
                        }
                    }

                    stack_rw_operations += 2;
                }
                void delegatecall(){
                    call_is_create = false;
                    call_is_create2 = false;
                    call_gas = std::size_t(stack.back());  stack.pop_back();
                    call_addr = stack.back()& 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256;;  stack.pop_back();
                    call_value = 0;
                    call_args_offset = std::size_t(stack.back());  stack.pop_back();
                    call_args_length = std::size_t(stack.back());  stack.pop_back();
                    std::size_t ret_offset = std::size_t(stack.back());  stack.pop_back();
                    std::size_t ret_length = std::size_t(stack.back());  stack.pop_back();
                    _call_stack.back().lastcall_returndataoffset = ret_offset;
                    _call_stack.back().lastcall_returndatalength = ret_length;

                    //BOOST_LOG_TRIVIAL(trace) << "addr = 0x" << std::hex << addr << std::dec ;
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack_rw_operations += 7;

                    // TODO: check memory expansion
                    std::size_t next_mem = memory.size();
                    next_mem = std::max(next_mem, ret_length == 0? 0: ret_offset + ret_length);
                    next_mem = std::max(next_mem, call_args_length ==0? 0: call_args_offset + call_args_length);
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());
                    if( memory.size() < next_mem) memory.resize(next_mem, 0);
                    gas -= memory_expansion;
                }
                void revert(){
                    std::size_t offset = std::size_t(stack.back()); stack.pop_back();
                    std::size_t length = std::size_t(stack.back()); stack.pop_back();
                    BOOST_ASSERT(last_opcode_push.size() == 0);

                    std::size_t next_mem = std::max(offset + length, memory.size());
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());

                    if( memory.size() < offset + length) memory.resize(offset + length);
                    for( std::size_t i = 0; i < last_opcode_memory.size(); i++){
                        BOOST_ASSERT(memory[offset+i] == last_opcode_memory[i]);
                    }
                    BOOST_ASSERT(last_opcode_gas_cost == memory_expansion);
                    gas -= memory_expansion;

                    returndata.clear();
                    BOOST_LOG_TRIVIAL(trace) << "Return data length = " << length << ": " << std::hex;
                    for( std::size_t i = 0; i < length; i++){
                        returndata.push_back(memory[offset+i]);
                    }
                    BOOST_LOG_TRIVIAL(trace) << byte_vector_to_sparse_hex_string(returndata) << std::dec ;
                    BOOST_LOG_TRIVIAL(trace) << std::dec ;

                    call_status = 0;
                    stack_rw_operations += 2;
                }

                void error(){
                    returndata.clear();
                    call_status = 0;
                    // TODO: It's only gas error!
                    gas = 0;
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
//                 void update_modified_items_list(
//                     rw_operation_type   op,
//                     zkevm_word_type     address,
//                     std::size_t         field_tag,
//                     zkevm_word_type     storage_key,
//                     const rw_operation  &rw_op
//                 ){
// //                    BOOST_LOG_TRIVIAL(trace) << "Update cold access RW operations depth = " << _call_stack.size() ;
//                     for( std::size_t i = 0; i < _call_stack.size(); i++ ){
//                         if( !_call_stack[i].cold_access_list.count(std::make_tuple(op, address, field_tag, storage_key)) ){
//                             _call_stack[i].cold_access_list[std::make_tuple(op, address, field_tag, storage_key)] = rw_op;
//                         }
//                         if( !rw_op.is_write ) continue;
//                         if( !_call_stack[i].cold_write_list.count(std::make_tuple(op, address, field_tag, storage_key)) ){
//                             _call_stack[i].cold_write_list[std::make_tuple(op, address, field_tag, storage_key)] = rw_op;
//                         }
//                     }
//                 }

//                 void append_modified_items_rw_operations(){
//                     auto &call_context = _call_stack[_call_stack.size()-1];
// //                    BOOST_LOG_TRIVIAL(trace) << "Append cold access RW operations depth = " << _call_stack.size()
// //                        << " call_id = " << call_context.call_id ;;
//                     _rw_operations.push_back(
//                         call_context_rw_operation(
//                             call_context.call_id,
//                             call_context_field::modified_items,
//                             call_context.cold_write_list.size()
//                         )
//                     );
// //                    BOOST_LOG_TRIVIAL(trace) << _rw_operations.back() ;
//                     _call_commits[call_context.call_id] = {
//                         call_context.call_id,                           // call_id
//                         _call_stack[_call_stack.size() - 2].call_id,    // parent_id
//                         _call_stack.size() - 1,                         // depth
//                         call_context.end
//                     };
//                     for( auto &[k,v]: _call_stack.back().cold_write_list){
//                         _call_commits[call_context.call_id].items.push_back(v);
//                     }
//                 }
                void load_state_diff(const boost::property_tree::ptree &state_diff){
                    BOOST_LOG_TRIVIAL(trace) << "Load state diff" ;
                    for( auto &[account_address, account]: state_diff){
                        if( account.get_child("balance").get_child_optional("+")) {
                            BOOST_LOG_TRIVIAL(trace) << "\tAccount " << account_address.data() << " not exist" ;
                            _existing_accounts.erase(zkevm_word_from_string(account_address.data()));
                        }
                    }
                }

                void load_call_trace(const boost::property_tree::ptree &call_trace){
                    if( !call_trace.get_child_optional("to") ){
                        BOOST_LOG_TRIVIAL(trace) << "To child is not defined" ;
                    } else {
                        zkevm_word_type address = zkevm_word_from_string(call_trace.get_child("to").data());
                        if( address >= 1 && address <= 0xa ){
                            std::vector<std::uint8_t> input = byte_vector_from_hex_string(call_trace.get_child("input").data(),2);
                            std::vector<std::uint8_t> output;
                            if( call_trace.get_child_optional("output"))
                                output = byte_vector_from_hex_string(call_trace.get_child("output").data(),2);
                            precompiles_cache[{std::size_t(address), input}] = output;
                        }
                    }
                    if( call_trace.get_child_optional("calls")){
                        for( const auto &ct: call_trace.get_child("calls") ){
                            load_call_trace(ct.second);
                        }
                    }
                }

                void load_accounts(const boost::property_tree::ptree &prestate){
                    BOOST_LOG_TRIVIAL(trace) << "Load accounts" ;
                    _accounts_current_state.clear();
                    _existing_accounts.clear();
                    _accounts_initial_state.clear();

                    for( std::size_t i = 1; i < 11; i++){
                        _existing_accounts.insert(i);
                    }
                    for( auto &[account_address, account]: prestate){
                        zkevm_account acc;
                        acc.address = zkevm_word_from_string(account_address.data());
                        _existing_accounts.insert(acc.address);
                        if( account.get_child_optional("nonce") ){
                            acc.seq_no = acc.ext_seq_no = std::size_t(zkevm_word_from_string(account.get_child("nonce").data()));
                        } else {
                            acc.seq_no = acc.ext_seq_no = 0;
                        }
                        if( account.get_child_optional("balance") ){
                            acc.balance = zkevm_word_from_string(account.get_child("balance").data());
                        } else {
                            acc.balance = 0;
                        }
                        if( account.get_child_optional("storage") ){
                            acc.storage = key_value_storage_from_ptree(account.get_child("storage"));
                        }
                        if( account.get_child_optional("code") )
                            acc.bytecode = byte_vector_from_hex_string(account.get_child("code").data(), 2);
                        acc.code_hash = zkevm_keccak_hash(acc.bytecode);
                        _accounts_initial_state[acc.address] = acc;
                        _accounts_current_state[acc.address] = acc;
                        BOOST_LOG_TRIVIAL(trace)<< "\t" << account_address.data() << " balance = " << std::hex << acc.balance << std::dec;
                    }
                }

                void load_transaction(std::string _tx_hash, const boost::property_tree::ptree &tt){
                    tx.to = zkevm_word_from_string(tt.get_child("to").data());
                    tx.from = zkevm_word_from_string(tt.get_child("from").data());
                    tx.gasprice = zkevm_word_from_string(tt.get_child("gasPrice").data());

                    if( tt.get_child_optional("chainId")  )
                        tx.chain_id = std::size_t(zkevm_word_from_string(tt.get_child("chainId").data().c_str()));

                    tx.blob_versioned_hashes.clear();
                    if( tt.get_child_optional("blobVersionedHashes")){
                        BOOST_LOG_TRIVIAL(trace) << "Blob versioned hashes amount " << tt.get_child("blobVersionedHashes").size() ;
                        tx.blob_versioned_hashes = zkevm_word_vector_from_ptree(tt.get_child("blobVersionedHashes"));
                    }
                    tx.value = call_context_value = call_value = zkevm_word_from_string(tt.get_child("value").data());
                    tx.hash = zkevm_word_from_string(_tx_hash);
                    tx.gas = std::size_t(zkevm_word_from_string(tt.get_child("gas").data()));

                    tx.calldata.clear();
                    tx.calldata = byte_vector_from_hex_string(tt.get_child("input").data(), 2);

                    BOOST_LOG_TRIVIAL(trace) << "CALLDATA size = " << tx.calldata.size() << " : ";
                    BOOST_LOG_TRIVIAL(trace) << byte_vector_to_sparse_hex_string(tx.calldata);
                    tx.account_access_list.clear();
                    tx.storage_access_list.clear();
                    if( tt.get_child_optional("accessList") ){
                        BOOST_LOG_TRIVIAL(trace) << "Access list" ;
                        for( auto &access_list: tt.get_child("accessList")){
                            zkevm_word_type address = zkevm_word_from_string(access_list.second.get_child("address").data());
                            BOOST_LOG_TRIVIAL(trace) << std::hex << "\t" << address ;
                            tx.account_access_list.insert(address);
                            for( auto &storage: access_list.second.get_child("storageKeys")){
                                tx.storage_access_list.insert({address, zkevm_word_from_string(storage.second.data())});
                            }
                        }
                    }
                }

                void load_block(zkevm_word_type _block_hash, const boost::property_tree::ptree &pt){
                    block.hash = _block_hash;
                    block.timestamp = zkevm_word_from_string(pt.get_child("timestamp").data());
                    block.number = std::size_t(zkevm_word_from_string(pt.get_child("number").data()));
                    block.difficulty = zkevm_word_from_string(pt.get_child("mixHash").data()); //TODO: Find out why
                    block.parent_hash = zkevm_word_from_string(pt.get_child("parentHash").data());
                    block.basefee =  zkevm_word_from_string(pt.get_child("baseFeePerGas").data());
                    block.coinbase = zkevm_word_from_string(pt.get_child("miner").data());
                }

                boost::property_tree::ptree load_json_input(std::string path){
                    std::ifstream ss;
                    //BOOST_LOG_TRIVIAL(trace) << "Open file " << std::string(TEST_DATA_DIR) + path ;
                    ss.open(std::string(TEST_DATA_DIR) + path);
                    if( !ss.is_open() ){
                        BOOST_LOG_TRIVIAL(trace) << "Cannot open file " << std::string(TEST_DATA_DIR) + path ;
                        exit(1);
                    }
                    boost::property_tree::ptree pt;
                    boost::property_tree::read_json(ss, pt);
                    ss.close();

                    return pt;
                }
            public:
                virtual ~zkevm_alchemy_input_generator(){
                    BOOST_LOG_TRIVIAL(trace) << "zkevm_alchemy_input_generator destructor" ;
                }
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil

