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
#include <nil/blueprint/zkevm_bbf/types/short_rw_operation.hpp>
#include <nil/blueprint/zkevm_bbf/types/copy_event.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_state.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_account.hpp>
#include <nil/blueprint/zkevm_bbf/types/call_context.hpp>
#include <nil/blueprint/zkevm_bbf/types/block_loader.hpp>

#include <nil/blueprint/zkevm_bbf/util/ptree.hpp>

// #include <nil/blueprint/zkevm_bbf/opcodes/zkevm_opcodes.hpp>
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

                boost::property_tree::ptree                                             block_ptree;
                std::size_t                                                             tx_order = 0;
                std::vector<boost::property_tree::ptree>                                tx_list;
                boost::property_tree::ptree                                             current_tx_ptree;
                boost::property_tree::ptree                                             tx_trace_tree;
                std::vector<std::pair<std::vector<boost::property_tree::ptree>, std::size_t>> trace_stack;
                std::map<std::pair<std::size_t, std::vector<std::uint8_t>>, std::vector<std::uint8_t>> precompiles_cache;

                // Statistics
                std::size_t opcode_sum = 0;
                std::size_t executed_opcodes = 0;
                std::size_t stack_short_rw_operations = 0;
                std::size_t memory_short_rw_operations = 0;
                std::size_t calldata_short_rw_operations = 0;
                std::size_t returndata_short_rw_operations = 0;
                std::size_t state_short_rw_operations = 0;
                std::size_t call_context_short_rw_operations = 0;
                std::map<zkevm_opcode, std::size_t> opcode_distribution;

                std::string path;
            public:
                zkevm_alchemy_input_generator(
                    std::string _path
                ) : zkevm_basic_input_generator(), path(_path) {
                    error_message = "";

                    opcode_sum = 0;
                    executed_opcodes = 0;
                    stack_short_rw_operations = 0;
                    memory_short_rw_operations = 0;
                    calldata_short_rw_operations = 0;
                    returndata_short_rw_operations = 0;
                    state_short_rw_operations = 0;
                    call_context_short_rw_operations = 0;

                    block_ptree = load_json_input(path + std::string("block.json"));
                    BOOST_LOG_TRIVIAL(trace) << "ZKEVM ALCHEMY INPUT GENERATOR loaded";

                    zkevm_basic_input_generator::execute_block();
                    BOOST_LOG_TRIVIAL(trace) << "ZKEVM ALCHEMY INPUT GENERATOR executed block";
                }

                virtual void blockhash(){
                    // TODO! Load more block hashes and remove this hook!
                    std::size_t n = std::size_t(stack.back());
                    if(n == (block.number - 1)) {
                        zkevm_basic_input_generator::blockhash();
                    } else {
                        BOOST_LOG_TRIVIAL(trace) << "Blockhash " << n << " is not implemented" ;
                        stack.pop_back();
                        stack.push_back(last_opcode_push.back());
                        pc++;
                        decrease_gas(20);
                    }
                }

                virtual void dummyprecompile() override{
                    // TODO: implement all precompiles. This function should never be called
                    BOOST_LOG_TRIVIAL(trace) << "Dummy Precompile" << std::endl;
                    zkevm_word_type precomp_gas = stack.back(); stack.pop_back(); // gas sometimes is -1. It's strange but it's not used after
                    zkevm_word_type precomp_addr = stack.back(); stack.pop_back(); // addr
                    std::size_t precomp_args_offset = std::size_t(stack.back()); stack.pop_back(); // args_offset
                    std::size_t precomp_args_length = std::size_t(stack.back()); stack.pop_back(); // args_length
                    std::size_t precomp_ret_offset = std::size_t(stack.back()); stack.pop_back(); // ret_offset
                    std::size_t precomp_ret_length = std::size_t(stack.back()); stack.pop_back(); // ret_length
                    std::size_t data_word_size = (precomp_args_length + 31) / 32;

                    BOOST_LOG_TRIVIAL(trace) << "precomp_gas = 0x" << precomp_gas << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "precomp_addr = 0x" << std::hex << precomp_addr << std::dec << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "precomp_args_offset = " << precomp_args_offset << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "precomp_args_length = " << precomp_args_length << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "precomp_ret_offset = " << precomp_ret_offset << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "precomp_ret_length = " << precomp_ret_length << std::endl;

                    // TODO: memory expansion gas cost
                    std::size_t next_mem = memory.size();
                    next_mem = std::max(next_mem, precomp_args_length == 0? 0: precomp_args_offset + precomp_args_length);
                    next_mem = std::max(next_mem, precomp_ret_length == 0? 0: precomp_ret_offset + precomp_ret_length);
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());
                    if( next_mem > memory.size()){
                        BOOST_LOG_TRIVIAL(trace) << "Memory expansion " << memory.size() << "=>" << next_mem << std::endl;
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
                    pc++;
                    _call_stack.back().lastcall_returndataoffset = precomp_ret_offset;
                    _call_stack.back().lastcall_returndatalength = precomp_ret_length;
                }

                virtual void dummycallprecompile() override{
                    BOOST_LOG_TRIVIAL(trace) << "Dummy call Precompile" << std::endl;
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

                    BOOST_LOG_TRIVIAL(trace) << "precomp_gas = " << precomp_gas << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "precomp_addr = 0x" << std::hex << precomp_addr << std::dec << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "precomp_args_offset = " << precomp_args_offset << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "precomp_args_length = " << precomp_args_length << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "precomp_ret_offset = " << precomp_ret_offset << std::endl;
                    BOOST_LOG_TRIVIAL(trace) << "precomp_ret_length = " << precomp_ret_length << std::endl;

                    // TODO: memory expansion gas cost
                    std::size_t next_mem = memory.size();
                    next_mem = std::max(next_mem, precomp_args_length == 0? 0: precomp_args_offset + precomp_args_length);
                    next_mem = std::max(next_mem, precomp_ret_length == 0? 0: precomp_ret_offset + precomp_ret_length);
                    std::size_t memory_expansion = memory_expansion_cost(next_mem, memory.size());
                    // gas -= memory_expansion;
                    // gas -= 100;
                    if( next_mem > memory.size()){
                        BOOST_LOG_TRIVIAL(trace) << "Memory expansion " << memory.size() << "=>" << next_mem << std::endl;
                        memory.resize(next_mem, 0);
                    }
                    gas = last_opcode_gas_used;

                    BOOST_LOG_TRIVIAL(trace) << "Input data:" << std::hex;
                    std::vector<std::uint8_t> precomp_input;
                    for( std::size_t i = 0; i < precomp_args_length; i++){
                        precomp_input.push_back(memory[precomp_args_offset+i]);
                        BOOST_LOG_TRIVIAL(trace) << std::size_t(precomp_input[i]) << " ";
                    }
                    BOOST_LOG_TRIVIAL(trace) << std::dec << std::endl;

                    BOOST_LOG_TRIVIAL(trace) << "Output data:" << std::hex;
                    returndata = precompiles_cache[{std::size_t(precomp_addr), precomp_input}];
                    for( std::size_t i = 0; i < returndata.size(); i++){
                        memory[precomp_ret_offset + i] = returndata[i];
                        BOOST_LOG_TRIVIAL(trace) << std::size_t(returndata[i]) << " ";
                    }
                    BOOST_LOG_TRIVIAL(trace) << std::dec << std::endl;

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
                        for( std::size_t i = 0; i < last_opcode_memory.size(); i++){
                            auto c = last_opcode_mem_offset+i < memory.size()? memory[last_opcode_mem_offset + i]: 0;
                            BOOST_LOG_TRIVIAL(trace) << std::size_t(c) << " ";
                        }
                        BOOST_LOG_TRIVIAL(trace) << std::dec << std::endl;
                        BOOST_LOG_TRIVIAL(trace) << "Trace memo piece:" << std::hex;
                        for( std::size_t i = 0; i < last_opcode_memory.size(); i++){
                            BOOST_LOG_TRIVIAL(trace) << std::size_t(last_opcode_memory[i]) << " ";
                        }
                        BOOST_LOG_TRIVIAL(trace) << std::dec << std::endl;
                    }
                    BOOST_ASSERT(is_equal);
                    BOOST_ASSERT(last_opcode_push.size() == 1);
                    stack.push_back(last_opcode_push.back());
                    pc++;
                    _call_stack.back().lastcall_returndataoffset = precomp_ret_offset;
                    _call_stack.back().lastcall_returndatalength = precomp_ret_length;
                }

                void start_block() override {
                    load_block(block_ptree);
                    tx_order = 0;
                    zkevm_basic_input_generator::start_block();
                    BOOST_LOG_TRIVIAL(trace) << "START BLOCK " << block_id ;
                    if( !execution_status ) return;
                    opcode_sum ++;
                    if (opcode_distribution.count(zkevm_opcode::start_block))
                        opcode_distribution[zkevm_opcode::start_block]++;
                    else
                        opcode_distribution[zkevm_opcode::start_block] = 1;
                    call_context_short_rw_operations += block_context_fields_amount - 1;

                    tx_list.clear();
                    for( auto &[k,v]: block_ptree.get_child("transactions") ){
                        tx_list.push_back(v);
                    }
                    BOOST_ASSERT(tx_list.size() == block.tx_amount);
                }

                void end_block() override{
                    trace_stack.clear();
                    zkevm_basic_input_generator::end_block();
                    if( !execution_status ) return;
                    BOOST_LOG_TRIVIAL(trace) << "END BLOCK " << block_id;
                }

                void start_transaction() override{
                    current_tx_ptree = tx_list[tx_order];
                    std::string tx_hash_string = current_tx_ptree.get_child("tx_hash").data();
                    BOOST_LOG_TRIVIAL(trace) << tx_order << "." << tx_hash_string << " " ;
                    tx_trace_tree = load_json_input(path + std::string("tx_" + tx_hash_string + ".json"));

                    load_accounts(current_tx_ptree.get_child("execution_trace.prestate_trace"));
                    if( current_tx_ptree.get_child_optional("execution_trace.call_trace")) load_call_trace(current_tx_ptree.get_child("execution_trace.call_trace"));
                    if( tx_trace_tree.get_child_optional("stateDiff") ) load_state_diff(tx_trace_tree.get_child("stateDiff"));
                    load_transaction(tx_hash_string, current_tx_ptree.get_child("details"));

                    std::vector<boost::property_tree::ptree> opcode_trace;
                    if( tx_trace_tree.get_child_optional("vmTrace.ops") ) {
                        for( auto &[k,v]: tx_trace_tree.get_child("vmTrace.ops")){
                            opcode_trace.push_back(v);
                        }
                    }
                    trace_stack.push_back({opcode_trace,0});
                    if( tx.to == 0 ) BOOST_LOG_TRIVIAL(trace) << "DEPLOY TRANSACTION" << std::endl;

                    BOOST_LOG_TRIVIAL(trace) << "START TRANSACTION " << tx_id << std::endl
                        << "\tfrom " << std::hex << tx.from << std::endl
                        << "\tto " << std::hex << tx.to << std::endl
                        << "\tvalue  = " << std::hex << tx.value << std::endl
                        << "\thash = " << tx.hash << std::dec << std::endl
                        << "\tgas = " << std::dec << tx.gas
                        ;

                    zkevm_basic_input_generator::start_transaction();
                    if( !execution_status ) return;

                    // statistics
                    opcode_sum ++;
                    if (opcode_distribution.count(zkevm_opcode::start_transaction))
                        opcode_distribution[zkevm_opcode::start_transaction]++;
                    else
                        opcode_distribution[zkevm_opcode::start_transaction] = 1;
                    calldata_short_rw_operations += calldata.size();
                    call_context_short_rw_operations += call_context_readonly_field_amount;
                }

                void end_transaction() override{
                    BOOST_LOG_TRIVIAL(trace) << "END TRANSACTION " << tx_id << std::endl << std::endl;
                    zkevm_basic_input_generator::end_transaction();
                    if( !execution_status ) {
                        BOOST_LOG_TRIVIAL(trace) << "TRANSACTION END not successful";
                        return;
                    }

                    if (opcode_distribution.count(zkevm_opcode::end_transaction))
                        opcode_distribution[zkevm_opcode::end_transaction]++;
                    else
                        opcode_distribution[zkevm_opcode::end_transaction] = 1;

                    opcode_sum++;
                    tx_order++;
                }

                void execute_transaction() override {
                    BOOST_LOG_TRIVIAL(trace) << "Execute transaction";
                    zkevm_basic_input_generator::execute_transaction();
                    if( !execution_status ) return;
                }

                void execute_opcode() override {
                    if( trace_stack.back().second >= trace_stack.back().first.size() ) {
                        is_end_call = true;
                        return;
                    }

                    std::size_t index = 0;
                    const boost::property_tree::ptree &opcode_description = trace_stack.back().first[trace_stack.back().second];

                    std::string indent; for(std::size_t i = 1; i < depth; i++ ) indent += "\t";
                    BOOST_LOG_TRIVIAL(trace) << indent
                        << opcode_from_number(opcode_number_from_str(opcode_description.get_child("op").data()))
                        << " tx_id = " << tx_id
                        << " call_id = " << call_id
                        << " pc = " << pc
                        << " gas = " << gas
                        << " call_context_address = " << std::hex << call_context_address << std::dec;

                    if( !check_equal<std::size_t>(pc, atoi(opcode_description.get_child("pc").data().c_str()) , "Wrong pc ") ) return;
                    if( !check(
                        pc == bytecode.size() ||
                        (pc < bytecode.size()),
                        "Wrong pc= " + std::to_string(pc) + " bytecode.size = " + std::to_string(bytecode.size())
                    )) return;
                    if ( pc == bytecode.size() )
                        if( !check(opcode_description.get_child("op").data() == "STOP", "Not enough STOP opcode in the trace") )
                            return;
                    if( pc < bytecode.size() )
                        if( !check(
                            bytecode[pc] == opcode_number_from_str(opcode_description.get_child("op").data()),
                            "Wrong opcode= " + std::to_string(opcode_from_number(bytecode[pc])) + " trace opcode = " + opcode_description.get_child("op").data()
                        )) return;

                    bool should_be_error = false;
                    last_opcode_push.clear();
                    last_opcode_memory.clear();
                    last_opcode_gas_cost = 0;
                    if( opcode_description.get_child("ex").data() == "null" ) {
                        should_be_error = true;
                    } else {
                        if( opcode_description.get_child_optional("ex.push") )
                            last_opcode_push = zkevm_word_vector_from_ptree(opcode_description.get_child("ex.push"));
                        if( opcode_description.get_child_optional("ex.mem.data") ){
                            last_opcode_memory = byte_vector_from_hex_string(opcode_description.get_child("ex.mem.data").data(), 2);
                        }
                        if( opcode_description.get_child_optional("ex.mem.off") )
                            last_opcode_mem_offset = opcode_description.get_child_optional("ex.mem.off")? atoi(opcode_description.get_child("ex.mem.off").data().c_str()) : 0;

                        last_opcode_gas_cost = atoi(opcode_description.get_child("cost").data().c_str());
                        last_opcode_gas_used = atoi(opcode_description.get_child("ex.used").data().c_str());
                    }

                    zkevm_basic_input_generator::execute_opcode();

                    if( !execution_status ) return;
                    if( opcode_description.get_child("ex").data() != "null" ) {
                        if( !check_equal<std::size_t>(gas, atoi(opcode_description.get_child("ex.used").data().c_str()) , "Wrong gas ") ) return;
                    }
                    if( !check(last_opcode_push.size() <= stack.size(), "Too small stack size") ) return;
                    if( !check(last_opcode_memory.size() <= memory.size(), "Too small memory size") ) return;
                    if( !check_memory() ) return;
                    if( !check_stack() ) return;

                    if( !execution_status ) return;
                    trace_stack.back().second++;
                }

                virtual void start_call() override {
                    BOOST_LOG_TRIVIAL(trace) << "START CALL " << call_id;
                    boost::property_tree::ptree opcode_description = trace_stack.back().first[trace_stack.back().second];

                    std::vector<boost::property_tree::ptree> opcode_trace;
                    if( opcode_description.get_child_optional("sub.ops") ) {
                        for( auto &v: opcode_description.get_child("sub.ops")){
                            opcode_trace.push_back(v.second);
                        }
                    }
                    BOOST_LOG_TRIVIAL(trace) << "Trace size " << opcode_trace.size();
                    trace_stack.push_back({opcode_trace,0});

                    zkevm_basic_input_generator::start_call();
                }

                virtual void end_call() override {
                    BOOST_LOG_TRIVIAL(trace) << "END CALL " << call_id;
                    trace_stack.back().first.clear();
                    trace_stack.pop_back();
                    zkevm_basic_input_generator::end_call();
                }

            protected:
                bool check_memory(){
                    bool is_equal = true;
                    for( std::size_t i = 0; i < last_opcode_memory.size(); i++ ){
                        if(last_opcode_memory[i] != memory[last_opcode_mem_offset + i]) {
                            is_equal = false;
                            break;
                        }
                    }
                    if( is_equal ) return true;
                    execution_status = false;
                    error_message = "Wrong memory";
                    BOOST_LOG_TRIVIAL(error) << error_message;
                    BOOST_LOG_TRIVIAL(trace) << "Our piece size " << last_opcode_memory.size() << " :" << byte_vector_to_sparse_hex_string(memory, last_opcode_mem_offset, last_opcode_memory.size());
                    BOOST_LOG_TRIVIAL(trace) << "Trace size     " << last_opcode_memory.size() << " :" << byte_vector_to_sparse_hex_string(last_opcode_memory);
                    return is_equal;
                }
                bool check_stack(){
                    bool is_equal = true;
                    for(std::size_t i = 0; i < last_opcode_push.size(); i++ ){
                        if( last_opcode_push[i] != stack[stack.size() - last_opcode_push.size() + i] ){
                            is_equal = false;
                            break;
                        }
                    }
                    if( is_equal ) return true;
                    execution_status = false;
                    error_message = "Wrong stack";
                    BOOST_LOG_TRIVIAL(error) << error_message;
                    for(std::size_t i = 0; i < last_opcode_push.size(); i++ ){
                        BOOST_LOG_TRIVIAL(trace) << "\t" << std::hex
                            << stack[stack.size() - last_opcode_push.size() + i] << " "
                            << last_opcode_push[i] << std::dec;
                    }
                    return is_equal;
                }
                void load_state_diff(const boost::property_tree::ptree &state_diff){
                    BOOST_LOG_TRIVIAL(trace) << "Load state diff" ;
                    for( const auto &[account_address, account]: state_diff){
                        _existing_accounts.insert(zkevm_word_from_string(account_address.data()));
                        if( account.get_child_optional("balance") && account.get_child("balance").get_child_optional("+")) {
                            BOOST_LOG_TRIVIAL(trace) << "\tAccount " << account_address.data() << " not exist" ;
                            _existing_accounts.erase(zkevm_word_from_string(account_address.data()));
                        }
                        if( account.get_child_optional("balance") && account.get_child("balance").get_child_optional("*")) {
                            _existing_accounts.insert(zkevm_word_from_string(account_address.data()));
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

                void load_transaction(std::string _tx_hash, const boost::property_tree::ptree &tt){
                    tx.to = zkevm_word_from_string(tt.get_child("to").data());
                    tx.from = zkevm_word_from_string(tt.get_child("from").data());
                    tx.gasprice = zkevm_word_from_string(tt.get_child("gasPrice").data());
                    tx.max_fee_per_gas = tt.get_child_optional("maxFeePerGas") ? zkevm_word_from_string(tt.get_child("maxFeePerGas").data()): tx.gasprice;
                    tx.max_fee_per_blob_gas = tt.get_child_optional("maxFeePerBlobGas") ? zkevm_word_from_string(tt.get_child("maxFeePerBlobGas").data()): 0;
                    tx.max_priority_fee_per_gas = tt.get_child_optional("maxPriorityFeePerGas") ? zkevm_word_from_string(tt.get_child("maxPriorityFeePerGas").data()): 0;

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

                void load_block(const boost::property_tree::ptree &pt){
                    block.hash = zkevm_word_from_string(pt.get_child("block.hash").data());
                    block.timestamp = zkevm_word_from_string(pt.get_child("block.timestamp").data());
                    block.number = std::size_t(zkevm_word_from_string(pt.get_child("block.number").data()));
                    block.difficulty = zkevm_word_from_string(pt.get_child("block.mixHash").data()); //TODO: Find out why
                    block.parent_hash = zkevm_word_from_string(pt.get_child("block.parentHash").data());
                    block.basefee =  zkevm_word_from_string(pt.get_child("block.baseFeePerGas").data());
                    block.coinbase = zkevm_word_from_string(pt.get_child("block.miner").data());
                    block.tx_amount = pt.get_child("block.transactions").size();
                    BOOST_LOG_TRIVIAL(trace) << "Transactions amount = " << block.tx_amount;
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
                    BOOST_LOG_TRIVIAL(trace) << "Destructor of zkevm_alchemy_input_generator";
                }
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil

