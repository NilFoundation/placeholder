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
#include <nil/blueprint/zkevm_bbf/util.hpp>

// #include <nil/blueprint/zkevm_bbf/opcodes/zkevm_opcodes.hpp>
#include <nil/blueprint/zkevm_bbf/input_generators/basic_evm.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            class vmtrace_block_loader : abstract_block_loader{
            protected:
                zkevm_block                                                 block;

                std::string                                                 path;
                boost::property_tree::ptree                                 block_ptree;
                std::vector<boost::property_tree::ptree>                    tx_list;
                std::map<zkevm_word_type, zkevm_account>                    _accounts_initial_state;
                std::set<zkevm_word_type>                                   _existing_accounts;
                std::map<std::pair<std::size_t, std::vector<std::uint8_t>>, std::pair<std::size_t, std::vector<std::uint8_t>>> precompiles_cache;
                boost::property_tree::ptree                                 tx_trace_tree;
                std::size_t                                                 current_tx;
                std::map<std::size_t, zkevm_word_type>                      old_blocks_hashes;
                bool                                                        _are_there_more_blocks = true;
            public:
                const boost::property_tree::ptree &get_tx_list(std::size_t tx_order) const {
                    BOOST_ASSERT(tx_list.size() > tx_order);
                    return tx_list.at(tx_order);
                }
                const boost::property_tree::ptree &get_tx_trace_tree(std::size_t tx_order) {
                    if(tx_order != current_tx) load_transaction(tx_order);
                    return tx_trace_tree;
                }

                virtual zkevm_block load_block() override {
                    BOOST_LOG_TRIVIAL(info) << "VmTrace:: Load block " << std::hex << block.hash  << std::dec << " tx_amount = " << block.tx_amount;
                    _are_there_more_blocks = false;
                    return block;
                }

                virtual bool are_there_more_blocks() override{
                    return _are_there_more_blocks;
                }

                virtual std::tuple<
                    zkevm_transaction,
                    std::map<zkevm_word_type, zkevm_account>,
                    std::set<zkevm_word_type>
                > load_transaction(std::size_t tx_order) override{
                    current_tx = tx_order;
                    zkevm_transaction tx;

                    auto current_tx_ptree = tx_list[tx_order];
                    std::string tx_hash_string = current_tx_ptree.get_child("tx_hash").data();
                    BOOST_LOG_TRIVIAL(info) << tx_order << ".VmTrace:: load transaction " << tx_hash_string;
                    tx_trace_tree = load_json_input(path + std::string("tx_" + tx_hash_string + ".json"));

                    load_accounts(current_tx_ptree.get_child("execution_trace.prestate_trace"));
                    if( current_tx_ptree.get_child_optional("execution_trace.call_trace")) load_call_trace(current_tx_ptree.get_child("execution_trace.call_trace"));
                    if( tx_trace_tree.get_child_optional("stateDiff") ) load_state_diff(tx_trace_tree.get_child("stateDiff"));
                    tx = load_zkevm_transaction(tx_hash_string, current_tx_ptree.get_child("details"));
                    if( tx.to == 0 ) BOOST_LOG_TRIVIAL(trace) << "DEPLOY TRANSACTION" << std::endl;

                    return {tx, _accounts_initial_state, _existing_accounts};
                }

                virtual std::tuple<zkevm_word_type, std::size_t, std::vector<std::uint8_t>>
                    compute_precompile(zkevm_word_type address, std::vector<std::uint8_t> calldata
                ) override {
                    // Status, gas, returndata
                    auto [g, rdata] = precompiles_cache[{std::size_t(address), calldata}];
                    BOOST_LOG_TRIVIAL(trace) << "Precompile " << std::hex << address << std::dec
                        << " calldata = " << byte_vector_to_sparse_hex_string(calldata) << std::endl
                        << " gas = " << g << std::endl
                        << " returndata = " << byte_vector_to_sparse_hex_string(rdata);
                    return {1,g,rdata};
                }

                vmtrace_block_loader(std::string _path) : path(_path) {
                    block_ptree = load_json_input(path + std::string("block.json"));

                    block.hash = zkevm_word_from_string(block_ptree.get_child("block.hash").data());
                    block.timestamp = zkevm_word_from_string(block_ptree.get_child("block.timestamp").data());
                    block.number = std::size_t(zkevm_word_from_string(block_ptree.get_child("block.number").data()));
                    block.difficulty = zkevm_word_from_string(block_ptree.get_child("block.mixHash").data()); //TODO: Find out why
                    block.parent_hash = zkevm_word_from_string(block_ptree.get_child("block.parentHash").data());
                    block.basefee =  zkevm_word_from_string(block_ptree.get_child("block.baseFeePerGas").data());
                    block.coinbase = zkevm_word_from_string(block_ptree.get_child("block.miner").data());
                    block.tx_amount = block_ptree.get_child("block.transactions").size();
                    BOOST_LOG_TRIVIAL(trace) << "Transactions amount = " << block.tx_amount;


                    BOOST_LOG_TRIVIAL(trace) << "Old blocks hashes" ;
                    if(block_ptree.get_child_optional("old_blocks_hashes")){
                        std::cout << "Old block hashes are presented" << std::endl;
                        for( auto &tr: block_ptree.get_child("old_blocks_hashes")){
                            std::size_t n = std::size_t(zkevm_word_from_string(tr.second.get_child("number").data()));
                            zkevm_word_type h = zkevm_word_from_string(tr.second.get_child("hash").data());
                            BOOST_LOG_TRIVIAL(trace) << "\t" << n << " : " << std::hex << h << std::dec;
                            block.old_blocks_hashes[n] = h;
                        }
                    }

                    tx_list.clear();
                    for( auto &[k,v]: block_ptree.get_child("transactions") ){
                        tx_list.push_back(v);
                    }
                    BOOST_ASSERT(tx_list.size() == block.tx_amount);
                }
            protected:
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
                void load_accounts(const boost::property_tree::ptree &prestate){
                    BOOST_LOG_TRIVIAL(trace) << "Load accounts" ;
                    _existing_accounts.clear();
                    _accounts_initial_state.clear();

                    for( std::size_t i = 1; i < 11; i++){
                        _existing_accounts.insert(i);
                    }
                    for( auto &[account_address, account]: prestate){
                        zkevm_account acc;
                        acc.address = zkevm_word_from_string(account_address.data());
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
                        if( acc.seq_no != 0 || acc.bytecode.size() != 0)
                            _existing_accounts.insert(acc.address);
                        acc.code_hash = zkevm_keccak_hash(acc.bytecode);
                        _accounts_initial_state[acc.address] = acc;
                        BOOST_LOG_TRIVIAL(trace)
                            << "\t" << account_address.data()
                            << " balance = " << std::hex << acc.balance << std::dec
                            << " nonce = " << std::dec << acc.seq_no;
                    }
                }

                zkevm_transaction load_zkevm_transaction(std::string _tx_hash, const boost::property_tree::ptree &tt){
                    zkevm_transaction tx;
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
                    tx.value = zkevm_word_from_string(tt.get_child("value").data());
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

                    return tx;
                }

                void load_call_trace(const boost::property_tree::ptree &call_trace){
                    if( !call_trace.get_child_optional("to") ){
                        BOOST_LOG_TRIVIAL(trace) << "To child is not defined" ;
                    } else {
                        zkevm_word_type address = zkevm_word_from_string(call_trace.get_child("to").data());
                        if( address >= 1 && address <= 0xa ){
                            std::vector<std::uint8_t> input = byte_vector_from_hex_string(call_trace.get_child("input").data(),2);
                            std::vector<std::uint8_t> output;
                            std::size_t precompile_gas = 0;
                            if( call_trace.get_child_optional("output"))
                                output = byte_vector_from_hex_string(call_trace.get_child("output").data(),2);
                            if( call_trace.get_child_optional("gasUsed"))
                                precompile_gas = std::size_t(zkevm_word_from_string(call_trace.get_child("gasUsed").data()));
                            precompiles_cache[{std::size_t(address), input}] = {precompile_gas, output};
                            BOOST_LOG_TRIVIAL(trace) << "load precompile " << std::hex << address << std::dec
                                << " gas = " << precompile_gas << std::endl
                                << " calldata = " << byte_vector_to_sparse_hex_string(input) << std::endl
                                << " returndata = " << byte_vector_to_sparse_hex_string(output);
                        }
                    }
                    if( call_trace.get_child_optional("calls")){
                        for( const auto &ct: call_trace.get_child("calls") ){
                            load_call_trace(ct.second);
                        }
                    }
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
            };

            class zkevm_vmtrace_trace_checker:public zkevm_basic_evm{
                using extended_integral_type = nil::crypto3::multiprecision::big_uint<512>;
            protected:
                std::size_t tx_order = 0;
                std::size_t call_id = 0;
                vmtrace_block_loader                           *loader;
                boost::property_tree::ptree                     current_tx_ptree;
                boost::property_tree::ptree                     tx_trace_tree;
                std::vector<boost::property_tree::ptree>        opcode_trace;
                std::vector<std::pair<std::vector<boost::property_tree::ptree>, std::size_t>> trace_stack;

                std::vector<zkevm_word_type> last_opcode_push;
                std::vector<std::uint8_t> last_opcode_memory;
                std::size_t last_opcode_mem_offset;
                std::size_t last_opcode_gas_cost;
                std::size_t last_opcode_gas_used;
            public:
                zkevm_vmtrace_trace_checker(vmtrace_block_loader *_loader):loader(_loader),zkevm_basic_evm((abstract_block_loader*)_loader){
                    zkevm_basic_evm::execute_blocks();
                }

                void start_block() override {
                    zkevm_basic_evm::start_block();
                    BOOST_LOG_TRIVIAL(trace) << "START BLOCK";
                    if( !execution_status ) return;
                }

                void start_transaction() override{
                    BOOST_LOG_TRIVIAL(trace) << "START TRANSACTION " << tx_order;
                    zkevm_basic_evm::start_transaction();
                    if( !execution_status ) return;
                    current_tx_ptree = loader->get_tx_list(tx_order);
                    tx_trace_tree = loader->get_tx_trace_tree(tx_order);

                    std::vector<boost::property_tree::ptree> opcode_trace;
                    if( tx_trace_tree.get_child_optional("vmTrace.ops") ) {
                        for( auto &[k,v]: tx_trace_tree.get_child("vmTrace.ops")){
                            opcode_trace.push_back(v);
                        }
                    }
                    trace_stack.push_back({opcode_trace,0});
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

                    zkevm_basic_evm::start_call();
                    if(!execution_status) return;
                }

                virtual void blockhash() override{
                    BOOST_LOG_TRIVIAL(trace) << "Blockhash correct value " << std::hex << last_opcode_push.back() << std::dec;
                    zkevm_basic_evm::blockhash();
                }


                void execute_opcode() override {
                    if( trace_stack.back().second >= trace_stack.back().first.size() ) {
                        is_end_call = true;
                        return;
                    }

                    std::size_t index = 0;
                    const boost::property_tree::ptree &opcode_description = trace_stack.back().first[trace_stack.back().second];

                    std::string indent; for(std::size_t i = 1; i < depth; i++ ) indent += "\t";
                    BOOST_LOG_TRIVIAL(debug) << indent
                        << opcode_from_number(opcode_number_from_str(opcode_description.get_child("op").data()))
                        << " tx_order = " << tx_order
                        << " call_order = " << call_id
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
                        )) {
                            BOOST_LOG_TRIVIAL(trace) << "Bytecode = " << std::hex << byte_vector_to_sparse_hex_string(bytecode) << std::dec;
                            return;
                        }

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

                    zkevm_basic_evm::execute_opcode();

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

                virtual void end_call() override {
                    BOOST_LOG_TRIVIAL(trace) << "END CALL " << call_id;
                    trace_stack.back().first.clear();
                    trace_stack.pop_back();
                    zkevm_basic_evm::end_call();
                    if(!execution_status) return;
                    call_id++;
                }

                void end_transaction() override {
                    BOOST_LOG_TRIVIAL(trace) << "END transaction" << std::endl << std::endl;
                    zkevm_basic_evm::end_transaction();
                    if( !execution_status ) return;
                    trace_stack.pop_back();
                    tx_order++;
                    call_id++;
                }

                void end_block() override{
                    trace_stack.clear();
                    zkevm_basic_evm::end_block();
                    if( !execution_status ) return;
                    BOOST_LOG_TRIVIAL(trace) << "END BLOCK";
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
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil

