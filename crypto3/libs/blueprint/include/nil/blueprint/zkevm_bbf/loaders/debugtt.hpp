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

#include <nil/blueprint/zkevm_bbf/input_generators/basic_evm.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            class debugtt_block_loader : abstract_block_loader{
            protected:
                std::map<zkevm_word_type, zkevm_account>                    _accounts_initial_state;
                std::set<zkevm_word_type>                                   _existing_accounts;
                std::size_t current_block = 0;
                std::size_t blocks_amount = 0;

                zkevm_block block;

                boost::property_tree::ptree                                         tree;
                std::vector<std::pair<zkevm_word_type, boost::property_tree::ptree>>block_list;
                std::vector<boost::property_tree::ptree>                            tx_list;
                std::vector<boost::property_tree::ptree>                            opcode_trace;
            public:
                debugtt_block_loader(std::string path){
                    tree = load_debugtt_input(path);
                    for( auto &[k,v]: tree ){
                        BOOST_LOG_TRIVIAL(trace) << "Key: " << k << std::endl;
                        block_list.push_back({zkevm_word_from_string(k), v});
                    }
                    blocks_amount = block_list.size();
                    BOOST_LOG_TRIVIAL(trace) << "Debug Trace Transaction blocks loader:: blocks_amount = " << blocks_amount << std::endl;
                }

                virtual zkevm_block load_block() {
                    block.hash = block_list[current_block].first;
                    const auto &bt = block_list[current_block].second;

                    block.number = atoi(bt.get_child("block.number").data().c_str());
                    block.basefee = zkevm_word_from_string(bt.get_child("block.baseFeePerGas").data());
                    block.difficulty = atoi(bt.get_child("block.difficulty").data().c_str());
                    block.timestamp = atoi(bt.get_child("block.timestamp").data().c_str());
                    block.parent_hash = zkevm_word_from_string(bt.get_child("block.parentHash").data());

                    BOOST_LOG_TRIVIAL(trace) << "ZKEVM DEBUGTT INPUT GENERATOR loaded" << std::endl;
                    // 1. Load eth_accounts. Not good that we have only one initial state for all blocks
                    for( auto &account: bt.get_child("eth_accounts")){
                        BOOST_LOG_TRIVIAL(trace)  << "Account " << account.first.data() << std::endl;
                        zkevm_account acc;
                        acc.address = zkevm_word_from_string(account.second.get_child("address").data());
                        acc.balance = zkevm_word_from_string(account.second.get_child("balance").data());
                        acc.seq_no = acc.ext_seq_no = std::size_t(zkevm_word_from_string(account.second.get_child("nonce").data()));
                        _accounts_initial_state[acc.address] = acc;
                        _existing_accounts.insert(acc.address);
                    }
                    BOOST_LOG_TRIVIAL(trace) << "Eth accounts loaded" << std::endl;

                    // 2. Load accounts
                    for( auto &account: bt.get_child("accounts")){
                        zkevm_account acc;
                        acc.address = zkevm_word_from_string(account.second.get_child("address").data());
                        acc.balance = zkevm_word_from_string(account.second.get_child("balance").data());
                        acc.seq_no = acc.ext_seq_no = std::size_t(zkevm_word_from_string(account.second.get_child("nonce").data()));
                        acc.storage = key_value_storage_from_ptree(account.second.get_child("storage"));

                        // Bytecode string starts from 0x, so second parameter is 2
                        acc.bytecode = byte_vector_from_hex_string(account.second.get_child("bytecode").data(), 2);
                        acc.code_hash = zkevm_keccak_hash(acc.bytecode);
                        _accounts_initial_state[acc.address] = acc;
                        _existing_accounts.insert(acc.address);
                    }
                    BOOST_LOG_TRIVIAL(trace) << "Accounts loaded" << std::endl;
                    for( auto &[k,v]: _accounts_initial_state){
                        BOOST_LOG_TRIVIAL(trace) << "0x" << std::hex << k << " => " << v << std::dec<< std::endl;
                    }

                    tx_list.clear();
                    for( auto &[k,v]: bt.get_child("transactions") ){
                        tx_list.push_back(v);
                    }
                    block.tx_amount = tx_list.size();
                    current_block++;
                    return block;
                }

                virtual std::tuple<zkevm_transaction, std::map<zkevm_word_type, zkevm_account>, std::set<zkevm_word_type>> load_transaction(std::size_t i) {
                    BOOST_LOG_TRIVIAL(trace) << "Load transaction " << i << std::endl;
                    const auto &tt = tx_list[i].get_child("tx");
                    zkevm_transaction tx;
                    tx.to = zkevm_word_from_string(tt.get_child("to").data());
                    tx.from = zkevm_word_from_string(tt.get_child("from").data());
                    tx.gasprice = zkevm_word_from_string(tt.get_child("gasPrice.hex").data());
                    tx.max_fee_per_gas = tt.get_child_optional("maxFeePerGas") ? zkevm_word_from_string(tt.get_child("maxFeePerGas.hex").data()):
                    tx.max_fee_per_blob_gas = tt.get_child_optional("maxFeePerBlobGas") ? zkevm_word_from_string(tt.get_child("maxFeePerBlobGas.hex").data()): 0;
                    tx.max_priority_fee_per_gas = tt.get_child_optional("maxPriorityFeePerGas") ? zkevm_word_from_string(tt.get_child("maxPriorityFeePerGas.hex").data()): 0;
                    tx.gas = std::size_t(zkevm_word_from_string(tt.get_child("gasLimit.hex").data()));

                    BOOST_LOG_TRIVIAL(trace) << "Gas limit = " << tx.gas << std::dec;

                    if( tt.get_child_optional("chainId")  )
                        tx.chain_id = atoi(tt.get_child("chainId").data().c_str());

                    tx.blob_versioned_hashes.clear();
                    if( tt.get_child_optional("blobVersionedHashes")){
                        BOOST_LOG_TRIVIAL(trace) << "Blob versioned hashes amount " << tt.get_child("blobVersionedHashes").size() ;
                        tx.blob_versioned_hashes = zkevm_word_vector_from_ptree(tt.get_child("blobVersionedHashes"));
                    }
                    tx.value = zkevm_word_from_string(tt.get_child("value.hex").data());
                    tx.hash = zkevm_word_from_string(tt.get_child("hash").data());

                    tx.calldata.clear();
                    tx.calldata = byte_vector_from_hex_string(tt.get_child("data").data(), 2);

                    BOOST_LOG_TRIVIAL(trace) << "CALLDATA size = " << tx.calldata.size() << " : ";
                    BOOST_LOG_TRIVIAL(trace) << byte_vector_to_sparse_hex_string(tx.calldata);
                    tx.account_access_list.clear();
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

                    opcode_trace.clear();
                    for( auto &[k,v]: tx_list[i].get_child("trace.structLogs")){
                        opcode_trace.push_back(v);
                    }
                    if ( i!= 0 )
                        return {tx, {}, {}};
                    return {tx, _accounts_initial_state, _existing_accounts};
                }
                virtual bool are_there_more_blocks() {
                    return current_block < blocks_amount;
                }
                // TODO: implement precompiles and remove this function from interface
                virtual std::tuple<zkevm_word_type, std::size_t, std::vector<std::uint8_t>> compute_precompile(
                    zkevm_word_type address, std::vector<std::uint8_t> calldata
                ) {
                    BOOST_ASSERT(false);
                    return {1, 0, {}};
                }
                const std::vector<boost::property_tree::ptree> &get_opcode_trace() const {
                    return opcode_trace;
                }
            protected:
                boost::property_tree::ptree load_debugtt_input(std::string path){
                    auto test_data_dir = std::getenv("NIL_CO3_TEST_DATA_DIR")
                                             ? std::getenv("NIL_CO3_TEST_DATA_DIR")
                                             : std::string(TEST_DATA_DIR);
                    auto full_path = test_data_dir + path;
                    std::ifstream ss;
                    BOOST_LOG_TRIVIAL(trace) << "Open file " << full_path << std::endl;
                    ss.open(full_path);
                    boost::property_tree::ptree pt;
                    boost::property_tree::read_json(ss, pt);
                    ss.close();

                    return pt;
                }
            };

            class debugtt_trace_checker: public zkevm_basic_evm{
            protected:
                debugtt_block_loader *loader;
                std::vector<boost::property_tree::ptree> opcode_trace;
                std::size_t executed_opcode;

                std::size_t tx_order = 0;
                std::size_t call_id = 0;
            public:
                debugtt_trace_checker(debugtt_block_loader *_loader):loader(_loader),zkevm_basic_evm((abstract_block_loader*)_loader){
                    zkevm_basic_evm::execute_blocks();
                }

                virtual void start_block() override {
                    BOOST_LOG_TRIVIAL(trace) << "START BLOCK";
                    zkevm_basic_evm::start_block();
                    if( !execution_status ) return;
                }

                virtual void start_transaction() override{
                    BOOST_LOG_TRIVIAL(trace) << "START TRANSACTION";
                    executed_opcode = 0;
                    opcode_trace = loader->get_opcode_trace();
                    zkevm_basic_evm::start_transaction();
                    if( !execution_status ) return;
                }

                virtual void start_call() override{
                    BOOST_LOG_TRIVIAL(trace) << "START CALL";
                    zkevm_basic_evm::start_call();
                    executed_opcode++;
                }

                virtual void end_call() override{
                    BOOST_LOG_TRIVIAL(trace) << "END CALL";
                    zkevm_basic_evm::end_call();
                    executed_opcode--;
                }

                virtual void execute_opcode() override{
                    const auto &opcode_description = opcode_trace[executed_opcode];

                    std::string indent; for(std::size_t i = 1; i < depth; i++ ) indent += "\t";
                    BOOST_LOG_TRIVIAL(debug) << indent
                        << opcode_from_number(opcode_number_from_str(opcode_description.get_child("op").data()))
                        << " tx_order = " << tx_order
                        << " call_order = " << call_id
                        << " pc = " << pc
                        << " gas = " << gas
                        << " call_context_address = " << std::hex << call_context_address << std::dec;

                    if( !check_equal<std::size_t>(pc, atoi(opcode_description.get_child("pc").data().c_str()) , "Wrong pc ", false) ) return;
                    if( !check_equal<std::size_t>(depth-1, atoi(opcode_description.get_child("depth").data().c_str()) , "Wrong depth ", false) ) return;
                    if( !check_equal<std::size_t>(gas, atoi(opcode_description.get_child("gas").data().c_str()) , "Wrong gas ", false) ) return;

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

                    if( !check_equal<std::size_t>(stack.size(), opcode_description.get_child("stack").size(), "Wrong stack size") ) return;
                    std::size_t d = 0;
                    for( const auto &v: opcode_description.get_child("stack") ){
                        auto expected = zkevm_word_from_string(v.second.data());
                        if( !check_equal<zkevm_word_type>(stack[d], expected, "Wrong stack") ) {
                            std::size_t ind = 0;
                            for( const auto &v: opcode_description.get_child("stack") ){
                                auto expected = zkevm_word_from_string(v.second.data());
                                BOOST_LOG_TRIVIAL(error)
                                    << "Stack[" << ind << "] = "
                                    << std::hex << stack[ind]
                                    << " != " << expected
                                    << std::dec;
                                ind++;
                            }
                            return;
                        }
                        d++;
                    }

                    zkevm_basic_evm::execute_opcode();
                    if( !execution_status ) return;
                    executed_opcode++;
                }
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil

