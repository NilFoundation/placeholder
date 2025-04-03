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
#include <nil/blueprint/zkevm_bbf/types/zkevm_block.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_transaction.hpp>

#include <nil/blueprint/zkevm_bbf/types/zkevm_input_generator.hpp>
#include <nil/blueprint/zkevm_bbf/opcodes/zkevm_opcodes.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            class zkevm_basic_input_generator: public zkevm_abstract_input_generator{
                using extended_integral_type = nil::crypto3::multiprecision::big_uint<512>;
            protected:
                // Data structures for assignment
                zkevm_keccak_buffers                                     _keccaks;
                zkevm_keccak_buffers                                     _bytecodes;
                rw_operations_vector                                     _rw_operations;
                std::vector<copy_event>                                  _copy_events;
                std::vector<zkevm_state>                                 _zkevm_states;
                std::vector<std::pair<zkevm_word_type, zkevm_word_type>> _exponentiations;
                std::map<std::size_t,zkevm_call_commit>                   _call_commits;

                // Data preloaded data structures
                std::set<zkevm_word_type>                               _existing_accounts;
                std::map<zkevm_word_type, zkevm_account>                _accounts_initial_state; // Initial state; Update it after block.
                std::map<zkevm_word_type, zkevm_account>                _accounts_current_state; // Initial state; Update it after block.
                std::map<std::pair<std::size_t, std::vector<std::uint8_t>>, std::vector<std::uint8_t>> precompiles_cache;

                std::vector<zkevm_call_context>                          _call_stack;
                std::map<std::tuple<rw_operation_type, zkevm_word_type, std::size_t, zkevm_word_type>, std::size_t>  last_write_rw_counter;

                // Variables for current block
                std::size_t block_id;
                zkevm_block block;

                // Variables for current transaction
                std::size_t tx_id;
                zkevm_transaction tx;

                // Variables for current call
                std::size_t depth;
                std::size_t     call_id;                // RW counter on start_call
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

                // variables for current opcode
                zkevm_word_type additional_input;
                std::size_t     current_opcode;
                std::size_t     pc;
                std::size_t     stack_size;             // BEFORE opcode
                std::size_t     memory_size;            // BEFORE opcode
                std::size_t     rw_counter;
                std::size_t     gas;
                bool            is_start_call = false;
                bool            is_end_call = false;
                std::vector<zkevm_word_type> stack;
                std::vector<std::uint8_t> memory;
                std::vector<std::uint8_t> bytecode;
                std::set<zkevm_word_type> _bytecode_hashes;

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
                    result.block_hash = block.hash;
                    result.tx_hash = tx.hash;
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
                    // result.modified_items = _call_stack.back().cold_write_list.size();;
                    result.last_write_rw_counter = last_write_rw_counter;
                    result.was_accessed = _call_stack.back().was_accessed;
                    result.was_written = _call_stack.back().was_written;

                    return result;
                }

                virtual void start_block(){
                    block_id = rw_counter++;
                    last_write_rw_counter.clear();
                    block_id = tx_id = call_id = rw_counter++;
                    tx_id = 0;
                    depth = 1;
                    tx.hash = 0;

                    _call_stack.push_back(zkevm_call_context());
                    _call_stack.back().call_id = block_id;
                }

                virtual void start_transaction(){
                    depth++;
                    pc = 0;
                    tx_id = call_id = rw_counter++;
                    caller = tx.from;
                    gas = tx.gas;
                    gas -= 21000; // transaction cost
                    current_opcode = opcode_to_number(zkevm_opcode::start_transaction);
                    call_context_address = tx.to;
                    _accounts_current_state[tx.from].balance -= tx.value;
                    _accounts_current_state[tx.from].balance -= tx.gasprice * gas;
                    _accounts_current_state[tx.to].balance += tx.value;

                    calldata = tx.calldata;
                    for( auto &c: calldata){
                        gas -= (c==0 ? 4: 16); // calldata cost
                    }

                    // TODO: fix it
                    if( tx.to == 0 ) {
                        BOOST_LOG_TRIVIAL(trace) << "Deploying contract";
                        gas -= 32000; // Deployment cost
                        std::size_t calldata_words = (calldata.size() + 31) / 32;
                        gas -= calldata_words * 2;
                    }

                    _call_stack.push_back(zkevm_call_context());
                    _call_stack.back().call_id = call_id;
                    _call_stack.back().calldata = calldata;
                    _call_stack.back().bytecode = bytecode;
                    _call_stack.back().caller = caller;
                    _call_stack.back().call_context_address = call_context_address;
                    _call_stack.back().was_accessed.insert({call_context_address, 1, 0});
                    _call_stack.back().was_accessed.insert({tx.from, 1, 0});
                    _call_stack.back().call_value = call_value;
                    _call_stack.back().call_context_value = call_context_value;

                    rw_counter += call_context_readonly_field_amount;

                    // Precompiles are always warm
                    for( std::size_t i = 1; i < 11; i++){
                        _call_stack.back().was_accessed.insert({i, 1, 0});
                    }

                    for( auto address: tx.account_access_list){
                        _call_stack.back().was_accessed.insert({address, 1, 0});
                        gas -= 2400; // access_list cost
                    }

                    for( auto [address,key]: tx.storage_access_list){
                        _call_stack.back().was_accessed.insert({address, 0, key});
                        gas -= 1900; // access_list cost
                    }

                    if( tx.to != 0 ) {
                        bytecode = _accounts_current_state[tx.to].bytecode;
                        bytecode_hash = zkevm_keccak_hash(bytecode);
                        if( _bytecode_hashes.find(bytecode_hash) == _bytecode_hashes.end() ){
                            _bytecode_hashes.insert(bytecode_hash);
                            _keccaks.new_buffer(bytecode);
                            _bytecodes.new_buffer(bytecode);
                        }
                    } else {
                        bytecode = tx.calldata;
                        bytecode_hash = zkevm_keccak_hash(bytecode);
                        if( _bytecode_hashes.find(bytecode_hash) == _bytecode_hashes.end() ){
                            _bytecode_hashes.insert(bytecode_hash);
                            _keccaks.new_buffer(bytecode);
                            _bytecodes.new_buffer(bytecode);
                        }
                    }
                    _call_stack.back().bytecode = bytecode;
                    memory = {};
                    stack = {};
                    returndata = {};
                }

                virtual void end_transaction(){
                    auto returned_call = _call_stack.back();
                    _call_stack.pop_back();
                    depth--;

                    std::size_t returndataoffset = _call_stack.back().lastcall_returndataoffset; // caller CALL opcode parameters
                    std::size_t returndatalength = _call_stack.back().lastcall_returndatalength; // caller CALL opcode parameters
                    std::size_t subcall_id = call_id;

                    stack.clear();
                    memory.clear();
                    returndata.clear();
                    calldata.clear();
                }

                virtual void end_block(){
                    depth--;
                    stack.clear();
                    memory.clear();
                    _call_stack.pop_back();
                    _accounts_current_state.clear();
                    _existing_accounts.clear();
                    _call_stack.clear();
                    _accounts_initial_state.clear();
                }
            public:
                zkevm_basic_input_generator(){
                    rw_counter = 1;
                }
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil

