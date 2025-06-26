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
#include <nil/blueprint/zkevm_bbf/types/state_operation.hpp>
#include <nil/blueprint/zkevm_bbf/types/short_rw_operation.hpp>
#include <nil/blueprint/zkevm_bbf/types/copy_event.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_state.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_account.hpp>
#include <nil/blueprint/zkevm_bbf/types/call_context.hpp>
#include <nil/blueprint/zkevm_bbf/types/call_state_data.hpp>
#include <nil/blueprint/zkevm_bbf/types/timeline_item.hpp>

#include <nil/blueprint/zkevm_bbf/types/zkevm_block.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_transaction.hpp>

#include <nil/blueprint/zkevm_bbf/input_generators/basic_evm.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            class zkevm_basic_input_generator: public zkevm_basic_evm{
                using extended_integral_type = nil::crypto3::multiprecision::big_uint<512>;
            protected:
                std::size_t block_id;
                std::size_t tx_id;
                std::size_t call_id;
                std::size_t rw_counter;

                // Data structures for assignment
                zkevm_keccak_buffers                                     _keccaks;
                zkevm_keccak_buffers                                     _bytecodes;
                short_rw_operations_vector                               _short_rw_operations;
                state_operations_vector                                  _state_operations;
                std::vector<copy_event>                                  _copy_events;
                std::vector<zkevm_state>                                 _zkevm_states;
                std::vector<std::pair<zkevm_word_type, zkevm_word_type>> _exponentiations;
                std::map<zkevm_word_type, zkevm_account>                 _accounts;
                std::map<std::size_t, zkevm_call_state_data>            _call_state_data;
                std::vector<timeline_item>                              _timeline;

                std::set<zkevm_word_type>                                 _bytecode_hashes;
                std::vector<std::map<std::tuple<rw_operation_type, zkevm_word_type, std::size_t, zkevm_word_type>, std::size_t>> last_state_counter_stack;

                const zkevm_word_type two_25 = zkevm_word_type(1) << 25; // Bound for rw_8 operations address
            public:
                virtual zkevm_keccak_buffers keccaks() const {return _keccaks;}
                virtual zkevm_keccak_buffers bytecodes() const  { return _bytecodes;}
                virtual state_operations_vector state_operations()  const {return _state_operations;}
                virtual short_rw_operations_vector short_rw_operations()  const {return _short_rw_operations;}
                virtual std::vector<copy_event> copy_events()  const { return _copy_events;}
                virtual std::vector<zkevm_state> zkevm_states()  const { return _zkevm_states;}
                virtual std::vector<std::pair<zkevm_word_type, zkevm_word_type>>  exponentiations() const {return _exponentiations;}
                virtual std::map<std::size_t, zkevm_call_state_data> call_state_data() const {return _call_state_data;}
                virtual std::vector<timeline_item> timeline()  const {return _timeline;}

                zkevm_basic_input_generator(abstract_block_loader *_loader): zkevm_basic_evm(_loader){
                    rw_counter = 1;
                    zkevm_basic_evm::execute_blocks();
                    std::sort(_short_rw_operations.begin(), _short_rw_operations.end(), [](short_rw_operation a, short_rw_operation b){
                        return a < b;
                    });
                    _timeline.push_back({
                        0,
                        rw_operation_type::start,
                        0
                    });
                    for( std::size_t i = 1; i < _short_rw_operations.size(); i++){
                        _short_rw_operations[i].internal_counter = _short_rw_operations[i-1].internal_counter;
                        if(
                            _short_rw_operations[i].op != _short_rw_operations[i-1].op ||
                            _short_rw_operations[i].id != _short_rw_operations[i-1].id ||
                            _short_rw_operations[i].address != _short_rw_operations[i-1].address
                        ) _short_rw_operations[i].internal_counter++;
                        _timeline.push_back({
                            _short_rw_operations[i].rw_counter,
                            _short_rw_operations[i].op,
                            _short_rw_operations[i].internal_counter
                        });
                    }
                    std::sort(_state_operations.begin(), _state_operations.end(), [](state_operation a, state_operation b){
                        return a < b;
                    });
                    for(std::size_t i = 1; i < _state_operations.size(); i++ ){
                        _state_operations[i].internal_counter = _state_operations[i-1].internal_counter;
                        if(
                            _state_operations[i].op != _state_operations[i-1].op ||
                            _state_operations[i].id != _state_operations[i-1].id ||
                            _state_operations[i].address != _state_operations[i-1].address ||
                            _state_operations[i].field != _state_operations[i-1].field ||
                            _state_operations[i].storage_key != _state_operations[i-1].storage_key
                        ) _state_operations[i].internal_counter++;
                        if( _state_operations[i].is_original ) _timeline.push_back({
                            _state_operations[i].rw_counter,
                            _state_operations[i].op,
                            _state_operations[i].internal_counter
                        });
                    }
                    std::sort(_timeline.begin(), _timeline.end(), [](timeline_item a, timeline_item b){
                        return a.rw_id < b.rw_id;
                    });
                }

                virtual void start_block() override{
                    block_id = tx_id = call_id = rw_counter;
                    BOOST_LOG_TRIVIAL(trace) << "START BLOCK " << block_id << std::endl;
                    _zkevm_states.push_back(zkevm_state(
                        call_id,
                        bytecode_hash,
                        pc,
                        opcode_to_number(zkevm_opcode::start_block),
                        stack.size(),
                        memory.size(),
                        gas,
                        rw_counter
                    ));
                    zkevm_basic_evm::start_block();
                    _short_rw_operations.push_back(call_context_header_operation(
                        block_id, call_context_field::parent_id, 0
                    ));
                    _short_rw_operations.push_back(call_context_header_operation(
                        block_id, call_context_field::block_id, block_id
                    ));
                    _short_rw_operations.push_back(call_context_header_operation(
                        block_id, call_context_field::tx_id, 0
                    ));
                    _short_rw_operations.push_back(call_context_header_operation(
                        block_id, call_context_field::call_context_value, 0
                    ));
                    _short_rw_operations.push_back(call_context_header_operation(
                        block_id, call_context_field::call_context_address, 0
                    ));
                    _short_rw_operations.push_back(call_context_header_operation(
                        block_id, call_context_field::calldata_size, 0
                    ));
                    _short_rw_operations.push_back(call_context_header_operation(
                        block_id, call_context_field::depth, 0
                    ));
                    _short_rw_operations.push_back(call_context_header_operation(
                        block_id, call_context_field::returndata_size, 0
                    ));
                    _short_rw_operations.push_back(call_context_header_operation(
                        block_id, call_context_field::call_status, 0
                    ));
                    last_state_counter_stack.push_back({});
                    _call_stack.back().call_id = block_id;
                    {
                        state_operation s;
                        s.op = rw_operation_type::state_call_context;
                        s.id = call_id;
                        s.address = std::size_t(state_call_context_fields::parent_id);
                        s.field = 0;
                        s.storage_key = 0;
                        s.rw_counter = call_id;
                        s.is_write = false;
                        s.initial_value = 0;
                        s.call_initial_value = 0;
                        s.previous_value = 0;
                        s.value = 0;
                        s.parent_id = 0;
                        s.grandparent_id = 0;
                        s.call_id = call_id;
                        _state_operations.push_back(s);
                    }
                    _call_state_data[call_id].parent_id = 0;
                    rw_counter += call_context_readonly_field_amount;
                }

                virtual void start_transaction() override{
                    tx_id = call_id = rw_counter;
                    BOOST_LOG_TRIVIAL(trace) << "START TRANSACTION " << tx_id << std::endl;
                    _zkevm_states.push_back(zkevm_state(
                        call_id,
                        bytecode_hash,
                        pc,
                        opcode_to_number(zkevm_opcode::start_transaction),
                        stack.size(),
                        memory.size(),
                        gas,
                        rw_counter
                    ));
                    zkevm_basic_evm::start_transaction();
                    _call_stack.back().call_id = tx_id;
                    last_state_counter_stack.push_back({});
                    if( _bytecode_hashes.count(bytecode_hash) == 0){
                        _keccaks.new_buffer(
                            bytecode
                        );
                        _bytecodes.new_buffer(
                            bytecode
                        );
                        _bytecode_hashes.insert(bytecode_hash);
                    }
                    append_call_context_readonly_fields();
                    {
                        state_operation s;
                        s.op = rw_operation_type::state_call_context;
                        s.id = call_id;
                        s.address = std::size_t(state_call_context_fields::parent_id);
                        s.field = 0;
                        s.storage_key = 0;
                        s.rw_counter = call_id + std::size_t(state_call_context_fields::parent_id);
                        s.is_write = false;
                        s.initial_value = block_id;
                        s.call_initial_value = block_id;
                        s.previous_value = block_id;
                        s.value = block_id;
                        s.parent_id = block_id;
                        s.grandparent_id = 0;
                        s.call_id = call_id;
                        _state_operations.push_back(s);
                    }
                    rw_counter += call_context_readonly_field_amount + tx_context_fields_amount;

                    for( std::size_t i = 0; i < calldata.size(); i++ ){
                        _short_rw_operations.push_back(calldata_rw_operation(
                            call_id, i,rw_counter++, true, calldata[i]
                        ));
                    }
                    _call_state_data[call_id].parent_id = block_id;
                    print_accounts_current_state();
                }

                virtual void start_call() override{
                    call_id = rw_counter;
                    BOOST_LOG_TRIVIAL(trace) << "START CALL " << call_id << std::endl;
                    _zkevm_states.push_back(zkevm_state(
                        call_id,
                        bytecode_hash,
                        pc,
                        opcode_to_number(zkevm_opcode::start_call),
                        stack.size(),
                        memory.size(),
                        gas,
                        rw_counter
                    ));
                    zkevm_basic_evm::start_call();

                    last_state_counter_stack.push_back({});
                    append_call_context_readonly_fields();
                    rw_counter += call_context_readonly_field_amount;

                    if (!call_is_precompile && _bytecode_hashes.count(bytecode_hash) == 0) {
                        _keccaks.new_buffer(
                            bytecode
                        );
                        _bytecodes.new_buffer(
                            bytecode
                        );
                        _bytecode_hashes.insert(bytecode_hash);
                    }
                    _call_stack.back().call_id = call_id;
                    {
                        state_operation s;
                        s.op = rw_operation_type::state_call_context;
                        s.id = call_id;
                        s.address = std::size_t(state_call_context_fields::parent_id);
                        s.field = 0;
                        s.storage_key = 0;
                        s.rw_counter = call_id + std::size_t(state_call_context_fields::parent_id);
                        s.is_write = false;
                        s.initial_value = _call_stack[_call_stack.size() - 2].call_id;
                        s.call_initial_value = _call_stack[_call_stack.size() - 2].call_id;
                        s.previous_value = _call_stack[_call_stack.size() - 2].call_id;
                        s.value = _call_stack[_call_stack.size() - 2].call_id;
                        s.parent_id = _call_stack[_call_stack.size() - 2].call_id;
                        s.grandparent_id = _call_stack[_call_stack.size() - 3].call_id;
                        s.call_id = call_id;
                        _state_operations.push_back(s);
                    }
                    _call_state_data[call_id].parent_id = _call_stack[_call_stack.size() - 2].call_id;
                    for( std::size_t i = 0; i < calldata.size(); i++ ){
                        _short_rw_operations.push_back(calldata_rw_operation(call_id, i, rw_counter++, true, calldata[i]));
                    }
                    print_accounts_current_state();
                }

                virtual void execute_precompile() override {
                    zkevm_basic_evm::execute_precompile();

                    for (size_t i = 0; i < returndata.size(); ++i) {
                        _short_rw_operations.push_back(returndata_rw_operation(
                            call_id,
                            i,
                            rw_counter++,
                            true,
                            returndata[i]
                        ));
                    }

                    _short_rw_operations.push_back(call_context_header_operation(
                        call_id,
                        call_context_field::call_status,
                        call_status
                    ));
                }

                virtual void transfer_to_eth_account() override{
                    zkevm_basic_evm::transfer_to_eth_account();
                }

                virtual void call() override{
                    zkevm_word_type address = stack[stack.size() - 2] & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256;
                    // // Precompiles
                    // if( address >= 0x1 && address <= 0xa ){
                    //     BOOST_LOG_TRIVIAL(fatal) << "Precompile call";
                    //     BOOST_ASSERT(false);
                    //     zkevm_basic_evm::call();
                    //     return;
                    // }
                    // // Transfer to empty account
                    // if( _accounts_current_state[address].bytecode.size() == 0){
                    //     BOOST_LOG_TRIVIAL(fatal) << "Transfer to empty account" << std::hex << address << std::dec;
                    //     zkevm_basic_evm::call();
                    //     return;
                    // }
                    BOOST_LOG_TRIVIAL(debug) << "Call to " << std::hex << address << std::dec;
                    _zkevm_states.back().load_stack(stack, 7);
                    append_stack_reads(7);
                    zkevm_basic_evm::call();
                }

                virtual void delegatecall() override{
                    zkevm_word_type address = stack[stack.size() - 2] & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256;
                    BOOST_LOG_TRIVIAL(debug) << "Delegatecall to " << std::hex << address << std::dec;
                    _zkevm_states.back().load_stack(stack, 6);
                    append_stack_reads(6);
                    zkevm_basic_evm::delegatecall();
                }

                virtual void staticcall() override{
                    zkevm_word_type address = stack[stack.size() - 2] & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256;
                    // Precompiles
                    // if( address >= 0x1 && address <= 0xa ){
                    //     BOOST_LOG_TRIVIAL(fatal) << "Precompile call";
                    //     BOOST_ASSERT(false);
                    //     zkevm_basic_evm::staticcall();
                    //     return;
                    // }
                    // // Transfer to empty account
                    // if( _accounts_current_state[address].bytecode.size() == 0){
                    //     BOOST_LOG_TRIVIAL(fatal) << "Transfer to empty account" << std::hex << address << std::dec;
                    //     BOOST_ASSERT(false);
                    //     zkevm_basic_evm::staticcall();
                    //     return;
                    // }
                    BOOST_LOG_TRIVIAL(debug) << "Staticcall to " << std::hex << address << std::dec;
                    _zkevm_states.back().load_stack(stack, 6);
                    append_stack_reads(6);
                    zkevm_basic_evm::staticcall();
                }

                virtual void execute_opcode() override{
                    _zkevm_states.push_back(zkevm_state(
                        call_id,
                        bytecode_hash,
                        pc,
                        current_opcode,
                        stack.size(),
                        memory.size(),
                        gas,
                        rw_counter
                    ));
                    zkevm_basic_evm::execute_opcode();
                }

                virtual void stop() override{
                    _zkevm_states.back().load_size_t_field(
                        zkevm_state_size_t_field::depth, depth
                    );
                    _zkevm_states.back().load_size_t_field(
                        zkevm_state_size_t_field::bytecode_size, bytecode.size()
                    );
                    _short_rw_operations.push_back(call_context_header_operation(
                        call_id,
                        call_context_field::call_status,
                        1
                    ));
                    zkevm_basic_evm::stop();
                }

                virtual void push_opcode( std::size_t x) override {

                    zkevm_basic_evm::push_opcode(x);
                    _zkevm_states.back().load_word_field(
                        zkevm_state_word_field::additional_input, stack.back()
                    );
                    _short_rw_operations.push_back(stack_rw_operation(
                        call_id,
                        stack.size() - 1,
                        rw_counter++,
                        true,
                        stack.back()
                    ));
                }

                virtual void add() override{
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::add();
                    append_stack_writes(1);
                }

                virtual void sub() override{

                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::sub();
                    append_stack_writes(1);
                }

                virtual void mul() override{

                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::mul();
                    append_stack_writes(1);
                }

                virtual void div() override{

                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::div();
                    append_stack_writes(1);
                }

                virtual void mod() override{

                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::mod();
                    append_stack_writes(1);
                }

                virtual void sdiv() override{

                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::sdiv();
                    append_stack_writes(1);
                }

                virtual void smod() override{

                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::smod();
                    append_stack_writes(1);
                }

                virtual void addmod() override{

                    _zkevm_states.back().load_stack(stack,3);
                    append_stack_reads(3);
                    zkevm_basic_evm::addmod();
                    append_stack_writes(1);
                }

                virtual void mulmod() override{

                    _zkevm_states.back().load_stack(stack,3);
                    append_stack_reads(3);
                    zkevm_basic_evm::mulmod();
                    append_stack_writes(1);
                }

                virtual void exp() override{

                    _zkevm_states.back().load_stack(stack,2);
                    _exponentiations.push_back({stack[stack.size() - 1], stack[stack.size() - 2]});
                    append_stack_reads(2);
                    zkevm_basic_evm::exp();
                    append_stack_writes(1);
                }

                virtual void mload() override{
                    zkevm_word_type full_offset = stack.back();
                    _zkevm_states.back().load_stack(stack,1);
                    append_stack_reads(1);
                    if (full_offset < (1 << 25) - 31 ) _zkevm_states.back().load_memory(memory, std::size_t(full_offset), 32);
                    zkevm_basic_evm::mload();
                    if( full_offset < (1 << 25) - 31){
                        std::size_t offset = std::size_t(full_offset);
                        for( std::size_t i = 0; i < 32; i++){
                            _short_rw_operations.push_back(memory_rw_operation(
                                call_id,
                                offset + i,
                                rw_counter++,
                                false,
                                memory[offset + i]
                            ));
                        }
                        append_stack_writes(1);
                    }
                }

                virtual void mstore() override{
                    zkevm_word_type full_offset = stack.back();
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::mstore();

                    if( full_offset < (1 << 25) - 31 ){
                        std::size_t offset = std::size_t(full_offset);
                        for( std::size_t i = 0; i < 32; i++){
                            _short_rw_operations.push_back(memory_rw_operation(
                                call_id,
                                offset + i,
                                rw_counter++,
                                true,
                                memory[offset + i]
                            ));
                        }
                    }
                }

                virtual void mstore8() override{
                    zkevm_word_type full_offset = stack.back();
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::mstore8();

                    if( full_offset < (1 << 25) ){
                        std::size_t offset = std::size_t(full_offset);
                        _short_rw_operations.push_back(memory_rw_operation(
                            call_id,
                            offset,
                            rw_counter++,
                            true,
                            memory[offset]
                        ));
                    }
                }

                virtual void tload() override{
                    zkevm_word_type key = stack.back();
                    _zkevm_states.back().load_stack(stack,1);
                    append_stack_reads(1);
                    _zkevm_states.back().load_word_field(zkevm_state_word_field::call_context_address, call_context_address);
                    _zkevm_states.back().load_word_field(zkevm_state_word_field::storage_key, key);
                    _zkevm_states.back().load_word_field(
                        zkevm_state_word_field::storage_value,
                        _call_stack.back().transient_storage.count({call_context_address,key})?_call_stack.back().transient_storage[{call_context_address,key}]:0
                    );
                    _zkevm_states.back().load_word_field(
                        zkevm_state_word_field::initial_storage_value, 0
                    );
                    zkevm_basic_evm::tload();
                    {
                        last_state_counter_stack.back()[{rw_operation_type::transient_storage, call_context_address, 0, key}] = rw_counter;
                        state_operation s;
                        s.is_original = true;
                        s.op = rw_operation_type::transient_storage;
                        s.id = call_id;
                        s.address = call_context_address;
                        s.field = 0;
                        s.storage_key = key;
                        s.rw_counter = rw_counter++;
                        s.is_write = false;
                        s.initial_value = 0;
                        s.call_initial_value = depth == 2? 0: _call_stack[_call_stack.size() - 2].transient_storage[{call_context_address, key}];
                        s.previous_value = _call_stack.back().transient_storage[{call_context_address, key}];
                        s.value = _call_stack.back().transient_storage[{call_context_address, key}];
                        s.parent_id = _call_stack[_call_stack.size() - 2].call_id;
                        s.grandparent_id = depth == 2? 0: _call_stack[_call_stack.size() - 3].call_id;
                        s.call_id = call_id;
                        _state_operations.push_back(s);
                    }
                    append_stack_writes(1);
                    BOOST_LOG_TRIVIAL(trace) << "TLOAD is done" << std::hex << key << std::dec;
                }

                virtual void tstore() override{
                    zkevm_word_type key = stack[stack.size() - 1];
                    zkevm_word_type value = stack[stack.size() - 2];
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    _zkevm_states.back().load_word_field(zkevm_state_word_field::call_context_address, call_context_address);
                    _zkevm_states.back().load_word_field(zkevm_state_word_field::storage_key, key);
                    _zkevm_states.back().load_word_field(
                        zkevm_state_word_field::storage_value,
                        _call_stack.back().transient_storage.count({call_context_address,key})?_call_stack.back().transient_storage[{call_context_address,key}]:0
                    );
                    _zkevm_states.back().load_word_field(
                        zkevm_state_word_field::initial_storage_value, 0
                    );
                    {
                        last_state_counter_stack.back()[{rw_operation_type::transient_storage, call_context_address, 0, key}] = rw_counter;
                        state_operation s;
                        s.is_original = true;
                        s.op = rw_operation_type::transient_storage;
                        s.id = call_id;
                        s.address = call_context_address;
                        s.field = 0;
                        s.storage_key = key;
                        s.rw_counter = rw_counter++;
                        s.is_write = true;
                        s.initial_value = 0;
                        s.call_initial_value = depth == 2? 0: _call_stack[_call_stack.size() - 2].transient_storage[{call_context_address, key}];
                        s.previous_value = _call_stack.back().transient_storage[{call_context_address, key}];
                        s.value = value;
                        s.parent_id = _call_stack[_call_stack.size() - 2].call_id;
                        s.grandparent_id = depth == 2? 0: _call_stack[_call_stack.size() - 3].call_id;
                        s.call_id = call_id;
                        _state_operations.push_back(s);
                    }
                    zkevm_basic_evm::tstore();
                }

                virtual void sload() override{
                    zkevm_word_type key = stack.back();
                    _zkevm_states.back().load_stack(stack,1);
                    append_stack_reads(1);
                    _zkevm_states.back().load_word_field(zkevm_state_word_field::call_context_address, call_context_address);
                    _zkevm_states.back().load_word_field(zkevm_state_word_field::storage_key, key);
                    _zkevm_states.back().load_word_field(
                        zkevm_state_word_field::storage_value,
                        _accounts_current_state[call_context_address].storage.count(key)?_accounts_current_state[call_context_address].storage[key]:0
                    );
                    _zkevm_states.back().load_word_field(
                        zkevm_state_word_field::initial_storage_value,
                        _call_stack[1].state[call_context_address].storage[key]
                    );
                    _zkevm_states.back().load_size_t_field(
                        zkevm_state_size_t_field::was_accessed, _call_stack.back().was_accessed.count({call_context_address, 0, key})
                    );
                    {
                        last_state_counter_stack.back()[{rw_operation_type::access_list, call_context_address, 0, key}] = rw_counter;
                        state_operation s;
                        s.op = rw_operation_type::access_list;
                        s.id = call_id;
                        s.address = call_context_address;
                        s.field = 0;
                        s.storage_key = key;
                        s.rw_counter = rw_counter++;
                        s.is_write = true;
                        s.initial_value = 0;
                        s.call_initial_value = depth == 2? 0: _call_stack[_call_stack.size() - 2].was_accessed.count({call_context_address, 0, key});
                        s.previous_value = _call_stack[_call_stack.size() - 1].was_accessed.count({call_context_address, 0, key});
                        s.value = 1;
                        s.parent_id = _call_stack[_call_stack.size() - 2].call_id;
                        s.grandparent_id = depth == 2? 0: _call_stack[_call_stack.size() - 3].call_id;
                        s.call_id = call_id;
                        _state_operations.push_back(s);
                    }
                    {
                        last_state_counter_stack.back()[{rw_operation_type::state, call_context_address, 0, key}] = rw_counter;
                        state_operation s;
                        s.op = rw_operation_type::state;
                        s.id = call_id;
                        s.address = call_context_address;
                        s.field = 0;
                        s.storage_key = key;
                        s.rw_counter = rw_counter++;
                        s.is_write = false;
                        s.initial_value = _call_stack[1].state[call_context_address].storage[key];
                        s.call_initial_value = depth == 2? _call_stack[1].state[call_context_address].storage[key]: _call_stack.back().state[call_context_address].storage[key];
                        s.previous_value = _accounts_current_state[call_context_address].storage[key];
                        s.value = _accounts_current_state[call_context_address].storage[key];
                        s.parent_id = _call_stack[_call_stack.size() - 2].call_id;
                        s.grandparent_id = depth == 2? 0: _call_stack[_call_stack.size() - 3].call_id;
                        s.call_id = call_id;
                        _state_operations.push_back(s);
                    }
                    zkevm_basic_evm::sload();
                    append_stack_writes(1);
                }

                virtual void sstore() override{
                    zkevm_word_type key = stack[stack.size() - 1];
                    zkevm_word_type value = stack[stack.size() - 2];
                    _zkevm_states.back().load_word_field(zkevm_state_word_field::call_context_address, call_context_address);
                    _zkevm_states.back().load_word_field(zkevm_state_word_field::storage_key, key);
                    _zkevm_states.back().load_word_field(
                        zkevm_state_word_field::storage_value,
                        _accounts_current_state[call_context_address].storage.count(key)?_accounts_current_state[call_context_address].storage[key]:0
                    );
                    _zkevm_states.back().load_word_field(
                        zkevm_state_word_field::initial_storage_value,
                        _call_stack[1].state[call_context_address].storage[key]
                    );
                    _zkevm_states.back().load_size_t_field(
                        zkevm_state_size_t_field::was_accessed, _call_stack.back().was_accessed.count({call_context_address, 0, key})
                    );
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    {
                        last_state_counter_stack.back()[{rw_operation_type::access_list, call_context_address, 0, key}] = rw_counter;
                        state_operation s;
                        s.op = rw_operation_type::access_list;
                        s.id = call_id;
                        s.address = call_context_address;
                        s.field = 0;
                        s.storage_key = key;
                        s.rw_counter = rw_counter++;
                        s.is_write = true;
                        s.initial_value =  0;
                        s.call_initial_value = depth == 2?  0 : _call_stack[_call_stack.size() - 2].was_accessed.count({call_context_address, 0, key});
                        s.previous_value = _call_stack[_call_stack.size() - 1].was_accessed.count({call_context_address, 0, key});
                        s.value = 1;
                        s.parent_id = _call_stack[_call_stack.size() - 2].call_id;
                        s.grandparent_id = depth == 2? 0: _call_stack[_call_stack.size() - 3].call_id;
                        s.call_id = call_id;
                        _state_operations.push_back(s);
                    }
                    {
                        last_state_counter_stack.back()[{rw_operation_type::state, call_context_address, 0, key}] = rw_counter;
                        state_operation s;
                        s.op = rw_operation_type::state;
                        s.id = call_id;
                        s.address = call_context_address;
                        s.field = 0;
                        s.storage_key = key;
                        s.rw_counter = rw_counter++;
                        s.is_write = true;
                        s.initial_value = _call_stack[1].state[call_context_address].storage[key];
                        s.call_initial_value = depth == 2? _accounts_initial_state[call_context_address].storage[key]: _call_stack.back().state[call_context_address].storage[key];
                        s.previous_value = _accounts_current_state[call_context_address].storage[key];
                        s.value = value;
                        s.parent_id = _call_stack[_call_stack.size() - 2].call_id;
                        s.grandparent_id = depth == 2? 0: _call_stack[_call_stack.size() - 3].call_id;
                        s.call_id = call_id;
                        _state_operations.push_back(s);
                    }
                    zkevm_basic_evm::sstore();
                }

                virtual void iszero() override{

                    _zkevm_states.back().load_stack(stack,1);
                    append_stack_reads(1);
                    zkevm_basic_evm::iszero();
                    append_stack_writes(1);
                }

                virtual void eq() override{

                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::eq();
                    append_stack_writes(1);
                }

                virtual void and_opcode() override{

                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::and_opcode();
                    append_stack_writes(1);
                }

                virtual void or_opcode() override{

                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::or_opcode();
                    append_stack_writes(1);
                }

                virtual void xor_opcode() override{

                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::xor_opcode();
                    append_stack_writes(1);
                }

                virtual void not_opcode() override{

                    _zkevm_states.back().load_stack(stack,1);
                    append_stack_reads(1);
                    zkevm_basic_evm::not_opcode();
                    append_stack_writes(1);
                }

                virtual void shr() override{
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::shr();
                    append_stack_writes(1);
                }

                virtual void shl() override{
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::shl();
                    append_stack_writes(1);
                }

                virtual void sar() override{
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::sar();
                    append_stack_writes(1);
                }

                virtual void lt() override{
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::lt();
                    append_stack_writes(1);
                }

                virtual void gt() override{
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::gt();
                    append_stack_writes(1);
                }

                virtual void slt() override{
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::slt();
                    append_stack_writes(1);
                }

                virtual void sgt() override{
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::sgt();
                    append_stack_writes(1);
                }

                virtual void byte() override{
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::byte();
                    append_stack_writes(1);
                }

                virtual void signextend() override{
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::signextend();
                    append_stack_writes(1);
                }

                virtual void jump() override{
                    _zkevm_states.back().load_stack(stack,1);
                    append_stack_reads(1);
                    zkevm_basic_evm::jump();
                }

                virtual void jumpi() override{
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::jumpi();
                }

                virtual void jumpdest() override{
                    zkevm_basic_evm::jumpdest();
                }

                virtual void pc_opcode() override{
                    zkevm_basic_evm::pc_opcode();
                    append_stack_writes(1);
                }

                virtual void gas_error() override{
                    BOOST_LOG_TRIVIAL(trace) << "Gas error";
                    _short_rw_operations.push_back(call_context_header_operation(
                        call_id,
                        call_context_field::call_status,
                        0
                    ));
                    zkevm_basic_evm::gas_error();
                }

                virtual void gas_opcode() override{
                    zkevm_basic_evm::gas_opcode();
                    append_stack_writes(1);
                }

                // TODO: Add small test with debug_traceTransaction
                virtual void msize_opcode() override{

                    zkevm_basic_evm::msize_opcode();
                    append_stack_writes(1);
                }

                virtual void logx( std::size_t l) override{
                    std::size_t offset = std::size_t(stack[stack.size() - 1]);
                    std::size_t length = std::size_t(stack[stack.size() - 2]);


                    _zkevm_states.back().load_stack(stack,2 + l);
                    append_stack_reads(2 + l);
                    zkevm_basic_evm::logx(l);

                    _zkevm_states.back().load_memory(memory, offset, length);
                    for( std::size_t i = 0; i < length; i++){
                        _short_rw_operations.push_back(memory_rw_operation(
                            call_id,
                            offset + i,
                            rw_counter++,
                            false,
                            memory[offset + i]
                        ));
                    }
                }

                virtual void calldatacopy() override {
                    std::size_t dst = std::size_t(stack[stack.size() - 1]);
                    std::size_t src = std::size_t(stack[stack.size() - 2]);
                    std::size_t length = std::size_t(stack[stack.size() - 3]);


                    _zkevm_states.back().load_stack(stack,3);
                    _zkevm_states.back().load_calldata(calldata, src, length);
                    append_stack_reads(3);
                    zkevm_basic_evm::calldatacopy();
                    copy_event cpy = calldatacopy_copy_event(
                        call_id,
                        src,
                        dst,
                        rw_counter,
                        length
                    );

                    for( std::size_t i = 0; i < length; i++){
                        _short_rw_operations.push_back(calldata_rw_operation(
                            call_id, src + i, rw_counter++, false, src + i < calldata.size() ? calldata[src + i] : 0
                        ));
                    }
                    for( std::size_t i = 0; i < length; i++){
                        _short_rw_operations.push_back(memory_rw_operation(
                            call_id, dst + i, rw_counter++, true, memory[dst + i]
                        ));
                        cpy.push_byte(memory[dst+i]);
                    }
                    if( length > 0 ) _copy_events.push_back(cpy);
                }

                virtual void returndatacopy() override {
                    std::size_t dst = std::size_t(stack[stack.size() - 1]);
                    std::size_t src = std::size_t(stack[stack.size() - 2]);
                    std::size_t length = std::size_t(stack[stack.size() - 3]);

                    _zkevm_states.back().load_stack(stack,3);
                    _zkevm_states.back().load_size_t_field(zkevm_state_size_t_field::lastsubcall_id, _call_stack.back().lastcall_id);
                    append_stack_reads(3);
                    zkevm_basic_evm::returndatacopy();

                    _short_rw_operations.push_back(
                        call_context_r_operation(
                            call_id,
                            call_context_field::lastcall_id,
                            rw_counter++,
                            _call_stack.back().lastcall_id
                        )
                    );
                    copy_event cpy = returndatacopy_copy_event(
                        _call_stack.back().lastcall_id,
                        src,
                        call_id,
                        dst,
                        rw_counter,
                        length
                    );

                    for( std::size_t i = 0; i < length; i++){
                        _short_rw_operations.push_back(returndata_rw_operation(
                            _call_stack.back().lastcall_id, src + i, rw_counter++, false, src + i < returndata.size() ? returndata[src + i] : 0
                        ));
                    }
                    for( std::size_t i = 0; i < length; i++){
                        _short_rw_operations.push_back(memory_rw_operation(
                            call_id, dst + i, rw_counter++, true, memory[dst + i]
                        ));
                        cpy.push_byte(memory[dst+i]);
                    }
                    if( length > 0 ) _copy_events.push_back(cpy);
                }

                virtual void codecopy() override{
                    std::size_t dst = std::size_t(stack[stack.size() - 1]);
                    std::size_t src = std::size_t(stack[stack.size() - 2]);
                    std::size_t length = std::size_t(stack[stack.size() - 3]);

                    _zkevm_states.back().load_stack(stack, 3);
                    append_stack_reads(3);

                    zkevm_basic_evm::codecopy();
                    if (memory.size() % 32 == 0) {
                        copy_event cpy = codecopy_copy_event(
                            bytecode_hash,
                            src,
                            call_id,
                            dst,
                            rw_counter,
                            length
                        );
                        for( std::size_t i = 0; i < length; i++){
                            _short_rw_operations.push_back(memory_rw_operation(
                                call_id, dst + i, rw_counter++, true, memory[dst + i]
                            ));
                            cpy.push_byte(memory[dst+i]);
                        }
                        if( length > 0 ) _copy_events.push_back(cpy);
                    }
                }

                virtual void dupx( std::size_t d) override {
                    _zkevm_states.back().load_stack(stack,d);
                    _short_rw_operations.push_back(stack_rw_operation(
                        call_id,
                        stack.size() - d,
                        rw_counter++,
                        false,
                        stack[stack.size() - d]
                    ));
                    zkevm_basic_evm::dupx(d);
                    _short_rw_operations.push_back(stack_rw_operation(
                        call_id,
                        stack.size() - 1,
                        rw_counter++,
                        true,
                        stack[stack.size() - 1]
                    ));
                }

                virtual void swapx( std::size_t s) override{
                    _zkevm_states.back().load_stack(stack, s + 1);
                    _short_rw_operations.push_back(stack_rw_operation(
                        call_id,
                        stack.size() - 1,
                        rw_counter++,
                        false,
                        stack[stack.size() - 1]
                    ));
                    _short_rw_operations.push_back(stack_rw_operation(
                        call_id,
                        stack.size() - s - 1,
                        rw_counter++,
                        false,
                        stack[stack.size() - s - 1]
                    ));
                    zkevm_basic_evm::swapx(s);
                    _short_rw_operations.push_back(stack_rw_operation(
                        call_id,
                        stack.size() - s - 1,
                        rw_counter++,
                        true,
                        stack[stack.size() - s - 1]
                    ));
                    _short_rw_operations.push_back(stack_rw_operation(
                        call_id,
                        stack.size() - 1,
                        rw_counter++,
                        true,
                        stack[stack.size() - 1]
                    ));
                }

                virtual void callvalue() override{
                    _zkevm_states.back().load_word_field(zkevm_state_word_field::call_context_value, call_context_value);
                    zkevm_basic_evm::callvalue();
                    append_stack_writes(1);
                }

                virtual void calldatasize() override{
                    _zkevm_states.back().load_size_t_field(zkevm_state_size_t_field::calldatasize, calldata.size());
                    zkevm_basic_evm::calldatasize();
                    append_stack_writes(1);
                }

                virtual void calldataload() override{
                    _zkevm_states.back().load_stack(stack,1);
                    append_stack_reads(1);
                    auto full_address = stack.back();
                    zkevm_basic_evm::calldataload();
                    if( full_address <= two_25 - 32){
                        std::size_t offset = std::size_t(full_address);
                        _zkevm_states.back().load_calldata(calldata, offset, 32);
                        for( std::size_t i = 0; i < 32; i++){
                            _short_rw_operations.push_back(calldata_rw_operation(
                                call_id,
                                offset + i,
                                rw_counter++,
                                false,
                                offset+i < calldata.size() ? calldata[offset+i] : 0
                            ));
                        }
                    }
                    append_stack_writes(1);
                }

                virtual void keccak() override{
                    std::size_t offset = std::size_t(stack[stack.size() - 1]);
                    std::size_t length = std::size_t(stack[stack.size() - 2]);

                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::keccak();
                    _zkevm_states.back().load_word_field(
                        zkevm_state_word_field::keccak_result,
                        stack.back()
                    );

                    copy_event cpy = keccak_copy_event(
                        call_id,
                        offset,
                        rw_counter,
                        stack.back(),
                        length
                    );

                    std::vector<std::uint8_t> buffer;
                    for( std::size_t i = 0; i < length; i++){
                        _short_rw_operations.push_back(memory_rw_operation(
                            call_id,
                            offset + i,
                            rw_counter++,
                            false,
                            memory[offset + i]
                        ));
                        cpy.push_byte(memory[offset + i]);
                        buffer.push_back(memory[offset + i]);
                    }
                    if( length > 0 ) _copy_events.push_back(cpy);
                    _keccaks.new_buffer(buffer);
                    append_stack_writes(1);
                }

                virtual void extcodesize() override{
                    zkevm_basic_evm::extcodesize();
                    append_stack_writes(1);
                }

                virtual void returndatasize() override{
                    _zkevm_states.back().load_size_t_field(zkevm_state_size_t_field::lastsubcall_id, _call_stack.back().lastcall_id);
                    _zkevm_states.back().load_size_t_field(zkevm_state_size_t_field::returndatasize, returndata.size());
                    _short_rw_operations.push_back(
                        call_context_r_operation(
                            call_id,
                            call_context_field::lastcall_id,
                            rw_counter++,
                            _call_stack.back().lastcall_id
                        )
                    );
                    zkevm_basic_evm::returndatasize();
                    append_stack_writes(1);
                }

                virtual void return_opcode() override{
                    std::size_t offset = std::size_t(stack[stack.size() - 1]);
                    std::size_t length = std::size_t(stack[stack.size() - 2]);

                    _zkevm_states.back().load_stack(stack,2);
                    _zkevm_states.back().load_size_t_field(zkevm_state_size_t_field::depth, depth);
                    append_stack_reads(2);
                    zkevm_basic_evm::return_opcode();

                    copy_event cpy = return_copy_event(
                        call_id,
                        offset,
                        rw_counter,
                        length
                    );
                    for( std::size_t i = 0; i < length; i++){
                        _short_rw_operations.push_back(memory_rw_operation(
                            call_id,
                            offset + i,
                            rw_counter++,
                            false,
                            memory[offset + i]
                        ));
                    }
                    for( std::size_t i = 0; i < length; i++){
                        _short_rw_operations.push_back(returndata_rw_operation(
                            call_id,
                            i,
                            rw_counter++,
                            true,
                            returndata[i]
                        ));
                        cpy.push_byte(returndata[i]);
                    }
                    // Write call_status in call_context
                    _short_rw_operations.push_back(call_context_header_operation(
                        call_id,
                        call_context_field::call_status,
                        1
                    ));
                    if( length > 0 ) _copy_events.push_back(cpy);
                }

                virtual void revert() override{
                    _call_state_data[call_id].is_reverted = true;

                    std::size_t offset = std::size_t(stack[stack.size() - 1]);
                    std::size_t length = std::size_t(stack[stack.size() - 2]);

                    _zkevm_states.back().load_stack(stack,2);
                    _zkevm_states.back().load_size_t_field(zkevm_state_size_t_field::modified_items_amount, last_state_counter_stack.back().size());
                    append_stack_reads(2);
                    append_state_reverts();
                    zkevm_basic_evm::revert();

                    copy_event cpy = return_copy_event(
                        call_id,
                        offset,
                        rw_counter,
                        length
                    );
                    for( std::size_t i = 0; i < length; i++){
                        _short_rw_operations.push_back(memory_rw_operation(
                            call_id,
                            offset + i,
                            rw_counter++,
                            false,
                            memory[offset + i]
                        ));
                    }
                    for( std::size_t i = 0; i < length; i++){
                        _short_rw_operations.push_back(returndata_rw_operation(
                            call_id,
                            i,
                            rw_counter++,
                            true,
                            returndata[i]
                        ));
                        cpy.push_byte(returndata[i]);
                    }
                    // Write call_status in call_context
                    _short_rw_operations.push_back(call_context_header_operation(
                        call_id,
                        call_context_field::call_status,
                        0
                    ));
                }

                virtual void end_call() override{
                    _zkevm_states.push_back(zkevm_state(
                        call_id,
                        bytecode_hash,
                        pc,
                        opcode_to_number(zkevm_opcode::end_call),
                        stack.size(),
                        memory.size(),
                        gas,
                        rw_counter
                    ));
                    after_call_last_state_operation_update();

                    zkevm_basic_evm::end_call();

                    _short_rw_operations.push_back(call_context_header_operation(
                        call_id,
                        call_context_field::returndata_size,
                        returndata.size()
                    ));

                    _zkevm_states.back().load_size_t_field(zkevm_state_size_t_field::lastsubcall_id, call_id);
                    _zkevm_states.back().load_size_t_field(zkevm_state_size_t_field::lastcall_returndata_length, _call_stack.back().lastcall_returndatalength);
                    _zkevm_states.back().load_size_t_field(zkevm_state_size_t_field::lastcall_returndata_offset, _call_stack.back().lastcall_returndataoffset);
                    _call_stack.back().lastcall_id = call_id;
                    call_id = _call_stack.back().call_id;
                    _short_rw_operations.push_back(
                        call_context_w_operation(
                            call_id,
                            call_context_field::lastcall_id,
                            rw_counter++,
                            _call_stack.back().lastcall_id
                        )
                    );
                    std::size_t real_length = std::min(_call_stack.back().lastcall_returndatalength, returndata.size());
                    copy_event cpy = end_call_copy_event(
                        _call_stack.back().call_id,
                        _call_stack.back().lastcall_returndataoffset,
                        _call_stack.back().lastcall_id,
                        rw_counter,
                        real_length
                    );
                    for( std::size_t i = 0; i < real_length; i++){
                        _short_rw_operations.push_back(returndata_rw_operation(
                            _call_stack.back().lastcall_id,
                            i,
                            rw_counter++,
                            false,
                            i < returndata.size() ? returndata[i]: 0
                        ));
                    }
                    for( std::size_t i = 0; i < real_length; i++){
                        _short_rw_operations.push_back(memory_rw_operation(
                            call_id,
                            _call_stack.back().lastcall_returndataoffset + i,
                            rw_counter++,
                            true,
                            memory[_call_stack.back().lastcall_returndataoffset + i]
                        ));
                        cpy.push_byte(memory[_call_stack.back().lastcall_returndataoffset + i]);
                    }
                    if( real_length > 0 ) _copy_events.push_back(cpy);
                    append_stack_writes(1);
                }

                virtual void end_transaction() override{
                    BOOST_LOG_TRIVIAL(trace) << "End transaction";
                    after_call_last_state_operation_update();
                    zkevm_basic_evm::end_transaction();
                    _short_rw_operations.push_back(call_context_header_operation(
                        call_id,
                        call_context_field::returndata_size,
                        returndata.size()
                    ));
                    _zkevm_states.push_back(zkevm_state(
                        call_id,
                        bytecode_hash,
                        pc,
                        opcode_to_number(zkevm_opcode::end_transaction),
                        stack.size(),
                        memory.size(),
                        gas,
                        rw_counter
                    ));
                }

                virtual void end_block() override{
                    BOOST_LOG_TRIVIAL(trace) << "End block";
                    zkevm_basic_evm::end_block();
                    _zkevm_states.push_back(zkevm_state(
                        call_id,
                        bytecode_hash,
                        pc,
                        opcode_to_number(zkevm_opcode::end_block),
                        stack.size(),
                        memory.size(),
                        gas,
                        rw_counter
                    ));
                    {
                        state_operation s;
                        s.op = rw_operation_type::state_call_context;
                        s.id = block_id;
                        s.address = std::size_t(state_call_context_fields::modified_items);
                        s.field = 0;
                        s.storage_key = 0;
                        s.rw_counter = block_id + std::size_t(state_call_context_fields::modified_items);
                        s.is_write = false;
                        s.initial_value = last_state_counter_stack.back().size();
                        s.call_initial_value = last_state_counter_stack.back().size();
                        s.previous_value = last_state_counter_stack.back().size();
                        s.value = last_state_counter_stack.back().size();
                        s.parent_id = 0;
                        s.grandparent_id = 0;
                        s.call_id = block_id;
                        _state_operations.push_back(s);
                    }
                    {
                        state_operation s;
                        s.op = rw_operation_type::state_call_context;
                        s.id = block_id;
                        s.address = std::size_t(state_call_context_fields::is_reverted);
                        s.field = 0;
                        s.storage_key = 0;
                        s.rw_counter = block_id + std::size_t(state_call_context_fields::is_reverted);
                        s.is_write = false;
                        s.initial_value = 0;
                        s.call_initial_value = 0;
                        s.previous_value = 0;
                        s.value = 0;
                        s.parent_id = 0;
                        s.grandparent_id = 0;
                        s.call_id = block_id;
                        _state_operations.push_back(s);
                    }
                    {
                        std::size_t end_call_rw_id = 0;
                        for( auto &[k,v]: last_state_counter_stack.back() ){
                            if( end_call_rw_id < v) end_call_rw_id = v;
                        }
                        state_operation s;
                        s.op = rw_operation_type::state_call_context;
                        s.id = block_id;
                        s.address = std::size_t(state_call_context_fields::end_call_rw_id);
                        s.field = 0;
                        s.storage_key = 0;
                        s.rw_counter = block_id + std::size_t(state_call_context_fields::end_call_rw_id);
                        s.is_write = false;
                        s.initial_value = end_call_rw_id;
                        s.call_initial_value = end_call_rw_id;
                        s.previous_value = end_call_rw_id;
                        s.value = end_call_rw_id;
                        s.parent_id = 0;
                        s.grandparent_id = 0;
                        s.call_id = block_id;
                        _state_operations.push_back(s);
                    }
                    _call_state_data[block_id].modified_items = last_state_counter_stack.back().size();
                    last_state_counter_stack.pop_back();
                }


                virtual ~zkevm_basic_input_generator(){
                    _call_stack.clear();
                    _existing_accounts.clear();
                    _accounts_current_state.clear();
                    _accounts_initial_state.clear();
                    BOOST_LOG_TRIVIAL(trace) << "Destructor of zkevm_basic_input_generator";
                }

                std::string print_statistics (){
                    std::stringstream ss;
                    ss << "Opcodes amount = " << _zkevm_states.size() << std::endl;
                    std::map<zkevm_opcode, std::size_t> opcode_count;
                    for(auto &op: _zkevm_states){
                        zkevm_opcode c= opcode_from_number(op.opcode());
                        if( opcode_count.count(c) ) opcode_count[c]++; else opcode_count[c] = 1;
                    }
                    for( auto &[k,v] : opcode_count){
                        ss << "\tOpcode " << opcode_to_string(k) << " = " << v << std::endl;
                    }
                    ss << "RW operations amount = " << _short_rw_operations.size() << std::endl;
                    ss << "State operations amount = " << _state_operations.size() << std::endl;
                    std::map<rw_operation_type, std::size_t> rw_count;
                    for(auto &op: _state_operations){
                        if( rw_count.count(op.op) ) rw_count[op.op]++; else rw_count[op.op] = 1;
                    }
                    for( auto &op: _short_rw_operations){
                        if( rw_count.count(op.op) ) rw_count[op.op]++; else rw_count[op.op] = 1;
                    }
                    for( auto &[k,v] : rw_count){
                        ss << "\tRW operation " << rw_operation_type_to_string(k) << " = " << v << std::endl;
                    }
                    ss << "Copy events amount = " << _copy_events.size() << std::endl;
                    std::size_t copy_full_length = 0;
                    for(auto &cpy: _copy_events){
                        copy_full_length += cpy.length;
                    }
                    ss << "Full length of copy events = " << copy_full_length << std::endl;
                    ss << "Bytecodes_amount = " << _bytecodes.get_data().size() << std::endl;
                    std::size_t bytecodes_length_sum = 0;
                    for( const auto &v: _bytecodes.get_data()){
                        bytecodes_length_sum += v.first.size();
                    }
                    ss << "Bytecodes_length_sum = " << bytecodes_length_sum << std::endl;
                    return ss.str();
                }
            protected:
                void append_call_context_readonly_fields(){
                    _short_rw_operations.push_back(call_context_header_operation(
                        call_id,
                        call_context_field::parent_id,
                        depth == 2 ? block_id: _call_stack[_call_stack.size() - 2].call_id
                    ));
                    _short_rw_operations.push_back(call_context_header_operation(
                        call_id,
                        call_context_field::block_id,
                        block_id
                    ));
                    _short_rw_operations.push_back(call_context_header_operation(
                        call_id,
                        call_context_field::tx_id,
                        tx_id
                    ));
                    _short_rw_operations.push_back(call_context_header_operation(
                        call_id,
                        call_context_field::call_context_value,
                        call_context_value
                    ));
                    _short_rw_operations.push_back(call_context_header_operation(
                        call_id,
                        call_context_field::call_context_address,
                        call_context_address
                    ));
                    _short_rw_operations.push_back(call_context_header_operation(
                        call_id,
                        call_context_field::calldata_size,
                        calldata.size()
                    ));
                    _short_rw_operations.push_back(call_context_header_operation(
                        call_id,
                        call_context_field::depth,
                        depth
                    ));
                }
                void append_stack_reads(std::size_t r){
                    for( std::size_t i = 0; i < r; i++){
                        _short_rw_operations.push_back(stack_rw_operation(
                            call_id,
                            stack.size() - 1 - i,
                            rw_counter++,
                            false,
                            stack[stack.size() - 1 - i]
                        ));
                    }
                }
                void append_stack_writes(std::size_t w){
                    for( std::size_t i = 0; i < w; i++){
                        _short_rw_operations.push_back(stack_rw_operation(
                            call_id,
                            stack.size() - w + i,
                            rw_counter++,
                            true,
                            stack[stack.size() - w + i]
                        ));
                    }
                }
            protected:
                void append_state_reverts(){
                    for( auto &[k,v]: last_state_counter_stack.back() ){
                        auto op = std::get<0>(k);
                        auto addr = std::get<1>(k);
                        auto f = std::get<2>(k);
                        auto st_k = std::get<3>(k);
                        std::size_t parent_id = _call_stack[_call_stack.size() - 2].call_id;
                        std::size_t grandparent_id = depth == 2 ? 0: _call_stack[_call_stack.size() - 3].call_id;
                        state_operation s;

                        last_state_counter_stack.back()[k] = rw_counter;
                        s.op = op;
                        s.is_original = true;      // This operation is not presented in the timeline
                        s.address = addr;
                        s.field = f;
                        s.storage_key = st_k;
                        s.id = call_id;
                        s.rw_counter = rw_counter++;
                        s.is_write = true;
                        s.parent_id = parent_id;
                        s.grandparent_id = grandparent_id;
                        s.call_id = call_id;

                        switch(op){
                        case rw_operation_type::access_list:
                        {
                            s.initial_value = 0;
                            s.call_initial_value = depth == 2? 0: _call_stack[_call_stack.size() - 2].was_accessed.count({addr, 0, st_k});
                            s.previous_value = _call_stack.back().was_accessed.count({addr, 0, st_k});
                            s.value = s.call_initial_value;
                            break;
                        }
                        case rw_operation_type::state:
                        {
                            s.initial_value = _block_initial_state[addr].storage[st_k];
                            s.call_initial_value = _call_stack.back().state[addr].storage[st_k];
                            s.previous_value = _accounts_current_state[addr].storage[st_k];
                            s.value = s.call_initial_value;
                            break;
                        }
                        case rw_operation_type::transient_storage:
                            s.initial_value = 0;
                            s.call_initial_value = depth == 2? 0: _call_stack[_call_stack.size() - 2].transient_storage[{addr, st_k}];
                            s.previous_value = _call_stack.back().transient_storage[{addr,st_k}];
                            s.value =  s.call_initial_value;
                            break;
                        default:
                            BOOST_LOG_TRIVIAL(fatal) << "Wrong stack operation" << std::endl;
                            BOOST_ASSERT(false);
                        }
                        _state_operations.push_back(s);
                    }
                }

                void after_call_last_state_operation_update(){
                    {
                        state_operation s;
                        s.op = rw_operation_type::state_call_context;
                        s.id = call_id;
                        s.address = std::size_t(state_call_context_fields::modified_items);
                        s.field = 0;
                        s.storage_key = 0;
                        s.rw_counter = call_id + std::size_t(state_call_context_fields::modified_items);
                        s.is_write = false;
                        s.initial_value = last_state_counter_stack.back().size();
                        s.call_initial_value = last_state_counter_stack.back().size();
                        s.previous_value = last_state_counter_stack.back().size();
                        s.value = last_state_counter_stack.back().size();
                        s.parent_id = _call_stack[_call_stack.size() - 2].call_id;
                        s.grandparent_id = depth < 3? 0: _call_stack[_call_stack.size() - 3].call_id;
                        s.call_id = call_id;
                        _state_operations.push_back(s);
                    }
                    {
                        state_operation s;
                        s.op = rw_operation_type::state_call_context;
                        s.id = call_id;
                        s.address = std::size_t(state_call_context_fields::is_reverted);
                        s.field = 0;
                        s.storage_key = 0;
                        s.rw_counter = call_id + std::size_t(state_call_context_fields::is_reverted);
                        s.is_write = false;
                        s.initial_value = _call_state_data[call_id].is_reverted? 1: 0;
                        s.call_initial_value = _call_state_data[call_id].is_reverted? 1: 0;
                        s.previous_value = _call_state_data[call_id].is_reverted? 1: 0;
                        s.value = _call_state_data[call_id].is_reverted? 1: 0;
                        s.parent_id = _call_stack[_call_stack.size() - 2].call_id;
                        s.grandparent_id = depth < 3? 0: _call_stack[_call_stack.size() - 3].call_id;
                        s.call_id = call_id;
                        _state_operations.push_back(s);
                    }
                    {
                        std::size_t end_call_rw_id = 0;
                        for( auto &[k,v]: last_state_counter_stack.back() ){
                            if( end_call_rw_id < v) end_call_rw_id = v;
                        }

                        state_operation s;
                        s.op = rw_operation_type::state_call_context;
                        s.id = call_id;
                        s.address = std::size_t(state_call_context_fields::end_call_rw_id);
                        s.field = 0;
                        s.storage_key = 0;
                        s.rw_counter = call_id + std::size_t(state_call_context_fields::end_call_rw_id);
                        s.is_write = false;
                        s.initial_value = end_call_rw_id;
                        s.call_initial_value = end_call_rw_id;
                        s.previous_value = end_call_rw_id;
                        s.value = end_call_rw_id;
                        s.parent_id = _call_stack[_call_stack.size() - 2].call_id;
                        s.grandparent_id = depth < 3? 0: _call_stack[_call_stack.size() - 3].call_id;
                        s.call_id = call_id;
                        _state_operations.push_back(s);
                    }
                    _call_state_data[call_id].is_reverted = _call_state_data[call_id].is_reverted;
                    _call_state_data[call_id].modified_items = last_state_counter_stack.back().size();
                    for( auto &[k,v]: last_state_counter_stack.back() ){
                        auto op = std::get<0>(k);
                        auto addr = std::get<1>(k);
                        auto f = std::get<2>(k);
                        auto st_k = std::get<3>(k);
                        std::size_t rw_id = v;
                        std::size_t parent_id = _call_stack[_call_stack.size() - 2].call_id;
                        std::size_t grandparent_id = depth == 2 ? 0: _call_stack[_call_stack.size() - 3].call_id;
                        std::size_t grandgrandparent_id = depth <= 3? 0: _call_stack[_call_stack.size() - 4].call_id;
                        state_operation s;
                        BOOST_LOG_TRIVIAL(trace) << "Call_id = " << call_id << " parent_id = " << parent_id;

                        s.op = op;
                        s.is_original = false;      // This operation is not presented in the timeline
                        s.address = addr;
                        s.field = f;
                        s.storage_key = st_k;
                        s.id = parent_id;
                        s.rw_counter = rw_id;
                        s.is_write = true;
                        s.parent_id = grandparent_id;
                        s.grandparent_id = grandgrandparent_id;
                        s.call_id = call_id;

                        switch(op){
                        case rw_operation_type::access_list:
                        {
                            s.initial_value = 0;
                            s.call_initial_value = depth == 2? 0: _call_stack[_call_stack.size() - 3].was_accessed.count({addr, 0, st_k});
                            s.previous_value = depth == 2? 0:  _call_stack[_call_stack.size() - 2].was_accessed.count({addr, 0, st_k});
                            s.value = _call_stack.back().was_accessed.count({addr, 0, st_k});
                            break;
                        }
                        case rw_operation_type::state:
                        {
                            s.initial_value = _block_initial_state[addr].storage[st_k];
                            s.call_initial_value = _call_stack[_call_stack.size() - 2].state[addr].storage[st_k];
                            s.previous_value = depth == 2? _accounts_initial_state[addr].storage[st_k]: _call_stack.back().state[addr].storage[st_k];
                            s.value = _accounts_current_state[addr].storage[st_k];
                            break;
                        }
                        case rw_operation_type::transient_storage:
                            s.initial_value = 0;
                            s.call_initial_value = depth == 2? 0: _call_stack[_call_stack.size() - 3].transient_storage[{addr, st_k}];
                            s.previous_value = depth == 2? 0: _call_stack[_call_stack.size() - 2].transient_storage[{addr, st_k}];;
                            s.value = _call_stack.back().transient_storage[{addr,st_k}];
                            break;
                        default:
                            BOOST_LOG_TRIVIAL(fatal) << "Wrong stack operation" << std::endl;
                            BOOST_ASSERT(false);
                        }
                        if( depth > 2 || op == rw_operation_type::state ) {
                            _state_operations.push_back(s);
                            last_state_counter_stack[last_state_counter_stack.size() - 2][k] = v;
                        }
                    }
                    last_state_counter_stack.pop_back();
                }
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil

