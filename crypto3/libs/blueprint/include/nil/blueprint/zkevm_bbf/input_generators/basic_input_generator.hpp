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
#include <nil/blueprint/zkevm_bbf/types/call_commit.hpp>
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
                std::map<std::size_t,zkevm_call_commit>                   _call_commits;

                std::set<zkevm_word_type>                                 _bytecode_hashes;
                //std::map<std::tuple<rw_operation_type, zkevm_word_type, std::size_t, zkevm_word_type>, std::size_t>  last_write_rw_counter;
            public:
                virtual zkevm_keccak_buffers keccaks()  {return _keccaks;}
                virtual zkevm_keccak_buffers bytecodes()  { return _bytecodes;}
                virtual state_operations_vector state_operations()  {return _state_operations;}
                virtual short_rw_operations_vector short_rw_operations()  {return _short_rw_operations;}
                virtual std::map<std::size_t,zkevm_call_commit> call_commits() {return _call_commits;}
                virtual std::vector<copy_event> copy_events() { return _copy_events;}
                virtual std::vector<zkevm_state> zkevm_states() { return _zkevm_states;}
                virtual std::vector<std::pair<zkevm_word_type, zkevm_word_type>> exponentiations(){return _exponentiations;}


                zkevm_basic_input_generator(abstract_block_loader *_loader): zkevm_basic_evm(_loader){
                    rw_counter = 1;
                    zkevm_basic_evm::execute_block();
                    std::sort(_short_rw_operations.begin(), _short_rw_operations.end(), [](short_rw_operation a, short_rw_operation b){
                        return a < b;
                    });

                }

                virtual void start_block() override{
                    block_id = tx_id = call_id = rw_counter;
                    BOOST_LOG_TRIVIAL(trace) << "START BLOCK " << block_id << std::endl;
                    _zkevm_states.push_back(zkevm_state(
                        call_id,
                        bytecode_hash,
                        pc,
                        stack.size(),
                        memory.size(),
                        gas,
                        rw_counter
                    ));
                    _zkevm_states.back().set_current_opcode(opcode_to_number(zkevm_opcode::start_block));
                    zkevm_basic_evm::start_block();
                    rw_counter += block_context_fields_amount;
                    _call_stack.back().call_id = block_id;
                }

                virtual void start_transaction() override{
                    tx_id = call_id = rw_counter;
                    BOOST_LOG_TRIVIAL(trace) << "START TRANSACTION " << tx_id << std::endl;
                    _call_stack.back().call_id = tx_id;
                    _zkevm_states.push_back(zkevm_state(
                        call_id,
                        bytecode_hash,
                        pc,
                        stack.size(),
                        memory.size(),
                        gas,
                        rw_counter
                    ));
                    _zkevm_states.back().set_current_opcode(opcode_to_number(zkevm_opcode::start_transaction));
                    zkevm_basic_evm::start_transaction();
                    if( _bytecode_hashes.count(bytecode_hash) == 0){
                        _keccaks.new_buffer(
                            bytecode
                        );
                        _bytecodes.new_buffer(
                            bytecode
                        );
                        _bytecode_hashes.insert(bytecode_hash);
                    }
                    rw_counter += tx_context_fields_amount;
                }

                virtual void start_call() override{
                    call_id = rw_counter++;
                    BOOST_LOG_TRIVIAL(trace) << "START CALL " << call_id << std::endl;
                    zkevm_basic_evm::start_call();
                    _call_stack.back().call_id = call_id;
                }

                virtual void execute_opcode() override{
                    _zkevm_states.push_back(zkevm_state(
                        call_id,
                        bytecode_hash,
                        pc,
                        stack.size(),
                        memory.size(),
                        gas,
                        rw_counter
                    ));
                    zkevm_basic_evm::execute_opcode();
                }

                virtual void stop() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_size_t_field(
                        zkevm_state_size_t_field::depth, depth
                    );
                    // _short_rw_operations.push_back(stack_rw_operation(
                    //     call_id,
                    //     stack.size() - 1,
                    //     rw_counter++,
                    //     true,
                    //     stack.back()
                    // ));
                    zkevm_basic_evm::stop();
                }

                virtual void push_opcode( std::size_t x) override {
                    _zkevm_states.back().set_current_opcode(current_opcode);
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
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::add();
                    append_stack_writes(1);
                }

                virtual void sub() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::sub();
                    append_stack_writes(1);
                }

                virtual void mul() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::mul();
                    append_stack_writes(1);
                }

                virtual void div() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::div();
                    append_stack_writes(1);
                }

                virtual void mod() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::mod();
                    append_stack_writes(1);
                }

                virtual void sdiv() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::sdiv();
                    append_stack_writes(1);
                }

                virtual void smod() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::smod();
                    append_stack_writes(1);
                }

                virtual void addmod() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,3);
                    append_stack_reads(3);
                    zkevm_basic_evm::addmod();
                    append_stack_writes(1);
                }

                virtual void mulmod() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,3);
                    append_stack_reads(3);
                    zkevm_basic_evm::mulmod();
                    append_stack_writes(1);
                }

                virtual void exp() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,2);
                    _exponentiations.push_back({stack[stack.size() - 1], stack[stack.size() - 2]});
                    append_stack_reads(2);
                    zkevm_basic_evm::exp();
                    append_stack_writes(1);
                }

                virtual void mload() override{
                    std::size_t offset = std::size_t(stack.back());
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,1);
                    _zkevm_states.back().load_memory(memory, offset, 32);
                    append_stack_reads(1);
                    zkevm_basic_evm::mload();
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

                virtual void mstore() override{
                    std::size_t offset = std::size_t(stack.back());
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::mstore();
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

                virtual void mstore8() override{
                    std::size_t offset = std::size_t(stack.back());
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::mstore8();
                    _short_rw_operations.push_back(memory_rw_operation(
                        call_id,
                        offset,
                        rw_counter++,
                        true,
                        memory[offset]
                    ));
                }

                virtual void iszero() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,1);
                    append_stack_reads(1);
                    zkevm_basic_evm::iszero();
                    append_stack_writes(1);
                }

                virtual void eq() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::eq();
                    append_stack_writes(1);
                }

                virtual void and_opcode() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::and_opcode();
                    append_stack_writes(1);
                }

                virtual void or_opcode() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::or_opcode();
                    append_stack_writes(1);
                }

                virtual void xor_opcode() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::xor_opcode();
                    append_stack_writes(1);
                }

                virtual void not_opcode() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,1);
                    append_stack_reads(1);
                    zkevm_basic_evm::not_opcode();
                    append_stack_writes(1);
                }

                virtual void shr() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::shr();
                    append_stack_writes(1);
                }

                virtual void shl() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::shl();
                    append_stack_writes(1);
                }

                virtual void sar() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::sar();
                    append_stack_writes(1);
                }

                virtual void lt() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::lt();
                    append_stack_writes(1);
                }

                virtual void gt() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::gt();
                    append_stack_writes(1);
                }

                virtual void slt() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::slt();
                    append_stack_writes(1);
                }

                virtual void sgt() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::sgt();
                    append_stack_writes(1);
                }

                virtual void byte() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::byte();
                    append_stack_writes(1);
                }

                virtual void signextend() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::signextend();
                    append_stack_writes(1);
                }

                virtual void jump() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,1);
                    append_stack_reads(1);
                    zkevm_basic_evm::jump();
                }

                virtual void jumpi() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    _zkevm_states.back().load_stack(stack,2);
                    append_stack_reads(2);
                    zkevm_basic_evm::jumpi();
                }

                virtual void jumpdest() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    zkevm_basic_evm::jumpdest();
                }

                virtual void pc_opcode() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    zkevm_basic_evm::pc_opcode();
                    append_stack_writes(1);
                }

                virtual void gas_opcode() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    zkevm_basic_evm::gas_opcode();
                    append_stack_writes(1);
                }

                // TODO: Add small test with debug_traceTransaction
                virtual void msize_opcode() override{
                    _zkevm_states.back().set_current_opcode(current_opcode);
                    zkevm_basic_evm::msize_opcode();
                    append_stack_writes(1);
                }

                virtual void logx( std::size_t l) override{
                    std::size_t offset = std::size_t(stack[stack.size() - 1]);
                    std::size_t length = std::size_t(stack[stack.size() - 2]);

                    _zkevm_states.back().set_current_opcode(current_opcode);
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

                    _zkevm_states.back().set_current_opcode(current_opcode);
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
                            call_id, src + i, rw_counter++, src + i < calldata.size() ? calldata[src + i] : 0
                        ));
                    }
                    for( std::size_t i = 0; i < length; i++){
                        _short_rw_operations.push_back(memory_rw_operation(
                            call_id, dst + i, rw_counter++, true, memory[dst + i]
                        ));
                        cpy.push_byte(memory[dst+i]);
                    }
                    _copy_events.push_back(cpy);
                }

                virtual void end_call() override{
                    zkevm_basic_evm::end_call();
                    call_id = _call_stack.back().call_id;
                }

                virtual void end_transaction() override{
                    zkevm_basic_evm::end_transaction();
                    _zkevm_states.push_back(zkevm_state(
                        call_id,
                        bytecode_hash,
                        pc,
                        stack.size(),
                        memory.size(),
                        gas,
                        rw_counter
                    ));
                    _zkevm_states.back().set_current_opcode(current_opcode);
                }

                virtual void end_block() override{
                    zkevm_basic_evm::end_block();
                    _zkevm_states.push_back(zkevm_state(
                        call_id,
                        bytecode_hash,
                        pc,
                        stack.size(),
                        memory.size(),
                        gas,
                        rw_counter
                    ));
                    _zkevm_states.back().set_current_opcode(current_opcode);
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
                    return ss.str();
                }
            protected:
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
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil

