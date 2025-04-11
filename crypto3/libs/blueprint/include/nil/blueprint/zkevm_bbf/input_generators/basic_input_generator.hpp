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
                }

                virtual void start_block() override{
                    block_id = tx_id = call_id = rw_counter++;
                    BOOST_LOG_TRIVIAL(trace) << "START BLOCK " << block_id << std::endl;
                    zkevm_basic_evm::start_block();
                    _call_stack.back().call_id = block_id;
                }

                virtual void start_transaction() override{
                    tx_id = call_id = rw_counter++;
                    BOOST_LOG_TRIVIAL(trace) << "START TRANSACTION " << tx_id << std::endl;
                    zkevm_basic_evm::start_transaction();
                    _call_stack.back().call_id = tx_id;
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
                        current_opcode,
                        stack.size(),
                        memory.size(),
                        gas,
                        rw_counter
                    ));
                    rw_counter++;
                    zkevm_basic_evm::execute_opcode();
                }

                virtual void end_call() override{
                    zkevm_basic_evm::end_call();
                    call_id = _call_stack.back().call_id;
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

            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil

