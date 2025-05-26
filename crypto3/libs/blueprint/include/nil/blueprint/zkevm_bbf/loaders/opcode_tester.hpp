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

#include <nil/blueprint/zkevm_bbf/input_generators/opcode_tester.hpp>

#include <nil/blueprint/zkevm_bbf/util/ptree.hpp>
#include <nil/blueprint/zkevm_bbf/util.hpp>

// #include <nil/blueprint/zkevm_bbf/opcodes/zkevm_opcodes.hpp>
#include <nil/blueprint/zkevm_bbf/input_generators/basic_evm.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            class opcode_tester_block_loader : abstract_block_loader{
                zkevm_block block;
                zkevm_transaction tx;
                std::map<zkevm_word_type, zkevm_account> _accounts_initial_state;
                std::set<zkevm_word_type>                _existing_accounts;
                bool                                     _are_there_more_blocks = true;
            public:
                virtual zkevm_block load_block() override {
                    BOOST_LOG_TRIVIAL(info) << "OpcodeTester:: Load block " << std::hex << block.hash  << std::dec << " tx_amount = " << block.tx_amount;
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
                    return {tx, _accounts_initial_state, _existing_accounts};
                }

                virtual std::tuple<zkevm_word_type, std::size_t, std::vector<std::uint8_t>>
                    compute_precompile(zkevm_word_type address, std::vector<std::uint8_t> calldata
                ) override {
                    BOOST_ASSERT(false);
                    return {0, 0, {}};
                }

                opcode_tester_block_loader(const zkevm_opcode_tester &opcode_tester) {
                    block.hash = zkevm_keccak_hash({0, 1, 2, 3, 4, 5});
                    block.number = 123;
                    block.parent_hash = zkevm_keccak_hash({0, 1, 2, 3, 4, 4});
                    block.tx_amount = 1;

                    zkevm_word_type caller_address = zkevm_keccak_hash({0, 1, 2, 3, 4, 5, 6}) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256;
                    zkevm_word_type test_account_address = zkevm_keccak_hash({0, 1, 2, 3, 4, 5, 6, 7}) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256;

                    _existing_accounts.insert(caller_address);
                    _existing_accounts.insert(test_account_address);

                    _accounts_initial_state[caller_address].address = caller_address;
                    _accounts_initial_state[caller_address].seq_no = 1;
                    _accounts_initial_state[caller_address].balance = 0xFFFFFFFFFF_big_uint256;

                    _accounts_initial_state[test_account_address].address = test_account_address;
                    _accounts_initial_state[test_account_address].bytecode = opcode_tester.get_bytecode();
                    _accounts_initial_state[test_account_address].code_hash = zkevm_keccak_hash(opcode_tester.get_bytecode());

                    tx.from = caller_address;
                    tx.to = test_account_address;
                    tx.gas = 30000000;
                    BOOST_LOG_TRIVIAL(trace) << "Transactions amount = " << block.tx_amount;
                }


            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil