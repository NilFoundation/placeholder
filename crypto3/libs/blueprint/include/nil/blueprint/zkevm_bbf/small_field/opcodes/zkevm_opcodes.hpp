//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin   <d.tabalin@nil.foundation>
// Copyright (c) 2024 Alexey Yashunsky  <a.yashunsky@nil.foundation>
// Copyright (c) 2024 Elena Tatuzova    <e.tatuzova@nil.foundation>
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

#include <iostream>

#include <boost/assert.hpp>
#include <boost/bimap.hpp>

#include <nil/blueprint/zkevm_bbf/types/copy_event.hpp>

#include <nil/blueprint/zkevm_bbf/util.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/abstract_opcode.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/pushx.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/mload.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/mstore.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/mstore8.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/add_sub.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/addmod.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/div_mod.hpp>
// #include <nil/blueprint/zkevm_bbf/small_field/opcodes/mulmod.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/bitwise.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/byte.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/cmp.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/calldatasize.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/calldataload.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/callvalue.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/iszero.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/mul.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/not.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/padding.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/jump.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/jumpi.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/dupx.hpp>
// #include <nil/blueprint/zkevm_bbf/small_field/opcodes/sdiv_smod.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/return.hpp>
// #include <nil/blueprint/zkevm_bbf/small_field/opcodes/err0.hpp>
// #include <nil/blueprint/zkevm_bbf/small_field/opcodes/err1.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/signextend.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/sload.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/sstore.hpp>
// #include <nil/blueprint/zkevm_bbf/small_field/opcodes/tload.hpp>
// #include <nil/blueprint/zkevm_bbf/small_field/opcodes/tstore.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/shl.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/shr.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/sar.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/swapx.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/pop.hpp>
// #include <nil/blueprint/zkevm_bbf/small_field/opcodes/calldatacopy.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/codecopy.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/stop.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/exp.hpp>
// #include <nil/blueprint/zkevm_bbf/small_field/opcodes/keccak.hpp>
// #include <nil/blueprint/zkevm_bbf/small_field/opcodes/mcopy.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/returndatasize.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/returndatacopy.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/call.hpp>
// #include <nil/blueprint/zkevm_bbf/small_field/opcodes/delegatecall.hpp>
// #include <nil/blueprint/zkevm_bbf/small_field/opcodes/staticcall.hpp>
// #include <nil/blueprint/zkevm_bbf/small_field/opcodes/gas.hpp>
// #include <nil/blueprint/zkevm_bbf/small_field/opcodes/revert.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/start_block.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/start_transaction.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/start_call.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/end_call.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/end_transaction.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/end_block.hpp>
// #include <nil/blueprint/zkevm_bbf/small_field/opcodes/extcodesize.hpp>
// #include <nil/blueprint/zkevm_bbf/small_field/opcodes/pc.hpp>
// #include <nil/blueprint/zkevm_bbf/small_field/opcodes/msize.hpp>
// #include <nil/blueprint/zkevm_bbf/small_field/opcodes/logx.hpp>
// #include <nil/blueprint/zkevm_bbf/small_field/opcodes/address.hpp>

namespace nil::blueprint::bbf::zkevm_small_field{
    template <typename BlueprintFieldType>
    std::map<zkevm_opcode, std::shared_ptr<opcode_abstract<BlueprintFieldType>>> get_opcode_implementations(){
        std::map<zkevm_opcode, std::shared_ptr<opcode_abstract<BlueprintFieldType>>> opcodes;
        // add all the implemented opcodes here

        opcodes[zkevm_opcode::STOP] = std::make_shared<zkevm_stop_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::ADD] = std::make_shared<zkevm_add_sub_operation<BlueprintFieldType>>(true);
        opcodes[zkevm_opcode::MUL] = std::make_shared<zkevm_mul_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::SUB] = std::make_shared<zkevm_add_sub_operation<BlueprintFieldType>>(false);
        opcodes[zkevm_opcode::DIV] = std::make_shared<zkevm_div_mod_operation<BlueprintFieldType>>(true);
        // opcodes[zkevm_opcode::SDIV] = std::make_shared<zkevm_sdiv_smod_operation<BlueprintFieldType>>(true);
        opcodes[zkevm_opcode::MOD] = std::make_shared<zkevm_div_mod_operation<BlueprintFieldType>>(false);
        // opcodes[zkevm_opcode::SMOD] = std::make_shared<zkevm_sdiv_smod_operation<BlueprintFieldType>>(false);
        opcodes[zkevm_opcode::ADDMOD] = std::make_shared<zkevm_addmod_operation<BlueprintFieldType>>();
        // opcodes[zkevm_opcode::MULMOD] = std::make_shared<zkevm_mulmod_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::EXP] = std::make_shared<zkevm_exp_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::SIGNEXTEND] = std::make_shared<zkevm_signextend_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::LT] = std::make_shared<zkevm_cmp_operation<BlueprintFieldType>>(cmp_type::C_LT);
        opcodes[zkevm_opcode::GT] = std::make_shared<zkevm_cmp_operation<BlueprintFieldType>>(cmp_type::C_GT);
        opcodes[zkevm_opcode::SLT] = std::make_shared<zkevm_cmp_operation<BlueprintFieldType>>(cmp_type::C_SLT);
        opcodes[zkevm_opcode::SGT] = std::make_shared<zkevm_cmp_operation<BlueprintFieldType>>(cmp_type::C_SGT);
        opcodes[zkevm_opcode::EQ] = std::make_shared<zkevm_cmp_operation<BlueprintFieldType>>(cmp_type::C_EQ);
        opcodes[zkevm_opcode::ISZERO] = std::make_shared<zkevm_iszero_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::AND] = std::make_shared<zkevm_bitwise_operation<BlueprintFieldType>>(bitwise_type::B_AND);
        opcodes[zkevm_opcode::OR] = std::make_shared<zkevm_bitwise_operation<BlueprintFieldType>>(bitwise_type::B_OR);
        opcodes[zkevm_opcode::XOR] = std::make_shared<zkevm_bitwise_operation<BlueprintFieldType>>(bitwise_type::B_XOR);
        opcodes[zkevm_opcode::NOT] = std::make_shared<zkevm_not_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::BYTE] = std::make_shared<zkevm_byte_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::SHL] = std::make_shared<zkevm_shl_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::SHR] = std::make_shared<zkevm_shr_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::SAR] = std::make_shared<zkevm_sar_operation<BlueprintFieldType>>();
        // opcodes[zkevm_opcode::KECCAK256] = std::make_shared<zkevm_keccak_operation<BlueprintFieldType>>();
        // // Memory operations
        opcodes[zkevm_opcode::MSTORE] = std::make_shared<zkevm_mstore_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::MSTORE8] = std::make_shared<zkevm_mstore8_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::MLOAD] = std::make_shared<zkevm_mload_operation<BlueprintFieldType>>();
        // opcodes[zkevm_opcode::MSIZE] = std::make_shared<zkevm_msize_operation<BlueprintFieldType>>();

        // Storage operations
        opcodes[zkevm_opcode::SLOAD] = std::make_shared<zkevm_sload_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::SSTORE] = std::make_shared<zkevm_sstore_operation<BlueprintFieldType>>();

        // // Storage operations
        // opcodes[zkevm_opcode::TLOAD] = std::make_shared<zkevm_tload_operation<BlueprintFieldType>>();
        // opcodes[zkevm_opcode::TSTORE] = std::make_shared<zkevm_tstore_operation<BlueprintFieldType>>();

        // // CALL operaitions
        opcodes[zkevm_opcode::CALLVALUE] = std::make_shared<zkevm_callvalue_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::CALLDATASIZE] = std::make_shared<zkevm_calldatasize_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::CALLDATALOAD] = std::make_shared<zkevm_calldataload_operation<BlueprintFieldType>>();
        // opcodes[zkevm_opcode::CALLDATACOPY] = std::make_shared<zkevm_calldatacopy_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::CODECOPY] = std::make_shared<zkevm_codecopy_operation<BlueprintFieldType>>();

        // // PC operations
        opcodes[zkevm_opcode::JUMPI] = std::make_shared<zkevm_jumpi_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::JUMP] = std::make_shared<zkevm_jump_operation<BlueprintFieldType>>();
        // opcodes[zkevm_opcode::PC] = std::make_shared<zkevm_pc_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::JUMPDEST] = std::make_shared<zkevm_jumpdest_operation<BlueprintFieldType>>();

        opcodes[zkevm_opcode::PUSH0] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(0);
        opcodes[zkevm_opcode::PUSH1] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(1);
        opcodes[zkevm_opcode::PUSH2] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(2);
        opcodes[zkevm_opcode::PUSH3] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(3);
        opcodes[zkevm_opcode::PUSH4] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(4);
        opcodes[zkevm_opcode::PUSH5] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(5);
        opcodes[zkevm_opcode::PUSH6] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(6);
        opcodes[zkevm_opcode::PUSH7] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(7);
        opcodes[zkevm_opcode::PUSH8] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(8);
        opcodes[zkevm_opcode::PUSH9] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(9);
        opcodes[zkevm_opcode::PUSH10] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(10);
        opcodes[zkevm_opcode::PUSH11] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(11);
        opcodes[zkevm_opcode::PUSH12] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(12);
        opcodes[zkevm_opcode::PUSH13] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(13);
        opcodes[zkevm_opcode::PUSH14] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(14);
        opcodes[zkevm_opcode::PUSH15] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(15);
        opcodes[zkevm_opcode::PUSH16] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(16);
        opcodes[zkevm_opcode::PUSH17] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(17);
        opcodes[zkevm_opcode::PUSH18] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(18);
        opcodes[zkevm_opcode::PUSH19] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(19);
        opcodes[zkevm_opcode::PUSH20] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(20);
        opcodes[zkevm_opcode::PUSH21] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(21);
        opcodes[zkevm_opcode::PUSH22] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(22);
        opcodes[zkevm_opcode::PUSH23] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(23);
        opcodes[zkevm_opcode::PUSH24] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(24);
        opcodes[zkevm_opcode::PUSH25] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(25);
        opcodes[zkevm_opcode::PUSH26] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(26);
        opcodes[zkevm_opcode::PUSH27] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(27);
        opcodes[zkevm_opcode::PUSH28] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(28);
        opcodes[zkevm_opcode::PUSH29] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(29);
        opcodes[zkevm_opcode::PUSH30] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(30);
        opcodes[zkevm_opcode::PUSH31] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(31);
        opcodes[zkevm_opcode::PUSH32] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(32);

        opcodes[zkevm_opcode::POP] = std::make_shared<zkevm_pop_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::RETURN] = std::make_shared<zkevm_return_operation<BlueprintFieldType>>();

        // // MEMORY EXPANSION
        opcodes[zkevm_opcode::CODECOPY] = std::make_shared<zkevm_codecopy_operation<BlueprintFieldType>>();
        // opcodes[zkevm_opcode::MCOPY] = std::make_shared<zkevm_mcopy_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::RETURNDATACOPY] = std::make_shared<zkevm_returndatacopy_operation<BlueprintFieldType>>();

        // // not implemented yet opcodes

        opcodes[zkevm_opcode::RETURNDATASIZE] = std::make_shared<zkevm_returndatasize_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::CALL] = std::make_shared<zkevm_call_operation<BlueprintFieldType>>();
        // opcodes[zkevm_opcode::DELEGATECALL] = std::make_shared<zkevm_delegatecall_operation<BlueprintFieldType>>();
        // opcodes[zkevm_opcode::GAS] = std::make_shared<zkevm_gas_operation<BlueprintFieldType>>();
        // opcodes[zkevm_opcode::STATICCALL] = std::make_shared<zkevm_staticcall_operation<BlueprintFieldType>>();
        // opcodes[zkevm_opcode::EXTCODESIZE] = std::make_shared<zkevm_extcodesize_operation<BlueprintFieldType>>();
        // opcodes[zkevm_opcode::ADDRESS] = std::make_shared<zkevm_address_operation<BlueprintFieldType>>();
        // opcodes[zkevm_opcode::BALANCE] = std::make_shared<zkevm_address_operation<BlueprintFieldType>>();

        // DUP
        opcodes[zkevm_opcode::DUP1] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(1);
        opcodes[zkevm_opcode::DUP2] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(2);
        opcodes[zkevm_opcode::DUP3] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(3);
        opcodes[zkevm_opcode::DUP4] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(4);
        opcodes[zkevm_opcode::DUP5] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(5);
        opcodes[zkevm_opcode::DUP6] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(6);
        opcodes[zkevm_opcode::DUP7] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(7);
        opcodes[zkevm_opcode::DUP8] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(8);
        opcodes[zkevm_opcode::DUP9] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(9);
        opcodes[zkevm_opcode::DUP10] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(10);
        opcodes[zkevm_opcode::DUP11] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(11);
        opcodes[zkevm_opcode::DUP12] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(12);
        opcodes[zkevm_opcode::DUP13] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(13);
        opcodes[zkevm_opcode::DUP14] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(14);
        opcodes[zkevm_opcode::DUP15] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(15);
        opcodes[zkevm_opcode::DUP16] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(16);

        // SWAP
        opcodes[zkevm_opcode::SWAP1] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(1);
        opcodes[zkevm_opcode::SWAP2] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(2);
        opcodes[zkevm_opcode::SWAP3] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(3);
        opcodes[zkevm_opcode::SWAP4] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(4);
        opcodes[zkevm_opcode::SWAP5] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(5);
        opcodes[zkevm_opcode::SWAP6] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(6);
        opcodes[zkevm_opcode::SWAP7] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(7);
        opcodes[zkevm_opcode::SWAP8] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(8);
        opcodes[zkevm_opcode::SWAP9] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(9);
        opcodes[zkevm_opcode::SWAP10] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(10);
        opcodes[zkevm_opcode::SWAP11] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(11);
        opcodes[zkevm_opcode::SWAP12] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(12);
        opcodes[zkevm_opcode::SWAP13] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(13);
        opcodes[zkevm_opcode::SWAP14] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(14);
        opcodes[zkevm_opcode::SWAP15] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(15);
        opcodes[zkevm_opcode::SWAP16] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(16);

        // // LOG
        // opcodes[zkevm_opcode::LOG0] = std::make_shared<zkevm_logx_operation<BlueprintFieldType>>(0);
        // opcodes[zkevm_opcode::LOG1] = std::make_shared<zkevm_logx_operation<BlueprintFieldType>>(1);
        // opcodes[zkevm_opcode::LOG2] = std::make_shared<zkevm_logx_operation<BlueprintFieldType>>(2);
        // opcodes[zkevm_opcode::LOG3] = std::make_shared<zkevm_logx_operation<BlueprintFieldType>>(3);
        // opcodes[zkevm_opcode::LOG4] = std::make_shared<zkevm_logx_operation<BlueprintFieldType>>(4);

        // opcodes[zkevm_opcode::REVERT] = std::make_shared<zkevm_revert_operation<BlueprintFieldType>>();

        // fake opcodes for errors and padding
        // opcodes[zkevm_opcode::err0] = std::make_shared<zkevm_err0_operation<BlueprintFieldType>>();
        // opcodes[zkevm_opcode::err1] = std::make_shared<zkevm_err1_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::padding] = std::make_shared<zkevm_padding_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::start_block] = std::make_shared<zkevm_start_block_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::start_transaction] = std::make_shared<zkevm_start_transaction_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::start_call] = std::make_shared<zkevm_start_call_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::end_call] = std::make_shared<zkevm_end_call_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::end_transaction] = std::make_shared<zkevm_end_transaction_operation<BlueprintFieldType>>();
        opcodes[zkevm_opcode::end_block] = std::make_shared<zkevm_end_block_operation<BlueprintFieldType>>();
        return opcodes;
    }
}