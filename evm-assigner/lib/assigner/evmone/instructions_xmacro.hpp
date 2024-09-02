// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// The default macro for ON_OPCODE_IDENTIFIER. It redirects to ON_OPCODE.
#define ON_OPCODE_IDENTIFIER_DEFAULT(OPCODE, NAME) ON_OPCODE(OPCODE)

/// The default macro for ON_OPCODE_UNDEFINED. Empty implementation to ignore undefined opcodes.
#define ON_OPCODE_UNDEFINED_DEFAULT(OPCODE)


#define ON_OPCODE_IDENTIFIER ON_OPCODE_IDENTIFIER_DEFAULT
#define ON_OPCODE_UNDEFINED ON_OPCODE_UNDEFINED_DEFAULT


/// The "X Macro" for opcodes and their matching identifiers.
///
/// The MAP_OPCODES is an extended variant of X Macro idiom.
/// It has 3 knobs for users.
///
/// 1. The ON_OPCODE(OPCODE) macro must be defined. It will receive all defined opcodes from
///    the evmc_opcode enum.
/// 2. The ON_OPCODE_UNDEFINED(OPCODE) macro may be defined to receive
///    the values of all undefined opcodes.
///    This macro is by default alias to ON_OPCODE_UNDEFINED_DEFAULT therefore users must first
///    undef it and restore the alias after usage.
/// 3. The ON_OPCODE_IDENTIFIER(OPCODE, IDENTIFIER) macro may be defined to receive
///    the pairs of all defined opcodes and their matching identifiers.
///    This macro is by default alias to ON_OPCODE_IDENTIFIER_DEFAULT therefore users must first
///    undef it and restore the alias after usage.
///
/// See for more about X Macros: https://en.wikipedia.org/wiki/X_Macro.
#define MAP_OPCODES                                         \
    ON_OPCODE_IDENTIFIER(OP_STOP, instructions<BlueprintFieldType>::stop)                     \
    ON_OPCODE_IDENTIFIER(OP_ADD, instructions<BlueprintFieldType>::add)                       \
    ON_OPCODE_IDENTIFIER(OP_MUL, instructions<BlueprintFieldType>::mul)                       \
    ON_OPCODE_IDENTIFIER(OP_SUB, instructions<BlueprintFieldType>::sub)                       \
    ON_OPCODE_IDENTIFIER(OP_DIV, instructions<BlueprintFieldType>::div)                       \
    ON_OPCODE_IDENTIFIER(OP_SDIV, instructions<BlueprintFieldType>::sdiv)                     \
    ON_OPCODE_IDENTIFIER(OP_MOD, instructions<BlueprintFieldType>::mod)                       \
    ON_OPCODE_IDENTIFIER(OP_SMOD, instructions<BlueprintFieldType>::smod)                     \
    ON_OPCODE_IDENTIFIER(OP_ADDMOD, instructions<BlueprintFieldType>::addmod)                 \
    ON_OPCODE_IDENTIFIER(OP_MULMOD, instructions<BlueprintFieldType>::mulmod)                 \
    ON_OPCODE_IDENTIFIER(OP_EXP, instructions<BlueprintFieldType>::exp)                       \
    ON_OPCODE_IDENTIFIER(OP_SIGNEXTEND, instructions<BlueprintFieldType>::signextend)         \
    ON_OPCODE_UNDEFINED(0x0c)                               \
    ON_OPCODE_UNDEFINED(0x0d)                               \
    ON_OPCODE_UNDEFINED(0x0e)                               \
    ON_OPCODE_UNDEFINED(0x0f)                               \
                                                            \
    ON_OPCODE_IDENTIFIER(OP_LT, instructions<BlueprintFieldType>::lt)                         \
    ON_OPCODE_IDENTIFIER(OP_GT, instructions<BlueprintFieldType>::gt)                         \
    ON_OPCODE_IDENTIFIER(OP_SLT, instructions<BlueprintFieldType>::slt)                       \
    ON_OPCODE_IDENTIFIER(OP_SGT, instructions<BlueprintFieldType>::sgt)                       \
    ON_OPCODE_IDENTIFIER(OP_EQ, instructions<BlueprintFieldType>::eq)                         \
    ON_OPCODE_IDENTIFIER(OP_ISZERO, instructions<BlueprintFieldType>::iszero)                 \
    ON_OPCODE_IDENTIFIER(OP_AND, instructions<BlueprintFieldType>::and_)                      \
    ON_OPCODE_IDENTIFIER(OP_OR, instructions<BlueprintFieldType>::or_)                        \
    ON_OPCODE_IDENTIFIER(OP_XOR, instructions<BlueprintFieldType>::xor_)                      \
    ON_OPCODE_IDENTIFIER(OP_NOT, instructions<BlueprintFieldType>::not_)                      \
    ON_OPCODE_IDENTIFIER(OP_BYTE, instructions<BlueprintFieldType>::byte)                     \
    ON_OPCODE_IDENTIFIER(OP_SHL, instructions<BlueprintFieldType>::shl)                       \
    ON_OPCODE_IDENTIFIER(OP_SHR, instructions<BlueprintFieldType>::shr)                       \
    ON_OPCODE_IDENTIFIER(OP_SAR, instructions<BlueprintFieldType>::sar)                       \
    ON_OPCODE_UNDEFINED(0x1e)                               \
    ON_OPCODE_UNDEFINED(0x1f)                               \
                                                            \
    ON_OPCODE_IDENTIFIER(OP_KECCAK256, instructions<BlueprintFieldType>::keccak256)           \
    ON_OPCODE_UNDEFINED(0x21)                               \
    ON_OPCODE_UNDEFINED(0x22)                               \
    ON_OPCODE_UNDEFINED(0x23)                               \
    ON_OPCODE_UNDEFINED(0x24)                               \
    ON_OPCODE_UNDEFINED(0x25)                               \
    ON_OPCODE_UNDEFINED(0x26)                               \
    ON_OPCODE_UNDEFINED(0x27)                               \
    ON_OPCODE_UNDEFINED(0x28)                               \
    ON_OPCODE_UNDEFINED(0x29)                               \
    ON_OPCODE_UNDEFINED(0x2a)                               \
    ON_OPCODE_UNDEFINED(0x2b)                               \
    ON_OPCODE_UNDEFINED(0x2c)                               \
    ON_OPCODE_UNDEFINED(0x2d)                               \
    ON_OPCODE_UNDEFINED(0x2e)                               \
    ON_OPCODE_UNDEFINED(0x2f)                               \
                                                            \
    ON_OPCODE_IDENTIFIER(OP_ADDRESS, instructions<BlueprintFieldType>::address)               \
    ON_OPCODE_IDENTIFIER(OP_BALANCE, instructions<BlueprintFieldType>::balance)               \
    ON_OPCODE_IDENTIFIER(OP_ORIGIN, instructions<BlueprintFieldType>::origin)                 \
    ON_OPCODE_IDENTIFIER(OP_CALLER, instructions<BlueprintFieldType>::caller)                 \
    ON_OPCODE_IDENTIFIER(OP_CALLVALUE, instructions<BlueprintFieldType>::callvalue)           \
    ON_OPCODE_IDENTIFIER(OP_CALLDATALOAD, instructions<BlueprintFieldType>::calldataload)     \
    ON_OPCODE_IDENTIFIER(OP_CALLDATASIZE, instructions<BlueprintFieldType>::calldatasize)     \
    ON_OPCODE_IDENTIFIER(OP_CALLDATACOPY, instructions<BlueprintFieldType>::calldatacopy)     \
    ON_OPCODE_IDENTIFIER(OP_CODESIZE, instructions<BlueprintFieldType>::codesize)             \
    ON_OPCODE_IDENTIFIER(OP_CODECOPY, instructions<BlueprintFieldType>::codecopy)             \
    ON_OPCODE_IDENTIFIER(OP_GASPRICE, instructions<BlueprintFieldType>::gasprice)             \
    ON_OPCODE_IDENTIFIER(OP_EXTCODESIZE, instructions<BlueprintFieldType>::extcodesize)       \
    ON_OPCODE_IDENTIFIER(OP_EXTCODECOPY, instructions<BlueprintFieldType>::extcodecopy)       \
    ON_OPCODE_IDENTIFIER(OP_RETURNDATASIZE, instructions<BlueprintFieldType>::returndatasize) \
    ON_OPCODE_IDENTIFIER(OP_RETURNDATACOPY, instructions<BlueprintFieldType>::returndatacopy) \
    ON_OPCODE_IDENTIFIER(OP_EXTCODEHASH, instructions<BlueprintFieldType>::extcodehash)       \
                                                            \
    ON_OPCODE_IDENTIFIER(OP_BLOCKHASH, instructions<BlueprintFieldType>::blockhash)           \
    ON_OPCODE_IDENTIFIER(OP_COINBASE, instructions<BlueprintFieldType>::coinbase)             \
    ON_OPCODE_IDENTIFIER(OP_TIMESTAMP, instructions<BlueprintFieldType>::timestamp)           \
    ON_OPCODE_IDENTIFIER(OP_NUMBER, instructions<BlueprintFieldType>::number)                 \
    ON_OPCODE_IDENTIFIER(OP_PREVRANDAO, instructions<BlueprintFieldType>::prevrandao)         \
    ON_OPCODE_IDENTIFIER(OP_GASLIMIT, instructions<BlueprintFieldType>::gaslimit)             \
    ON_OPCODE_IDENTIFIER(OP_CHAINID, instructions<BlueprintFieldType>::chainid)               \
    ON_OPCODE_IDENTIFIER(OP_SELFBALANCE, instructions<BlueprintFieldType>::selfbalance)       \
    ON_OPCODE_IDENTIFIER(OP_BASEFEE, instructions<BlueprintFieldType>::basefee)               \
    ON_OPCODE_IDENTIFIER(OP_BLOBHASH, instructions<BlueprintFieldType>::blobhash)             \
    ON_OPCODE_IDENTIFIER(OP_BLOBBASEFEE, instructions<BlueprintFieldType>::blobbasefee)       \
    ON_OPCODE_UNDEFINED(0x4b)                               \
    ON_OPCODE_UNDEFINED(0x4c)                               \
    ON_OPCODE_UNDEFINED(0x4d)                               \
    ON_OPCODE_UNDEFINED(0x4e)                               \
    ON_OPCODE_UNDEFINED(0x4f)                               \
                                                            \
    ON_OPCODE_IDENTIFIER(OP_POP, instructions<BlueprintFieldType>::pop)                       \
    ON_OPCODE_IDENTIFIER(OP_MLOAD, instructions<BlueprintFieldType>::template mload<typename nil::evm_assigner::zkevm_word<BlueprintFieldType>::value_type>)          \
    ON_OPCODE_IDENTIFIER(OP_MLOAD8, instructions<BlueprintFieldType>::template mload<uint8_t>)         \
    ON_OPCODE_IDENTIFIER(OP_MLOAD16, instructions<BlueprintFieldType>::template mload<uint16_t>)       \
    ON_OPCODE_IDENTIFIER(OP_MLOAD32, instructions<BlueprintFieldType>::template mload<uint32_t>)       \
    ON_OPCODE_IDENTIFIER(OP_MLOAD64, instructions<BlueprintFieldType>::template mload<uint64_t>)       \
    ON_OPCODE_IDENTIFIER(OP_MSTORE, instructions<BlueprintFieldType>::template mstore<typename nil::evm_assigner::zkevm_word<BlueprintFieldType>::value_type>)        \
    ON_OPCODE_IDENTIFIER(OP_MSTORE8, instructions<BlueprintFieldType>::template mstore<uint8_t>)       \
    ON_OPCODE_IDENTIFIER(OP_MSTORE16, instructions<BlueprintFieldType>::template mstore<uint16_t>)     \
    ON_OPCODE_IDENTIFIER(OP_MSTORE32, instructions<BlueprintFieldType>::template mstore<uint32_t>)     \
    ON_OPCODE_IDENTIFIER(OP_MSTORE64, instructions<BlueprintFieldType>::template mstore<uint64_t>)     \
    ON_OPCODE_IDENTIFIER(OP_SLOAD, instructions<BlueprintFieldType>::sload)                   \
    ON_OPCODE_IDENTIFIER(OP_SSTORE, instructions<BlueprintFieldType>::sstore)                 \
    ON_OPCODE_IDENTIFIER(OP_JUMP, instructions<BlueprintFieldType>::jump)                     \
    ON_OPCODE_IDENTIFIER(OP_JUMPI, instructions<BlueprintFieldType>::jumpi)                   \
    ON_OPCODE_IDENTIFIER(OP_PC, instructions<BlueprintFieldType>::pc)                         \
    ON_OPCODE_IDENTIFIER(OP_MSIZE, instructions<BlueprintFieldType>::msize)                   \
    ON_OPCODE_IDENTIFIER(OP_GAS, instructions<BlueprintFieldType>::gas)                       \
    ON_OPCODE_IDENTIFIER(OP_JUMPDEST, instructions<BlueprintFieldType>::jumpdest)             \
    ON_OPCODE_IDENTIFIER(OP_TLOAD, instructions<BlueprintFieldType>::tload)                   \
    ON_OPCODE_IDENTIFIER(OP_TSTORE, instructions<BlueprintFieldType>::tstore)                 \
    ON_OPCODE_IDENTIFIER(OP_MCOPY, instructions<BlueprintFieldType>::mcopy)                   \
    ON_OPCODE_IDENTIFIER(OP_PUSH0, instructions<BlueprintFieldType>::push0)                   \
                                                            \
    ON_OPCODE_IDENTIFIER(OP_PUSH1, instructions<BlueprintFieldType>::template push<1>)                 \
    ON_OPCODE_IDENTIFIER(OP_PUSH2, instructions<BlueprintFieldType>::template push<2>)                 \
    ON_OPCODE_IDENTIFIER(OP_PUSH3, instructions<BlueprintFieldType>::template push<3>)                 \
    ON_OPCODE_IDENTIFIER(OP_PUSH4, instructions<BlueprintFieldType>::template push<4>)                 \
    ON_OPCODE_IDENTIFIER(OP_PUSH5, instructions<BlueprintFieldType>::template push<5>)                 \
    ON_OPCODE_IDENTIFIER(OP_PUSH6, instructions<BlueprintFieldType>::template push<6>)                 \
    ON_OPCODE_IDENTIFIER(OP_PUSH7, instructions<BlueprintFieldType>::template push<7>)                 \
    ON_OPCODE_IDENTIFIER(OP_PUSH8, instructions<BlueprintFieldType>::template push<8>)                 \
    ON_OPCODE_IDENTIFIER(OP_PUSH9, instructions<BlueprintFieldType>::template push<9>)                 \
    ON_OPCODE_IDENTIFIER(OP_PUSH10, instructions<BlueprintFieldType>::template push<10>)               \
    ON_OPCODE_IDENTIFIER(OP_PUSH11, instructions<BlueprintFieldType>::template push<11>)               \
    ON_OPCODE_IDENTIFIER(OP_PUSH12, instructions<BlueprintFieldType>::template push<12>)               \
    ON_OPCODE_IDENTIFIER(OP_PUSH13, instructions<BlueprintFieldType>::template push<13>)               \
    ON_OPCODE_IDENTIFIER(OP_PUSH14, instructions<BlueprintFieldType>::template push<14>)               \
    ON_OPCODE_IDENTIFIER(OP_PUSH15, instructions<BlueprintFieldType>::template push<15>)               \
                                                            \
    ON_OPCODE_IDENTIFIER(OP_PUSH16, instructions<BlueprintFieldType>::template push<16>)               \
    ON_OPCODE_IDENTIFIER(OP_PUSH17, instructions<BlueprintFieldType>::template push<17>)               \
    ON_OPCODE_IDENTIFIER(OP_PUSH18, instructions<BlueprintFieldType>::template push<18>)               \
    ON_OPCODE_IDENTIFIER(OP_PUSH19, instructions<BlueprintFieldType>::template push<19>)               \
    ON_OPCODE_IDENTIFIER(OP_PUSH20, instructions<BlueprintFieldType>::template push<20>)               \
    ON_OPCODE_IDENTIFIER(OP_PUSH21, instructions<BlueprintFieldType>::template push<21>)               \
    ON_OPCODE_IDENTIFIER(OP_PUSH22, instructions<BlueprintFieldType>::template push<22>)               \
    ON_OPCODE_IDENTIFIER(OP_PUSH23, instructions<BlueprintFieldType>::template push<23>)               \
    ON_OPCODE_IDENTIFIER(OP_PUSH24, instructions<BlueprintFieldType>::template push<24>)               \
    ON_OPCODE_IDENTIFIER(OP_PUSH25, instructions<BlueprintFieldType>::template push<25>)               \
    ON_OPCODE_IDENTIFIER(OP_PUSH26, instructions<BlueprintFieldType>::template push<26>)               \
    ON_OPCODE_IDENTIFIER(OP_PUSH27, instructions<BlueprintFieldType>::template push<27>)               \
    ON_OPCODE_IDENTIFIER(OP_PUSH28, instructions<BlueprintFieldType>::template push<28>)               \
    ON_OPCODE_IDENTIFIER(OP_PUSH29, instructions<BlueprintFieldType>::template push<29>)               \
    ON_OPCODE_IDENTIFIER(OP_PUSH30, instructions<BlueprintFieldType>::template push<30>)               \
    ON_OPCODE_IDENTIFIER(OP_PUSH31, instructions<BlueprintFieldType>::template push<31>)               \
    ON_OPCODE_IDENTIFIER(OP_PUSH32, instructions<BlueprintFieldType>::template push<32>)               \
                                                            \
    ON_OPCODE_IDENTIFIER(OP_DUP1, instructions<BlueprintFieldType>::template dup<1>)                   \
    ON_OPCODE_IDENTIFIER(OP_DUP2, instructions<BlueprintFieldType>::template dup<2>)                   \
    ON_OPCODE_IDENTIFIER(OP_DUP3, instructions<BlueprintFieldType>::template dup<3>)                   \
    ON_OPCODE_IDENTIFIER(OP_DUP4, instructions<BlueprintFieldType>::template dup<4>)                   \
    ON_OPCODE_IDENTIFIER(OP_DUP5, instructions<BlueprintFieldType>::template dup<5>)                   \
    ON_OPCODE_IDENTIFIER(OP_DUP6, instructions<BlueprintFieldType>::template dup<6>)                   \
    ON_OPCODE_IDENTIFIER(OP_DUP7, instructions<BlueprintFieldType>::template dup<7>)                   \
    ON_OPCODE_IDENTIFIER(OP_DUP8, instructions<BlueprintFieldType>::template dup<8>)                   \
    ON_OPCODE_IDENTIFIER(OP_DUP9, instructions<BlueprintFieldType>::template dup<9>)                   \
    ON_OPCODE_IDENTIFIER(OP_DUP10, instructions<BlueprintFieldType>::template dup<10>)                 \
    ON_OPCODE_IDENTIFIER(OP_DUP11, instructions<BlueprintFieldType>::template dup<11>)                 \
    ON_OPCODE_IDENTIFIER(OP_DUP12, instructions<BlueprintFieldType>::template dup<12>)                 \
    ON_OPCODE_IDENTIFIER(OP_DUP13, instructions<BlueprintFieldType>::template dup<13>)                 \
    ON_OPCODE_IDENTIFIER(OP_DUP14, instructions<BlueprintFieldType>::template dup<14>)                 \
    ON_OPCODE_IDENTIFIER(OP_DUP15, instructions<BlueprintFieldType>::template dup<15>)                 \
    ON_OPCODE_IDENTIFIER(OP_DUP16, instructions<BlueprintFieldType>::template dup<16>)                 \
                                                            \
    ON_OPCODE_IDENTIFIER(OP_SWAP1, instructions<BlueprintFieldType>::template swap<1>)                 \
    ON_OPCODE_IDENTIFIER(OP_SWAP2, instructions<BlueprintFieldType>::template swap<2>)                 \
    ON_OPCODE_IDENTIFIER(OP_SWAP3, instructions<BlueprintFieldType>::template swap<3>)                 \
    ON_OPCODE_IDENTIFIER(OP_SWAP4, instructions<BlueprintFieldType>::template swap<4>)                 \
    ON_OPCODE_IDENTIFIER(OP_SWAP5, instructions<BlueprintFieldType>::template swap<5>)                 \
    ON_OPCODE_IDENTIFIER(OP_SWAP6, instructions<BlueprintFieldType>::template swap<6>)                 \
    ON_OPCODE_IDENTIFIER(OP_SWAP7, instructions<BlueprintFieldType>::template swap<7>)                 \
    ON_OPCODE_IDENTIFIER(OP_SWAP8, instructions<BlueprintFieldType>::template swap<8>)                 \
    ON_OPCODE_IDENTIFIER(OP_SWAP9, instructions<BlueprintFieldType>::template swap<9>)                 \
    ON_OPCODE_IDENTIFIER(OP_SWAP10, instructions<BlueprintFieldType>::template swap<10>)               \
    ON_OPCODE_IDENTIFIER(OP_SWAP11, instructions<BlueprintFieldType>::template swap<11>)               \
    ON_OPCODE_IDENTIFIER(OP_SWAP12, instructions<BlueprintFieldType>::template swap<12>)               \
    ON_OPCODE_IDENTIFIER(OP_SWAP13, instructions<BlueprintFieldType>::template swap<13>)               \
    ON_OPCODE_IDENTIFIER(OP_SWAP14, instructions<BlueprintFieldType>::template swap<14>)               \
    ON_OPCODE_IDENTIFIER(OP_SWAP15, instructions<BlueprintFieldType>::template swap<15>)               \
    ON_OPCODE_IDENTIFIER(OP_SWAP16, instructions<BlueprintFieldType>::template swap<16>)               \
                                                            \
    ON_OPCODE_IDENTIFIER(OP_SWAP, instructions<BlueprintFieldType>::template swap<0>)                  \
    ON_OPCODE_IDENTIFIER(OP_DUP, instructions<BlueprintFieldType>::template dup<0>)                    \
    ON_OPCODE_IDENTIFIER(OP_LOG1, instructions<BlueprintFieldType>::log)                    \
    ON_OPCODE_UNDEFINED(0xa8)                               \
    ON_OPCODE_UNDEFINED(0xa9)                               \
    ON_OPCODE_UNDEFINED(0xaa)                               \
    ON_OPCODE_UNDEFINED(0xab)                               \
    ON_OPCODE_UNDEFINED(0xac)                               \
    ON_OPCODE_UNDEFINED(0xad)                               \
    ON_OPCODE_UNDEFINED(0xae)                               \
    ON_OPCODE_UNDEFINED(0xaf)                               \
                                                            \
    ON_OPCODE_UNDEFINED(0xb3)                               \
    ON_OPCODE_UNDEFINED(0xb4)                               \
    ON_OPCODE_UNDEFINED(0xb5)                               \
    ON_OPCODE_UNDEFINED(0xb6)                               \
    ON_OPCODE_UNDEFINED(0xb7)                               \
    ON_OPCODE_UNDEFINED(0xb8)                               \
    ON_OPCODE_UNDEFINED(0xb9)                               \
    ON_OPCODE_UNDEFINED(0xba)                               \
    ON_OPCODE_UNDEFINED(0xbb)                               \
    ON_OPCODE_UNDEFINED(0xbc)                               \
    ON_OPCODE_UNDEFINED(0xbd)                               \
    ON_OPCODE_UNDEFINED(0xbe)                               \
    ON_OPCODE_UNDEFINED(0xbf)                               \
                                                            \
    ON_OPCODE_UNDEFINED(0xc4)                               \
    ON_OPCODE_UNDEFINED(0xc5)                               \
    ON_OPCODE_UNDEFINED(0xc6)                               \
    ON_OPCODE_UNDEFINED(0xc7)                               \
    ON_OPCODE_UNDEFINED(0xc8)                               \
    ON_OPCODE_UNDEFINED(0xc9)                               \
    ON_OPCODE_UNDEFINED(0xca)                               \
    ON_OPCODE_UNDEFINED(0xcb)                               \
    ON_OPCODE_UNDEFINED(0xcc)                               \
    ON_OPCODE_UNDEFINED(0xcd)                               \
    ON_OPCODE_UNDEFINED(0xce)                               \
    ON_OPCODE_UNDEFINED(0xcf)                               \
                                                            \
    ON_OPCODE_UNDEFINED(0xd0)                               \
    ON_OPCODE_UNDEFINED(0xd1)                               \
    ON_OPCODE_UNDEFINED(0xd2)                               \
    ON_OPCODE_UNDEFINED(0xd3)                               \
    ON_OPCODE_UNDEFINED(0xd4)                               \
    ON_OPCODE_UNDEFINED(0xd5)                               \
    ON_OPCODE_UNDEFINED(0xd6)                               \
    ON_OPCODE_UNDEFINED(0xd7)                               \
    ON_OPCODE_UNDEFINED(0xd8)                               \
    ON_OPCODE_UNDEFINED(0xd9)                               \
    ON_OPCODE_UNDEFINED(0xda)                               \
    ON_OPCODE_UNDEFINED(0xdb)                               \
    ON_OPCODE_UNDEFINED(0xdc)                               \
    ON_OPCODE_UNDEFINED(0xdd)                               \
    ON_OPCODE_UNDEFINED(0xde)                               \
    ON_OPCODE_UNDEFINED(0xdf)                               \
                                                            \
    ON_OPCODE_IDENTIFIER(OP_RJUMP, instructions<BlueprintFieldType>::rjump)                   \
    ON_OPCODE_IDENTIFIER(OP_RJUMPI, instructions<BlueprintFieldType>::rjumpi)                 \
    ON_OPCODE_IDENTIFIER(OP_RJUMPV, instructions<BlueprintFieldType>::rjumpv)                 \
    ON_OPCODE_IDENTIFIER(OP_CALLF, instructions<BlueprintFieldType>::callf)                   \
    ON_OPCODE_IDENTIFIER(OP_RETF, instructions<BlueprintFieldType>::retf)                     \
    ON_OPCODE_IDENTIFIER(OP_JUMPF, instructions<BlueprintFieldType>::jumpf)                   \
    ON_OPCODE_IDENTIFIER(OP_DUPN, instructions<BlueprintFieldType>::dupn)                     \
    ON_OPCODE_IDENTIFIER(OP_SWAPN, instructions<BlueprintFieldType>::swapn)                   \
    ON_OPCODE_IDENTIFIER(OP_DATALOAD, instructions<BlueprintFieldType>::dataload)             \
    ON_OPCODE_IDENTIFIER(OP_DATALOADN, instructions<BlueprintFieldType>::dataloadn)           \
    ON_OPCODE_IDENTIFIER(OP_DATASIZE, instructions<BlueprintFieldType>::datasize)             \
    ON_OPCODE_IDENTIFIER(OP_DATACOPY, instructions<BlueprintFieldType>::datacopy)             \
    ON_OPCODE_UNDEFINED(0xec)                               \
    ON_OPCODE_UNDEFINED(0xed)                               \
    ON_OPCODE_UNDEFINED(0xee)                               \
    ON_OPCODE_UNDEFINED(0xef)                               \
                                                            \
    ON_OPCODE_IDENTIFIER(OP_CREATE, instructions<BlueprintFieldType>::create)                 \
    ON_OPCODE_IDENTIFIER(OP_CALL, instructions<BlueprintFieldType>::call)                     \
    ON_OPCODE_IDENTIFIER(OP_CALLCODE, instructions<BlueprintFieldType>::callcode)             \
    ON_OPCODE_IDENTIFIER(OP_RETURN, instructions<BlueprintFieldType>::return_)                \
    ON_OPCODE_IDENTIFIER(OP_DELEGATECALL, instructions<BlueprintFieldType>::delegatecall)     \
    ON_OPCODE_IDENTIFIER(OP_CREATE2, instructions<BlueprintFieldType>::create2)               \
    ON_OPCODE_UNDEFINED(0xf6)                               \
    ON_OPCODE_UNDEFINED(0xf7)                               \
    ON_OPCODE_UNDEFINED(0xf8)                               \
    ON_OPCODE_UNDEFINED(0xf9)                               \
    ON_OPCODE_IDENTIFIER(OP_STATICCALL, instructions<BlueprintFieldType>::staticcall)         \
    ON_OPCODE_UNDEFINED(0xfb)                               \
    ON_OPCODE_UNDEFINED(0xfc)                               \
    ON_OPCODE_IDENTIFIER(OP_REVERT, instructions<BlueprintFieldType>::revert)                 \
    ON_OPCODE_IDENTIFIER(OP_INVALID, instructions<BlueprintFieldType>::invalid)               \
    ON_OPCODE_IDENTIFIER(OP_SELFDESTRUCT, instructions<BlueprintFieldType>::selfdestruct)
