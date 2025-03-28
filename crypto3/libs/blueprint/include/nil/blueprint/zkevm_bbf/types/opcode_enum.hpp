//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova   <e.tatuzova@nil.foundation>
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

#include <nil/blueprint/components/hashes/keccak/util.hpp> //Move needed utils to bbf
#include <nil/blueprint/bbf/generic.hpp>

#include <nil/blueprint/zkevm_bbf/types/zkevm_state.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_word.hpp>
#include <nil/blueprint/zkevm_bbf/types/opcode_enum.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {

            #define ZKEVM_OPCODE_ENUM(X) \
                X(STOP) \
                X(ADD) \
                X(MUL) \
                X(SUB) \
                X(DIV) \
                X(SDIV) \
                X(MOD) \
                X(SMOD) \
                X(ADDMOD) \
                X(MULMOD) \
                X(EXP) \
                X(SIGNEXTEND) \
                X(LT) \
                X(GT) \
                X(SLT) \
                X(SGT) \
                X(EQ) \
                X(ISZERO) \
                X(AND) \
                X(OR) \
                X(XOR) \
                X(NOT) \
                X(BYTE) \
                X(SHL) \
                X(SHR) \
                X(SAR) \
                X(KECCAK256) \
                X(ADDRESS) \
                X(BALANCE) \
                X(ORIGIN) \
                X(CALLER) \
                X(CALLVALUE) \
                X(CALLDATALOAD) \
                X(CALLDATASIZE) \
                X(CALLDATACOPY) \
                X(CODESIZE) \
                X(CODECOPY) \
                X(GASPRICE) \
                X(EXTCODESIZE) \
                X(EXTCODECOPY) \
                X(RETURNDATASIZE) \
                X(RETURNDATACOPY) \
                X(EXTCODEHASH) \
                X(BLOCKHASH) \
                X(COINBASE) \
                X(TIMESTAMP) \
                X(NUMBER) \
                X(DIFFICULTY) \
                X(GASLIMIT) \
                X(CHAINID) \
                X(SELFBALANCE) \
                X(BASEFEE) \
                X(BLOBHASH) \
                X(BLOBBASEFEE) \
                X(POP) \
                X(MLOAD) \
                X(MSTORE) \
                X(MSTORE8) \
                X(SLOAD) \
                X(SSTORE) \
                X(JUMP) \
                X(JUMPI) \
                X(PC) \
                X(MSIZE) \
                X(GAS) \
                X(JUMPDEST) \
                X(TLOAD) \
                X(TSTORE) \
                X(MCOPY) \
                X(PUSH0) \
                X(PUSH1) \
                X(PUSH2) \
                X(PUSH3) \
                X(PUSH4) \
                X(PUSH5) \
                X(PUSH6) \
                X(PUSH7) \
                X(PUSH8) \
                X(PUSH9) \
                X(PUSH10) \
                X(PUSH11) \
                X(PUSH12) \
                X(PUSH13) \
                X(PUSH14) \
                X(PUSH15) \
                X(PUSH16) \
                X(PUSH17) \
                X(PUSH18) \
                X(PUSH19) \
                X(PUSH20) \
                X(PUSH21) \
                X(PUSH22) \
                X(PUSH23) \
                X(PUSH24) \
                X(PUSH25) \
                X(PUSH26) \
                X(PUSH27) \
                X(PUSH28) \
                X(PUSH29) \
                X(PUSH30) \
                X(PUSH31) \
                X(PUSH32) \
                X(DUP1) \
                X(DUP2) \
                X(DUP3) \
                X(DUP4) \
                X(DUP5) \
                X(DUP6) \
                X(DUP7) \
                X(DUP8) \
                X(DUP9) \
                X(DUP10) \
                X(DUP11) \
                X(DUP12) \
                X(DUP13) \
                X(DUP14) \
                X(DUP15) \
                X(DUP16) \
                X(SWAP1) \
                X(SWAP2) \
                X(SWAP3) \
                X(SWAP4) \
                X(SWAP5) \
                X(SWAP6) \
                X(SWAP7) \
                X(SWAP8) \
                X(SWAP9) \
                X(SWAP10) \
                X(SWAP11) \
                X(SWAP12) \
                X(SWAP13) \
                X(SWAP14) \
                X(SWAP15) \
                X(SWAP16) \
                X(LOG0) \
                X(LOG1) \
                X(LOG2) \
                X(LOG3) \
                X(LOG4) \
                X(CREATE) \
                X(CALL) \
                X(CALLCODE) \
                X(RETURN) \
                X(DELEGATECALL) \
                X(CREATE2) \
                X(STATICCALL) \
                X(REVERT) \
                X(INVALID) \
                X(SELFDESTRUCT) \
                X(err0) \
                X(err1) \
                X(padding) \
                X(start_block) \
                X(start_transaction) \
                X(start_call) \
                X(end_call) \
                X(end_transaction) \
                X(end_block)

            enum zkevm_opcode {
                #define ENUM_DEF(name) name,
                ZKEVM_OPCODE_ENUM(ENUM_DEF)
                #undef ENUM_DEF
            };

            std::uint16_t opcode_number_from_str(const std::string &str){
                if( str == "STOP" ) return 0x00;
                if( str == "ADD" ) return 0x01;
                if( str == "MUL" ) return 0x02;
                if( str == "SUB" ) return 0x03;
                if( str == "DIV" ) return 0x04;
                if( str == "SDIV" ) return 0x05;
                if( str == "MOD" ) return 0x06;
                if( str == "SMOD" ) return 0x07;
                if( str == "ADDMOD" ) return 0x08;
                if( str == "MULMOD" ) return 0x09;
                if( str == "EXP" ) return 0x0a;
                if( str == "SIGNEXTEND" ) return 0x0b;
                if( str == "LT" ) return 0x10;
                if( str == "GT" ) return 0x11;
                if( str == "SLT" ) return 0x12;
                if( str == "SGT" ) return 0x13;
                if( str == "EQ" ) return 0x14;
                if( str == "ISZERO" ) return 0x15;
                if( str == "AND" ) return 0x16;
                if( str == "OR" ) return 0x17;
                if( str == "XOR" ) return 0x18;
                if( str == "NOT" ) return 0x19;
                if( str == "BYTE" ) return 0x1a;
                if( str == "SHL" ) return 0x1b;
                if( str == "SHR" ) return 0x1c;
                if( str == "SAR" ) return 0x1d;
                if( str == "KECCAK256" ) return 0x20;
                if( str == "ADDRESS" ) return 0x30;
                if( str == "BALANCE" ) return 0x31;
                if( str == "ORIGIN" ) return 0x32;
                if( str == "CALLER" ) return 0x33;
                if( str == "CALLVALUE" ) return 0x34;
                if( str == "CALLDATALOAD" ) return 0x35;
                if( str == "CALLDATASIZE" ) return 0x36;
                if( str == "CALLDATACOPY" ) return 0x37;
                if( str == "CODESIZE" ) return 0x38;
                if( str == "CODECOPY" ) return 0x39;
                if( str == "GASPRICE" ) return 0x3a;
                if( str == "EXTCODESIZE" ) return 0x3b;
                if( str == "EXTCODECOPY" ) return 0x3c;
                if( str == "RETURNDATASIZE" ) return 0x3d;
                if( str == "RETURNDATACOPY" ) return 0x3e;
                if( str == "EXTCODEHASH" ) return 0x3f;
                if( str == "BLOCKHASH" ) return 0x40;
                if( str == "COINBASE" ) return 0x41;
                if( str == "TIMESTAMP" ) return 0x42;
                if( str == "NUMBER" ) return 0x43;
                if( str == "DIFFICULTY" ) return 0x44;
                if( str == "GASLIMIT" ) return 0x45;
                if( str == "CHAINID" ) return 0x46;
                if( str == "SELFBALANCE" ) return 0x47;
                if( str == "BASEFEE" ) return 0x48;
                if( str == "BLOBHASH" ) return 0x49;
                if( str == "BLOBBASEFEE" ) return 0x4a;
                if( str == "POP" ) return 0x50;
                if( str == "MLOAD" ) return 0x51;
                if( str == "MSTORE" ) return 0x52;
                if( str == "MSTORE8" ) return 0x53;
                if( str == "SLOAD" ) return 0x54;
                if( str == "SSTORE" ) return 0x55;
                if( str == "JUMP" ) return 0x56;
                if( str == "JUMPI" ) return 0x57;
                if( str == "PC" ) return 0x58;
                if( str == "MSIZE" ) return 0x59;
                if( str == "GAS" ) return 0x5a;
                if( str == "JUMPDEST" ) return 0x5b;
                if( str == "TLOAD" ) return 0x5c;
                if( str == "TSTORE" ) return 0x5d;
                if( str == "MCOPY" ) return 0x5e;
                if( str == "PUSH0" ) return 0x5f;
                if( str == "PUSH1" ) return 0x60;
                if( str == "PUSH2" ) return 0x61;
                if( str == "PUSH3" ) return 0x62;
                if( str == "PUSH4" ) return 0x63;
                if( str == "PUSH5" ) return 0x64;
                if( str == "PUSH6" ) return 0x65;
                if( str == "PUSH7" ) return 0x66;
                if( str == "PUSH8" ) return 0x67;
                if( str == "PUSH9" ) return 0x68;
                if( str == "PUSH10" ) return 0x69;
                if( str == "PUSH11" ) return 0x6a;
                if( str == "PUSH12" ) return 0x6b;
                if( str == "PUSH13" ) return 0x6c;
                if( str == "PUSH14" ) return 0x6d;
                if( str == "PUSH15" ) return 0x6e;
                if( str == "PUSH16" ) return 0x6f;
                if( str == "PUSH17" ) return 0x70;
                if( str == "PUSH18" ) return 0x71;
                if( str == "PUSH19" ) return 0x72;
                if( str == "PUSH20" ) return 0x73;
                if( str == "PUSH21" ) return 0x74;
                if( str == "PUSH22" ) return 0x75;
                if( str == "PUSH23" ) return 0x76;
                if( str == "PUSH24" ) return 0x77;
                if( str == "PUSH25" ) return 0x78;
                if( str == "PUSH26" ) return 0x79;
                if( str == "PUSH27" ) return 0x7a;
                if( str == "PUSH28" ) return 0x7b;
                if( str == "PUSH29" ) return 0x7c;
                if( str == "PUSH30" ) return 0x7d;
                if( str == "PUSH31" ) return 0x7e;
                if( str == "PUSH32" ) return 0x7f;
                if( str == "DUP1" ) return 0x80;
                if( str == "DUP2" ) return 0x81;
                if( str == "DUP3" ) return 0x82;
                if( str == "DUP4" ) return 0x83;
                if( str == "DUP5" ) return 0x84;
                if( str == "DUP6" ) return 0x85;
                if( str == "DUP7" ) return 0x86;
                if( str == "DUP8" ) return 0x87;
                if( str == "DUP9" ) return 0x88;
                if( str == "DUP10" ) return 0x89;
                if( str == "DUP11" ) return 0x8a;
                if( str == "DUP12" ) return 0x8b;
                if( str == "DUP13" ) return 0x8c;
                if( str == "DUP14" ) return 0x8d;
                if( str == "DUP15" ) return 0x8e;
                if( str == "DUP16" ) return 0x8f;
                if( str == "SWAP1" ) return 0x90;
                if( str == "SWAP2" ) return 0x91;
                if( str == "SWAP3" ) return 0x92;
                if( str == "SWAP4" ) return 0x93;
                if( str == "SWAP5" ) return 0x94;
                if( str == "SWAP6" ) return 0x95;
                if( str == "SWAP7" ) return 0x96;
                if( str == "SWAP8" ) return 0x97;
                if( str == "SWAP9" ) return 0x98;
                if( str == "SWAP10" ) return 0x99;
                if( str == "SWAP11" ) return 0x9a;
                if( str == "SWAP12" ) return 0x9b;
                if( str == "SWAP13" ) return 0x9c;
                if( str == "SWAP14" ) return 0x9d;
                if( str == "SWAP15" ) return 0x9e;
                if( str == "SWAP16" ) return 0x9f;
                if( str == "LOG0" ) return 0xa0;
                if( str == "LOG1" ) return 0xa1;
                if( str == "LOG2" ) return 0xa2;
                if( str == "LOG3" ) return 0xa3;
                if( str == "LOG4" ) return 0xa4;
                if( str == "CREATE" ) return 0xf0;
                if( str == "CALL" ) return 0xf1;
                if( str == "CALLCODE" ) return 0xf2;
                if( str == "RETURN" ) return 0xf3;
                if( str == "DELEGATECALL" ) return 0xf4;
                if( str == "CREATE2" ) return 0xf5;
                if( str == "STATICCALL" ) return 0xfa;
                if( str == "REVERT" ) return 0xfd;
                if( str == "INVALID" ) return 0xfe;
                if( str == "SELFDESTRUCT" ) return 0xff;
                // these are not real opcodes, they are for exception processing
                if( str == "err0" ) return 0x100; // not enough static gas or incorrect stack size
                if( str == "err1" ) return 0x101; // not enough static gas or incorrect stack size
                if( str == "padding" ) return 0x102; // empty opcode for the fixed circuit size
                if( str == "start_block" ) return 0x103; // start call
                if( str == "start_transaction" ) return 0x104; // start call
                if( str == "start_call" ) return 0x105; // start call
                if( str == "end_call" ) return 0x106; // end call
                if( str == "end_transaction" ) return 0x107; // end call
                if( str == "end_block" ) return 0x108; // end call
                std::cout << "Unknown opcode: " << str << std::endl;
                BOOST_ASSERT(false);
                return 0x102;
            }

            zkevm_opcode opcode_from_number(std::size_t number){
                if( number == 0x00) return zkevm_opcode::STOP;
                if( number == 0x01 ) return zkevm_opcode::ADD;
                if( number == 0x02 ) return zkevm_opcode::MUL;
                if( number ==  0x03) return zkevm_opcode::SUB;
                if( number ==  0x04) return zkevm_opcode::DIV;
                if( number ==  0x05) return zkevm_opcode::SDIV;
                if( number ==  0x06) return zkevm_opcode::MOD;
                if( number ==  0x07) return zkevm_opcode::SMOD;
                if( number ==  0x08) return zkevm_opcode::ADDMOD;
                if( number ==  0x09) return zkevm_opcode::MULMOD;
                if( number ==  0x0a) return zkevm_opcode::EXP;
                if( number ==  0x0b) return zkevm_opcode::SIGNEXTEND;
                if( number ==  0x10) return zkevm_opcode::LT;
                if( number ==  0x11) return zkevm_opcode::GT;
                if( number ==  0x12) return zkevm_opcode::SLT;
                if( number ==  0x13) return zkevm_opcode::SGT;
                if( number ==  0x14) return zkevm_opcode::EQ;
                if( number ==  0x15) return zkevm_opcode::ISZERO;
                if( number ==  0x16) return zkevm_opcode::AND;
                if( number ==  0x17) return zkevm_opcode::OR;
                if( number ==  0x18) return zkevm_opcode::XOR;
                if( number ==  0x19) return zkevm_opcode::NOT;
                if( number ==  0x1a) return zkevm_opcode::BYTE;
                if( number ==  0x1b) return zkevm_opcode::SHL;
                if( number ==  0x1c) return zkevm_opcode::SHR;
                if( number ==  0x1d) return zkevm_opcode::SAR;
                if( number ==  0x20) return zkevm_opcode::KECCAK256;
                if( number ==  0x30) return zkevm_opcode::ADDRESS;
                if( number ==  0x31) return zkevm_opcode::BALANCE;
                if( number ==  0x32) return zkevm_opcode::ORIGIN;
                if( number ==  0x33) return zkevm_opcode::CALLER;
                if( number ==  0x34) return zkevm_opcode::CALLVALUE;
                if( number ==  0x35) return zkevm_opcode::CALLDATALOAD;
                if( number ==  0x36) return zkevm_opcode::CALLDATASIZE;
                if( number ==  0x37) return zkevm_opcode::CALLDATACOPY;
                if( number ==  0x38) return zkevm_opcode::CODESIZE;
                if( number ==  0x39) return zkevm_opcode::CODECOPY;
                if( number ==  0x3a) return zkevm_opcode::GASPRICE;
                if( number ==  0x3b) return zkevm_opcode::EXTCODESIZE;
                if( number ==  0x3c) return zkevm_opcode::EXTCODECOPY;
                if( number ==  0x3d) return zkevm_opcode::RETURNDATASIZE;
                if( number ==  0x3e) return zkevm_opcode::RETURNDATACOPY;
                if( number ==  0x3f) return zkevm_opcode::EXTCODEHASH;
                if( number ==  0x40) return zkevm_opcode::BLOCKHASH;
                if( number ==  0x41) return zkevm_opcode::COINBASE;
                if( number ==  0x42) return zkevm_opcode::TIMESTAMP;
                if( number ==  0x43) return zkevm_opcode::NUMBER;
                if( number ==  0x44) return zkevm_opcode::DIFFICULTY;
                if( number ==  0x45) return zkevm_opcode::GASLIMIT;
                if( number ==  0x46) return zkevm_opcode::CHAINID;
                if( number ==  0x47) return zkevm_opcode::SELFBALANCE;
                if( number ==  0x48) return zkevm_opcode::BASEFEE;
                if( number ==  0x49) return zkevm_opcode::BLOBHASH;
                if( number ==  0x4a) return zkevm_opcode::BLOBBASEFEE;
                if( number ==  0x50) return zkevm_opcode::POP;
                if( number ==  0x51) return zkevm_opcode::MLOAD;
                if( number ==  0x52) return zkevm_opcode::MSTORE;
                if( number ==  0x53) return zkevm_opcode::MSTORE8;
                if( number ==  0x54) return zkevm_opcode::SLOAD;
                if( number ==  0x55) return zkevm_opcode::SSTORE;
                if( number ==  0x56) return zkevm_opcode::JUMP;
                if( number ==  0x57) return zkevm_opcode::JUMPI;
                if( number ==  0x58) return zkevm_opcode::PC;
                if( number ==  0x59) return zkevm_opcode::MSIZE;
                if( number ==  0x5a) return zkevm_opcode::GAS;
                if( number ==  0x5b) return zkevm_opcode::JUMPDEST;
                if( number ==  0x5c) return zkevm_opcode::TLOAD;
                if( number ==  0x5d) return zkevm_opcode::TSTORE;
                if( number ==  0x5e) return zkevm_opcode::MCOPY;
                if( number ==  0x5f) return zkevm_opcode::PUSH0;
                if( number ==  0x60) return zkevm_opcode::PUSH1;
                if( number ==  0x61) return zkevm_opcode::PUSH2;
                if( number ==  0x62) return zkevm_opcode::PUSH3;
                if( number ==  0x63) return zkevm_opcode::PUSH4;
                if( number ==  0x64) return zkevm_opcode::PUSH5;
                if( number ==  0x65) return zkevm_opcode::PUSH6;
                if( number ==  0x66) return zkevm_opcode::PUSH7;
                if( number ==  0x67) return zkevm_opcode::PUSH8;
                if( number ==  0x68) return zkevm_opcode::PUSH9;
                if( number ==  0x69) return zkevm_opcode::PUSH10;
                if( number ==  0x6a) return zkevm_opcode::PUSH11;
                if( number ==  0x6b) return zkevm_opcode::PUSH12;
                if( number ==  0x6c) return zkevm_opcode::PUSH13;
                if( number ==  0x6d) return zkevm_opcode::PUSH14;
                if( number ==  0x6e) return zkevm_opcode::PUSH15;
                if( number ==  0x6f) return zkevm_opcode::PUSH16;
                if( number ==  0x70) return zkevm_opcode::PUSH17;
                if( number ==  0x71) return zkevm_opcode::PUSH18;
                if( number ==  0x72) return zkevm_opcode::PUSH19;
                if( number ==  0x73) return zkevm_opcode::PUSH20;
                if( number ==  0x74) return zkevm_opcode::PUSH21;
                if( number ==  0x75) return zkevm_opcode::PUSH22;
                if( number ==  0x76) return zkevm_opcode::PUSH23;
                if( number ==  0x77) return zkevm_opcode::PUSH24;
                if( number ==  0x78) return zkevm_opcode::PUSH25;
                if( number ==  0x79) return zkevm_opcode::PUSH26;
                if( number ==  0x7a) return zkevm_opcode::PUSH27;
                if( number ==  0x7b) return zkevm_opcode::PUSH28;
                if( number ==  0x7c) return zkevm_opcode::PUSH29;
                if( number ==  0x7d) return zkevm_opcode::PUSH30;
                if( number ==  0x7e) return zkevm_opcode::PUSH31;
                if( number ==  0x7f) return zkevm_opcode::PUSH32;
                if( number ==  0x80) return zkevm_opcode::DUP1;
                if( number ==  0x81) return zkevm_opcode::DUP2;
                if( number ==  0x82) return zkevm_opcode::DUP3;
                if( number ==  0x83) return zkevm_opcode::DUP4;
                if( number ==  0x84) return zkevm_opcode::DUP5;
                if( number ==  0x85) return zkevm_opcode::DUP6;
                if( number ==  0x86) return zkevm_opcode::DUP7;
                if( number ==  0x87) return zkevm_opcode::DUP8;
                if( number ==  0x88) return zkevm_opcode::DUP9;
                if( number ==  0x89) return zkevm_opcode::DUP10;
                if( number ==  0x8a) return zkevm_opcode::DUP11;
                if( number ==  0x8b) return zkevm_opcode::DUP12;
                if( number ==  0x8c) return zkevm_opcode::DUP13;
                if( number ==  0x8d) return zkevm_opcode::DUP14;
                if( number ==  0x8e) return zkevm_opcode::DUP15;
                if( number ==  0x8f) return zkevm_opcode::DUP16;
                if( number ==  0x90) return zkevm_opcode::SWAP1;
                if( number ==  0x91) return zkevm_opcode::SWAP2;
                if( number ==  0x92) return zkevm_opcode::SWAP3;
                if( number ==  0x93) return zkevm_opcode::SWAP4;
                if( number ==  0x94) return zkevm_opcode::SWAP5;
                if( number ==  0x95) return zkevm_opcode::SWAP6;
                if( number ==  0x96) return zkevm_opcode::SWAP7;
                if( number ==  0x97) return zkevm_opcode::SWAP8;
                if( number ==  0x98) return zkevm_opcode::SWAP9;
                if( number ==  0x99) return zkevm_opcode::SWAP10;
                if( number ==  0x9a) return zkevm_opcode::SWAP11;
                if( number ==  0x9b) return zkevm_opcode::SWAP12;
                if( number ==  0x9c) return zkevm_opcode::SWAP13;
                if( number ==  0x9d) return zkevm_opcode::SWAP14;
                if( number ==  0x9e) return zkevm_opcode::SWAP15;
                if( number ==  0x9f) return zkevm_opcode::SWAP16;
                if( number ==  0xa0) return zkevm_opcode::LOG0;
                if( number ==  0xa1) return zkevm_opcode::LOG1;
                if( number ==  0xa2) return zkevm_opcode::LOG2;
                if( number ==  0xa3) return zkevm_opcode::LOG3;
                if( number ==  0xa4) return zkevm_opcode::LOG4;
                if( number ==  0xf0) return zkevm_opcode::CREATE;
                if( number ==  0xf1) return zkevm_opcode::CALL;
                if( number ==  0xf2) return zkevm_opcode::CALLCODE;
                if( number ==  0xf3) return zkevm_opcode::RETURN;
                if( number ==  0xf4) return zkevm_opcode::DELEGATECALL;
                if( number ==  0xf5) return zkevm_opcode::CREATE2;
                if( number ==  0xfa) return zkevm_opcode::STATICCALL;
                if( number ==  0xfd) return zkevm_opcode::REVERT;
                if( number ==  0xfe) return zkevm_opcode::INVALID;
                if( number ==  0xff) return zkevm_opcode::SELFDESTRUCT;
                // these are not real opcodes, they are for exception processing
                if( number == 0x100 ) return zkevm_opcode::err0; // incorrect stack size
                if( number == 0x101 ) return zkevm_opcode::err1; // not enough gas
                if( number == 0x102 ) return zkevm_opcode::padding; // empty opcode for the fixed circuit size
                if( number == 0x103 ) return zkevm_opcode::start_block; // opcode for start call
                if( number == 0x104 ) return zkevm_opcode::start_transaction; // opcode for start call
                if( number == 0x105 ) return zkevm_opcode::start_call; // opcode for start call
                if( number == 0x106 ) return zkevm_opcode::end_call; // opcode for end call
                if( number == 0x107 ) return zkevm_opcode::end_transaction; // opcode for end call
                if( number == 0x108 ) return zkevm_opcode::end_block; // opcode for end call
                std::cout << "Unknown opcode " << std::hex << number << std::dec << std::endl;
                BOOST_ASSERT(false);
                return zkevm_opcode::padding;
            }

            zkevm_opcode  opcode_from_str(const std::string &str){
                // these are not real opcodes, they are for exception processing
                #define ENUM_DEF(name) if(str == #name) return zkevm_opcode::name;
                ZKEVM_OPCODE_ENUM(ENUM_DEF)
                #undef ENUM_DEF
                std::cout << "Unknown opcode " << str << std::endl;
                return zkevm_opcode::err0; // not enough static gas or incorrect stack size
            }

            std::string opcode_to_string(const zkevm_opcode& opcode) {
                switch (opcode) {
                    #define ENUM_DEF(name) case zkevm_opcode::name: return #name;
                    ZKEVM_OPCODE_ENUM(ENUM_DEF)
                    #undef ENUM_DEF
                }
                return "unknown";
            }

            std::size_t opcode_to_number(const zkevm_opcode &opcode ){
                return opcode_number_from_str(opcode_to_string(opcode));
            }

            std::ostream& operator<<(std::ostream& os, const zkevm_opcode& opcode) {
                #define ENUM_DEF(name) case zkevm_opcode::name: os << "zkevm_opcode::" << #name; break;
                switch (opcode) {
                    ZKEVM_OPCODE_ENUM(ENUM_DEF)
                }
                #undef ENUM_DEF
                return os;
            }

            std::vector<zkevm_opcode> get_implemented_opcodes_list(){
                std::vector<zkevm_opcode> result;
                #define ENUM_DEF(name) result.push_back(zkevm_opcode::name);
                    ZKEVM_OPCODE_ENUM(ENUM_DEF)
                #undef ENUM_DEF
                return result;
            }
        } // namespace bbf
    } // namespace blueprint
} // namespace nil
