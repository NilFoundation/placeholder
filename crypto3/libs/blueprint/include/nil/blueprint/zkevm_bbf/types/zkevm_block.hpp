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

#include <nil/blueprint/zkevm_bbf/types/zkevm_word.hpp>

// #include <nil/blueprint/zkevm_bbf/util/ptree.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            struct zkevm_block{
                // pre-London
                zkevm_word_type  hash;
                zkevm_word_type  parent_hash;
                zkevm_word_type  sha3_uncles;
                zkevm_word_type  miner;
                zkevm_word_type  state_root;
                zkevm_word_type  tx_root;
                zkevm_word_type  receipts_root;
                zkevm_word_type  mix_hash;
                std::array<zkevm_word_type, 8> logs_bloom;

                std::vector<std::uint8_t>     difficulty;
                std::vector<std::uint8_t>     block_number;
                std::vector<std::uint8_t>     gas_limit;
                std::vector<std::uint8_t>     gas_used;
                std::vector<std::uint8_t>     timestamp;
                std::vector<std::uint8_t>     extra_data;
                std::array<std::uint8_t, 8>   nonce;
                // London
                std::vector<std::uint8_t>     base_fee;
                // Shapella
                zkevm_word_type  withdrawals_root;
                // Dencun
                std::vector<std::uint8_t>     blob_gas_used;
                std::vector<std::uint8_t>     excess_blob_gas;
                zkevm_word_type  parent_beacon_root;
                // Pectra
                zkevm_word_type  requests_hash;

                // fork_type
                std::size_t fork_type;
                std::vector<std::uint8_t>      rlp_encoding;
            };

            bool is_valid_block_header(const zkevm_block &obj){

                if (obj.fork_type > 4) return false;

                bool flag = true;
                flag &= (obj.difficulty.size() <= 7);
                flag &= (obj.block_number.size() <= 4);
                flag &= (obj.gas_limit.size() <= 4);
                flag &= (obj.gas_used.size() <= 4);
                flag &= (obj.timestamp.size() <= 4);
                flag &= (obj.extra_data.size() <= 32);
                if (obj.fork_type == 0){
                    flag &= (obj.base_fee.size() == 0);
                    flag &= (obj.blob_gas_used.size() == 0);
                    flag &= (obj.excess_blob_gas.size() == 0);
                    flag &= (obj.withdrawals_root == zkevm_word_type(0));
                    flag &= (obj.parent_beacon_root == zkevm_word_type(0));
                    flag &= (obj.requests_hash == zkevm_word_type(0));
                }
                if (obj.fork_type > 0){
                    flag &= (obj.base_fee.size() <= 32);
                    flag &= (obj.base_fee.size() > 0);
                }

                if (obj.fork_type > 2){
                    flag &= (obj.blob_gas_used.size() <= 8);
                    flag &= (obj.blob_gas_used.size() >  0);
                    flag &= (obj.excess_blob_gas.size() <= 8);
                    flag &= (obj.excess_blob_gas.size() >  0);
                }

                return flag;
            }

            std::vector<std::uint8_t> encode_rlp(const zkevm_block &obj){
                std::vector<std::uint8_t> rlp;

                
                auto parent_hash = w_to_8(obj.parent_hash);
                auto sha3_uncles = w_to_8(obj.sha3_uncles);
                auto coinbase    = w_to_8(obj.miner);
                auto state_root  = w_to_8(obj.state_root);
                auto tx_root     = w_to_8(obj.tx_root);
                auto receipts_root  = w_to_8(obj.receipts_root);
                auto mix_hash    = w_to_8(obj.mix_hash);

                rlp.push_back(0xa0);
                rlp.insert(rlp.end(), parent_hash.begin(), parent_hash.end());
                rlp.push_back(0xa0);
                rlp.insert(rlp.end(), sha3_uncles.begin(), sha3_uncles.end());
                rlp.push_back(0x94);
                rlp.insert(rlp.end(), coinbase.end() - 20, coinbase.end());
                rlp.push_back(0xa0);
                rlp.insert(rlp.end(), state_root.begin(), state_root.end());
                rlp.push_back(0xa0);
                rlp.insert(rlp.end(), tx_root.begin(), tx_root.end());
                rlp.push_back(0xa0);
                rlp.insert(rlp.end(), receipts_root.begin(), receipts_root.end());
                rlp.push_back(0xb9);
                rlp.push_back(0x01);
                rlp.push_back(0x00);
                for(std::size_t i = 0; i < 8; i++){
                    auto log_bloom = w_to_8(obj.logs_bloom[i]);
                    rlp.insert(rlp.end(), log_bloom.begin(), log_bloom.end());
                }
                rlp.push_back(0x80 + obj.difficulty.size());
                rlp.insert(rlp.end(), obj.difficulty.begin(), obj.difficulty.end());
                rlp.push_back(0x80 + obj.block_number.size());
                rlp.insert(rlp.end(), obj.block_number.begin(), obj.block_number.end());
                rlp.push_back(0x80 + obj.gas_limit.size());
                rlp.insert(rlp.end(), obj.gas_limit.begin(), obj.gas_limit.end());
                rlp.push_back(0x80 + obj.gas_used.size());
                rlp.insert(rlp.end(), obj.gas_used.begin(), obj.gas_used.end());
                rlp.push_back(0x80 + obj.timestamp.size());
                rlp.insert(rlp.end(), obj.timestamp.begin(), obj.timestamp.end());
                rlp.push_back(0x80 + obj.extra_data.size());
                rlp.insert(rlp.end(), obj.extra_data.begin(), obj.extra_data.end());
                rlp.push_back(0xa0);
                rlp.insert(rlp.end(), mix_hash.begin(), mix_hash.end());
                rlp.push_back(0x88);
                rlp.insert(rlp.end(), obj.nonce.begin(), obj.nonce.end());

                if (obj.fork_type >= 1) {
                    rlp.push_back(0x80 + obj.base_fee.size());
                    rlp.insert(rlp.end(), obj.base_fee.begin(), obj.base_fee.end());
                }
                if (obj.fork_type >= 2) {
                    auto w_root = w_to_8(obj.withdrawals_root);
                    rlp.push_back(0xa0);
                    rlp.insert(rlp.end(), w_root.begin(), w_root.end());
                }
                if (obj.fork_type >= 3) {
                    auto pb_root = w_to_8(obj.parent_beacon_root);
                    rlp.push_back(0x80 + obj.blob_gas_used.size());
                    rlp.insert(rlp.end(), obj.blob_gas_used.begin(), obj.blob_gas_used.end());
                    rlp.push_back(0x80 + obj.excess_blob_gas.size());
                    rlp.insert(rlp.end(), obj.excess_blob_gas.begin(), obj.excess_blob_gas.end());
                    
                    rlp.push_back(0xa0);
                    rlp.insert(rlp.end(), pb_root.begin(), pb_root.end());
                }
                if (obj.fork_type == 4) {
                    auto requests_hash = w_to_8(obj.requests_hash);
                    rlp.push_back(0xa0);
                    rlp.insert(rlp.end(), requests_hash.begin(), requests_hash.end());
                }

                
                std::size_t rlp_len = rlp.size();
                BOOST_ASSERT(rlp_len > 55);
                BOOST_ASSERT(rlp_len < 65536);
                std::uint8_t len_hi = std::uint8_t(rlp_len >> 8);
                std::uint8_t len_lo = std::uint8_t(rlp_len & 0xFF);
                std::vector<std::uint8_t> prefix = {0xf9, len_hi, len_lo};
                rlp.insert(rlp.begin(), prefix.begin(), prefix.end()); 

                auto hash = zkevm_keccak_hash(rlp);
                BOOST_ASSERT(hash == obj.hash);
                return rlp;
            }

            std::ostream &operator<<(std::ostream &os, const zkevm_block &obj) {
                std::size_t number = 0;
                for(std::size_t i = 0; i < obj.block_number.size(); i++) {
                    number = (number << 8) | obj.block_number[i];
                }
                os << "Block " << number << std::endl;
                os << "\tblock_hash = 0x" << std::hex << obj.hash << std::dec << std::endl;
                os << "\tparent_hash = 0x" << std::hex << obj.parent_hash << std::dec << std::endl;
                os << "\tsha3_uncles = 0x" << std::hex << obj.sha3_uncles << std::dec << std::endl;
                os << "\tminer = 0x" << std::hex << obj.miner << std::dec << std::endl;
                os << "\tstate_root = 0x" << std::hex << obj.state_root << std::dec << std::endl;
                os << "\ttx_root = 0x" << std::hex << obj.tx_root << std::dec << std::endl;
                os << "\treceipts_root = 0x" << std::hex << obj.receipts_root << std::dec << std::endl;
                for (std::size_t i = 0; i < 8; i++) {
                    os << "\tlogs_bloom_" << i << " = 0x" << std::hex << obj.logs_bloom[i] << std::dec << std::endl;
                }
                os << "\tdifficulty = 0x";
                for (std::size_t i = 0; i < obj.difficulty.size(); i++) {
                    os << std::hex << std::setfill('0') << std::setw(2) << +obj.difficulty[i] << std::dec;
                }
                os << std::endl << "\tnumber = 0x";
                for (std::size_t i = 0; i < obj.block_number.size(); i++) {
                    os << std::hex << std::setfill('0') << std::setw(2) << +obj.block_number[i] << std::dec;
                }
                os << std::endl << "\tgas_limit = 0x";
                for (std::size_t i = 0; i < obj.gas_limit.size(); i++) {
                    os << std::hex << std::setfill('0') << std::setw(2) << +obj.gas_limit[i] << std::dec;
                }
                os << std::endl << "\tgas_used = 0x";
                for (std::size_t i = 0; i < obj.gas_used.size(); i++) {
                    os << std::hex << std::setfill('0') << std::setw(2) << +obj.gas_used[i] << std::dec;
                }
                os << std::endl << "\ttimestamp = 0x";
                for (std::size_t i = 0; i < obj.timestamp.size(); i++) {
                    os << std::hex << std::setfill('0') << std::setw(2) << +obj.timestamp[i] << std::dec;
                }
                os << std::endl << "\textra_data = 0x";
                for (std::size_t i = 0; i < obj.extra_data.size(); i++) {
                    os << std::hex << std::setfill('0') << std::setw(2) << +obj.extra_data[i] << std::dec;
                }
                os  << std::endl << "\tnonce = 0x";
                for (std::size_t i = 0; i < obj.nonce.size(); i++) {
                    os << std::hex << std::setfill('0') << std::setw(2) << +obj.nonce[i] << std::dec;
                }
                os << std::endl;
                if(obj.base_fee.size() > 0 && obj.fork_type > 0){
                    os << "\tbase_fee = 0x";
                    for (std::size_t i = 0; i < obj.base_fee.size(); i++) {
                        os << std::hex << std::setfill('0') << std::setw(2) << +obj.base_fee[i] << std::dec;
                    }
                    os << std::endl;
                }
                if(obj.fork_type > 1) {
                    os << "\twithdrawals_root = 0x" << std::hex << +obj.withdrawals_root << std::dec << std::endl;
                }
                if(obj.fork_type > 2) {
                    os << "\tblob_gas_used = 0x";
                    for (std::size_t i = 0; i < obj.blob_gas_used.size(); i++) {
                        os << std::hex << std::setfill('0') << std::setw(2) << +obj.blob_gas_used[i] << std::dec;
                    }
                    os << std::endl << "\texcess_blob_gas = 0x";
                    for (std::size_t i = 0; i < obj.excess_blob_gas.size(); i++) {
                        os << std::hex << std::setfill('0') << std::setw(2) << +obj.excess_blob_gas[i] << std::dec;
                    }
                    os << std::endl << "\tparent_beacon_root = 0x" << std::hex << obj.parent_beacon_root << std::dec << std::endl;
                }
                if(obj.fork_type > 3) {
                    os << "\trequests_hash = 0x" << std::hex << obj.requests_hash << std::dec << std::endl;
                }

                return os;
            }
        } // namespace bbf
    } // namespace blueprint
} // namespace nil
