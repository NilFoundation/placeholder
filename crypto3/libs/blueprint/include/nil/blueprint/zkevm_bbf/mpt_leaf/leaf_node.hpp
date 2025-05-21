//---------------------------------------------------------------------------//
// Copyright (c) 2025 Alexey Yashunsky <a.yashunsky@nil.foundation>
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

#include <nil/crypto3/bench/scoped_profiler.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/blueprint/zkevm_bbf/types/hashed_buffers.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/util.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/rlp_table.hpp>
// #include <nil/blueprint/zkevm_bbf/subcomponents/mpt_leaf_table.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/keccak_table.hpp>
#include <nil/blueprint/zkevm_bbf/mpt_leaf.hpp>
#include <nil/blueprint/zkevm_bbf/mpt_leaf/node_header.hpp>

namespace nil::blueprint::bbf {

    template<typename FieldType, GenerationStage stage>
    class leaf_node: public node_inner_array<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using RLPTable = typename bbf::rlp_table<FieldType, stage>;
        using KeccakTable = typename bbf::keccak_table<FieldType, stage>;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

    public:
        using typename generic_component<FieldType, stage>::table_params;
        using typename generic_component<FieldType, stage>::TYPE;
        using node_inner = node_inner<FieldType, stage>;
        using node_header = node_header<FieldType, stage>;

        using node_inner_array = node_inner_array<FieldType, stage>;
        using node_header_array = node_header_array<FieldType, stage>;
        using node_inner_string = node_inner_string<FieldType, stage>;
        using storage_trie_value = node_inner_string_container<FieldType, stage>;

        node_inner* key;
        node_inner* value;
        TYPE hash_low;
        TYPE hash_high;
        TYPE node_exists;
        std::size_t rlp_encoding_index = 0;
        TYPE rlc_accumulator = 0;
        TYPE rlc_challenge;
        std::size_t row_index;
        std::vector<std::uint8_t> hash_input;
            
        leaf_node(
            context_type &context_object,
            mpt_type _trie_t,
            TYPE _node_exists,
            TYPE _rlc_challenge,
            std::size_t _row_index
        ): node_inner_array(context_object, _rlc_challenge),
        node_exists(_node_exists),
        rlc_challenge(_rlc_challenge),
        row_index(_row_index) {
            key = new node_inner_string(context_object, _rlc_challenge, 32);
            this->inners.push_back(key);
            if (_trie_t == mpt_type::storage_trie) {
                value = new storage_trie_value(context_object, _rlc_challenge, 32);
            } else {
                // TODO
            }
            this->inners.push_back(value);
        }

        void peek_and_encode_data(std::vector<zkevm_word_type> key_raw, std::vector<zkevm_word_type> value_raw) {

            if (node_exists == 0) {
                key_raw = key->empty();
                value_raw = value->empty();
            }

            std::vector<zkevm_word_type> key_copy(key_raw.begin(), key_raw.end());
            std::vector<zkevm_word_type> value_copy(value_raw.begin(), value_raw.end());
            this->h->peek_and_encode_data(get_rlp_length(key_raw) + get_rlp_length(value_raw), rlp_encoding_index, rlc_accumulator, true);
            key->peek_and_encode_data(key_raw, rlp_encoding_index, rlc_accumulator);
            BOOST_ASSERT_MSG(key_raw.size() == 0, "Error in RLP encoding of key!");
            value->peek_and_encode_data(value_raw, rlp_encoding_index, rlc_accumulator);
            BOOST_ASSERT_MSG(value_raw.size() == 0, "Error in RLP encoding of value!"); 
            _set_hash_input(key_copy, value_copy);
            _calculate_and_store_hash();

        }

        void _set_hash_input(std::vector<zkevm_word_type> key_raw, std::vector<zkevm_word_type> value_raw) {
            for (size_t i = 0; i < this->header->prefix_exists.size(); i++) {
                if (this->header->prefix_exists[i] == 1)
                    hash_input.push_back(static_cast<std::uint8_t>(this->header->prefix[i].data.base()));
            }

            for (size_t i = 0; i < key->header->prefix_exists.size(); i++) {
                if (key->header->prefix_exists[i] == 1)
                    hash_input.push_back(static_cast<std::uint8_t>(key->header->prefix[i].data.base()));
            }

            for (size_t i = 0; i < key_raw.size(); i++)
                hash_input.push_back(static_cast<std::uint8_t>(key_raw[i]));

            for (size_t i = 0; i < value->header->prefix_exists.size(); i++) {
                if (value->header->prefix_exists[i] == 1)
                    hash_input.push_back(static_cast<std::uint8_t>(value->header->prefix[i].data.base()));
            }

            for (size_t i = 0; i < value_raw.size(); i++)
                hash_input.push_back(static_cast<std::uint8_t>(value_raw[i]));
        }

        void _calculate_and_store_hash() {
            std::vector<std::uint8_t> buffer(hash_input.begin(), hash_input.end());
            zkevm_word_type hash = nil::blueprint::zkevm_keccak_hash(buffer);
            hash_low = w_lo<FieldType>(hash);
            hash_high = w_hi<FieldType>(hash);
        }

        void print() {
            
            std::cout << "rlp prefix:\n" << std::endl;
            std::cout << "hash: "
                    << std::hex << hash_high << std::dec << "\t"
                    << std::hex << hash_low << std::dec << "\n";
            this->header->print();

            std::cout << "key:\n";
            key->print();
        
            std::cout << "value:\n";
            value->print();
            std::cout << "rlc: " << this->last_rlc() << std::endl;
        }

        void allocate_witness(){
            std::size_t column_index = 0;
            allocate(rlc_challenge, column_index ++, row_index);
            allocate(hash_low, column_index ++, row_index);
            allocate(hash_high, column_index ++, row_index);
            node_inner_array::allocate_witness(column_index, row_index);
            // std::cout << "witnessesss " << column_index << std::endl;
        }

        void keccak_lookup_constraint() {
            std::vector<TYPE> keccak_lookup = {
                1,
                this->last_rlc(),
                hash_high,
                hash_low
            };
            lookup(keccak_lookup, "keccak_table");
        }

        void constraints() {
            this->rlp_lookup_constraints();
            this->keccak_lookup_constraint();
            TYPE initial_rlc = this->header->get_total_length_constraint();
            this->main_constraints(initial_rlc, 0, node_exists);
        }

        std::size_t rows_count() {
            return 1 + this->extra_rows_count();
        }
    };
}

