//---------------------------------------------------------------------------//
// Copyright (c) 2025 Amirhossein Khajehpour <a.khajepour@nil.foundation>
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
#include <nil/blueprint/zkevm_bbf/small_field/tables/keccak.hpp>
#include <nil/blueprint/zkevm_bbf/mpt_leaf.hpp>
#include <nil/blueprint/zkevm_bbf/mpt_leaf/node_header.hpp>

namespace nil::blueprint::bbf {

    template<typename FieldType, GenerationStage stage>
    class leaf_node: public node_inner_array<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using RLPTable = typename bbf::rlp_table<FieldType, stage>;
        using KeccakTable = typename zkevm_small_field::keccak_table<FieldType, stage>;
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
        using node_inner_key = node_inner_key<FieldType, stage>;

        using node_inner_container = node_inner_container<FieldType, stage>;

        node_inner_key* key;
        node_inner_container* value;
        std::array<TYPE, 32> node_hash;
        TYPE query_offset;
        // std::vector<TYPE> key_prefix;
        std::vector<TYPE> query_value;
        TYPE query_selector;
        TYPE query_value_len;
        TYPE node_exists;
        std::size_t rlp_encoding_index = 0;
        TYPE rlc_accumulator = 0;
        std::size_t row_index;
        std::vector<std::uint8_t> hash_input;

        leaf_node(
            context_type &context_object,
            mpt_type _trie_t,
            std::size_t _row_index,
            query_type _q_type = query_type::full_value_query
        ): node_inner_array(context_object, _q_type)
         , row_index(_row_index) {
            key = new node_inner_key(context_object, _trie_t);
            this->inners.push_back(key);
            value = new node_inner_container(context_object, _trie_t, _q_type);
            this->inners.push_back(value);
            query_value.resize(value->get_max_length());
            // key_prefix.resize(key->trie_key_size);
        }

        void set_data(std::vector<zkevm_word_type> key_raw, std::vector<zkevm_word_type> value_raw, std::vector<zkevm_word_type> original_key, std::size_t _query_offset, std::size_t _query_selector=0) {
            query_offset = _query_offset;
            query_selector = _query_selector;
            peek_and_encode_data(key_raw, value_raw, original_key);
            query_value = value->set_query_data(
                static_cast<std::uint8_t>(query_offset.to_integral()),
                static_cast<std::uint8_t>(query_selector.to_integral())
            );
            key->set_key_prefix(original_key);
            query_value_len = value->get_query_value_len();
        }

        void peek_and_encode_data(std::vector<zkevm_word_type> key_raw, std::vector<zkevm_word_type> value_raw, std::vector<zkevm_word_type> original_key_raw) {
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

        void set_empty_data() {
            auto keys_raw = key->empty_key();
            std::vector<zkevm_word_type> value_raw = value->empty();
            set_data(std::get<0>(keys_raw), value_raw, std::get<1>(keys_raw), 0, 0);
        }

        std::string print() {
            std::stringstream ss;
            ss << "rlp prefix:\n" << std::endl;
            ss << "hash:\n";
            for (auto &i : node_hash)
                ss << std::hex << i << std::dec << " ";

            ss << this->header->print();
            ss << "\tquery values:\n\t";
            for (auto &v : query_value)
                ss << v << " ";
            ss << std::endl;
            ss << "\tquery offset:\t" << query_offset << std::endl;

            ss << "key:\n";
            ss << key->print();

            ss << "value:\n";
            ss << value->print();
            ss << "rlc: " << this->last_rlc() << std::endl;
            return ss.str();
        }

        std::string print_table_entry() {
            std::stringstream ss;
            ss << "original key:\t";

            for (auto &i : key->original_key) {
                if (i <= 0xF)
                    ss << "0";
                ss << std::hex << i << std::dec;
            }
            ss << std::endl;
            ss << "query offset:\t" << query_offset << std::endl;
            ss << "query value:\t"; 
            for (auto &v : query_value) {
                ss << std::hex << v << std::dec << " ";
            }
            ss << std::endl;
            ss << "query selector:\t" << query_selector << std::endl;
            ss << "value len:\t" << query_value_len << std::endl;
            ss << "------------------------------------------\n";
            return ss.str();
        }

        void allocate_witness(){
            std::size_t column_index = 0;
            for (size_t i = 0; i < key->original_key.size(); i++)
                allocate(key->original_key[i], column_index ++, row_index); 
            if (this->q_type == query_type::single_byte_query)
                allocate(query_offset, column_index ++, row_index);

            for (size_t i = 0; i < query_value.size(); i++)
                allocate(query_value[i], column_index ++, row_index);

            allocate(query_selector, column_index ++, row_index);
            if (this->q_type == query_type::single_byte_query)
                allocate(query_value_len, column_index ++, row_index);

            allocate(node_exists, column_index ++, row_index);
            allocate(this->rlc_challenge, column_index ++, row_index);
            for (size_t i = 0; i < node_hash.size(); i++)
                allocate(node_hash[i], column_index ++, row_index); 
            node_inner_array::allocate_witness(column_index, row_index);
            // std::cout << "witnessesss " << column_index << std::endl;
        }

        void keccak_lookup_constraint() {
            auto keccak_tuple = chunks8_to_chunks16<TYPE>(node_hash);
            keccak_tuple.emplace(keccak_tuple.begin(), this->last_rlc());
            lookup(keccak_tuple, "keccak_table");
        }

        void mpt_lookup_constraint() {
            TYPE selector = 1;
            TYPE trie_id = 1;
            TYPE child_nibble_present = key->prefix_has_last_nibble;
            TYPE parent_length = key->get_prefix_length() * 2 + child_nibble_present - 1;
            std::vector<TYPE> accumulated_key = key->get_accumulated_key();
            // TODO lookup main MPT circuit table to find the position of this leaf-node

        }

        void constraints() {
            this->rlp_lookup_constraints();
            this->keccak_lookup_constraint();
            TYPE initial_rlc = this->header->get_total_length_constraint();
            this->main_constraints(initial_rlc, 0, this->rlc_challenge);
            value->query_constraints(query_offset, query_value, query_selector, query_value_len, node_exists);
            mpt_lookup_constraint();
        }

        std::size_t rows_count() {
            return 1 + this->extra_rows_count();
        }

        std::vector<std::vector<std::uint8_t>> get_keccak_buffers() {
            std::vector<std::vector<std::uint8_t>> buffers;
            buffers.push_back(hash_input);
            auto key_buffer = key->get_keccak_buffer();
            if (key_buffer.has_value())
                buffers.push_back(key_buffer.value());
            return buffers;
        }

    protected:

        void _set_hash_input(std::vector<zkevm_word_type> key_raw, std::vector<zkevm_word_type> value_raw) {
            for (size_t i = 0; i < this->header->prefix_exists.size(); i++) {
                if (this->header->prefix_exists[i] == 1)
                    hash_input.push_back(static_cast<std::uint8_t>(this->header->prefix[i].to_integral()));
            }

            for (size_t i = 0; i < key->header->prefix_exists.size(); i++) {
                if (key->header->prefix_exists[i] == 1)
                    hash_input.push_back(static_cast<std::uint8_t>(key->header->prefix[i].to_integral()));
            }

            for (size_t i = 0; i < key_raw.size(); i++)
                hash_input.push_back(uint8_t(key_raw[i]));

            for (size_t i = 0; i < value->header->prefix_exists.size(); i++) {
                if (value->header->prefix_exists[i] == 1)
                    hash_input.push_back(static_cast<std::uint8_t>(value->header->prefix[i].to_integral()));
            }

            for (size_t i = 0; i < value_raw.size(); i++)
                hash_input.push_back(uint8_t(value_raw[i]));
        }

        void _calculate_and_store_hash() {
            std::vector<std::uint8_t> buffer(hash_input.begin(), hash_input.end());
            int i = 0;
            for (auto &w: w_to_8(nil::blueprint::zkevm_keccak_hash(buffer)))
                node_hash[i++] = w;
        }

    };
}

