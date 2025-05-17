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
#include <nil/blueprint/zkevm_bbf/mpt_leaf_inner.hpp>
#include <nil/blueprint/zkevm_bbf/mpt_leaf_header.hpp>


namespace nil::blueprint::bbf {

    using child = typename std::vector<zkevm_word_type>;
    
    template<typename FieldType, GenerationStage stage>
    class leaf_node  : public node_inner_array<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using RLPTable = typename bbf::rlp_table<FieldType, stage>;
        using KeccakTable = typename bbf::keccak_table<FieldType, stage>;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

      public:
        struct input_type {};
        using typename generic_component<FieldType, stage>::table_params;
        using typename generic_component<FieldType, stage>::TYPE;
        using value_type = typename std::vector<zkevm_word_type>;
        using node_inner = node_inner<FieldType, stage>;
        using node_inner_array = node_inner_array<FieldType, stage>;
        using node_header_array_encoder = node_header_array_encoder<FieldType, stage>;
        using node_inner_string_encoder = node_inner_string_encoder<FieldType, stage>;
        using node_inner_string_container = node_inner_string_container<FieldType, stage>;

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
        ): node_inner_array(context_object, _trie_t, _rlc_challenge),
           node_exists(_node_exists),
           rlc_challenge(_rlc_challenge),
           row_index(_row_index) {
            node_header_array_encoder* h = new node_header_array_encoder(
                context_object,
                _rlc_challenge
            );
            this->header = h;

            key = new node_inner_string_encoder(context_object, inner_node_type::key, _trie_t, _rlc_challenge);
            this->inners.push_back(key);
            value = new node_inner_string_container(context_object, inner_node_type::storage_value, _trie_t, _rlc_challenge);
            this->inners.push_back(value);
        }

        void set_data(std::vector<zkevm_word_type> key_raw, std::vector<zkevm_word_type> value_raw) {

            if (node_exists == 0) {
                key_raw = {};
                value_raw = {0x80};
            }

            std::vector<zkevm_word_type> key_copy(key_raw.begin(), key_raw.end());
            std::vector<zkevm_word_type> value_copy(value_raw.begin(), value_raw.end());
            _get_header()->encode_data(get_rlp_size(key_raw) + get_rlp_size(value_raw), rlp_encoding_index, rlc_accumulator, true);
            key->peek_and_set_data(key_raw, rlp_encoding_index, rlc_accumulator);
            BOOST_ASSERT_MSG(key_raw.size() == 0, "Error in RLP decoding1!");
            value->peek_and_set_data(value_raw, rlp_encoding_index, rlc_accumulator);
            BOOST_ASSERT_MSG(value_raw.size() == 0, "Error in RLP decoding2!"); 
            // std::size_t internals_length = key->get_total_length() + value->get_total_length();
            // this->header->set_data_length(internals_length);
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


        // void _set_header_data(std::vector<zkevm_word_type> &raw, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
        //     _get_header()->encode_data(raw.size(), rlp_encoding_index, rlc_accumulator);
        // }

        void constraints() {
            this->rlp_lookup_constraints();
            this->keccak_lookup_constraint();
            TYPE initial_rlc = this->header->get_total_length_constraint();
            this->main_constraints(initial_rlc, 0, node_exists);
        }

        std::size_t rows_count() {
            return 1 + this->extra_rows_count();
        }

        void rlp_lookup_constraints() {
            _get_header()->rlp_lookup_constraints();
            for (size_t i = 0; i < this->inners.size(); i++){
                this->inners[i]->rlp_lookup_constraints();
            }
        }

        private:
        // std::vector<std::uint8_t> hash_input;


        node_header_array_encoder* _get_header() {
            return dynamic_cast<node_header_array_encoder*>(this->header);
        }
    };







    

    struct _leaf_node {
        enum mpt_type type;
        std::array<child, 2> data;
    };

    struct mpt_query {
        std::size_t index;
        inner_node_type type;
        _leaf_node node;
    };

    template<typename FieldType, GenerationStage stage>
    class mpt_leaf_node : public generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using RLPTable = typename bbf::rlp_table<FieldType, stage>;
        using KeccakTable = typename bbf::keccak_table<FieldType, stage>;
        // using MPTLeafTable = typename bbf::mpt_leaf_table<FieldType, stage>;
        // using mpt_leaf_table_input_type = typename bbf::mpt_leaf_table<FieldType, stage>::input_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

      public:
        using typename generic_component<FieldType, stage>::table_params;
        using typename generic_component<FieldType, stage>::TYPE;
        using node_inner_string = node_inner_string<FieldType, stage>;

        struct input_type {
            std::vector<mpt_query> queries;
            TYPE rlc_challenge;
        };

        // using input_type =
        //     typename std::conditional<stage == GenerationStage::ASSIGNMENT,
        //                                 _input_type, std::nullptr_t>::type;

        using value = typename FieldType::value_type;
        using integral_type = nil::crypto3::multiprecision::big_uint<257>;

        static table_params get_minimal_requirements(std::size_t max_mpt_query_size) {
            return {
                    .witnesses = 2000,
                    .public_inputs = 0,
                    .constants = 0,
                    .rows = max_mpt_query_size + 2178 + 10};
        }

        static void allocate_public_inputs(context_type &context, input_type &input,
                                           std::size_t max_mpt_query_size) {}

        mpt_leaf_node(context_type &context_object, const input_type &input,
            std::size_t max_mpt_query_size)
            : generic_component<FieldType, stage>(context_object) {

            std::vector<std::size_t> keccak_lookup_area;
            std::size_t keccak_max_blocks = 10;
            std::vector<std::size_t> rlp_lookup_area;
            // std::vector<TYPE> node_type(max_mpt_query_size);
            std::vector<std::size_t> leaf_table_lookup_area;
            // mpt_leaf_table_input_type leaf_table_inputs;
            // std::vector<TYPE> node_type_inv_2(max_mpt_query_size);
            // std::vector<TYPE> r(max_mpt_query_size);
            std::size_t node_num = 0;
            typename KeccakTable::private_input_type keccak_buffers;
            std::vector<leaf_node<FieldType, stage>> nodes;
            // leaf_node sag = leaf_node(mpt_type::storage_trie, 1);
            std::size_t row_index = 0;

            for (size_t i = 0; i < max_mpt_query_size; i++) {
                leaf_node n = leaf_node<FieldType, stage>(context_object, mpt_type::storage_trie, i < input.queries.size(), input.rlc_challenge, row_index);
                nodes.push_back(n);
                row_index += n.rows_count();
                // nodes[i].set_challenge(input.rlc_challenge);
            }
            
            
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                BOOST_ASSERT_MSG(input.queries.size() <= max_mpt_query_size, "number of queries exceeds!");
                // assignment
                for (size_t i = 0; i < max_mpt_query_size; i++) {
                    // std::cout << "initializing\n";
                    nodes[i].initialize();
                    if (i < input.queries.size()) {
                        _leaf_node mn = input.queries[i].node;
                        std::size_t index = input.queries[i].index;
                        std::vector<zkevm_word_type> key = mn.data[0];
                        std::vector<zkevm_word_type> value = mn.data[1];
                        // nodes[i].set_challenge(input.rlc_challenge);
                        nodes[i].set_data(key, value);
                    } else {
                        nodes[i].set_data({}, {});
                    }
                    // std::cout << "calculate hash\n";
                    std::vector<std::uint8_t> buf = nodes[i].hash_input;
                    // for (size_t i = 0; i < buf.size(); i++) {
                    //     if (buf[i] <= 0x0F)
                    //         std::cout << "0" << std::hex << int(buf[i]) << std::dec;
                    //     else
                    //         std::cout << std::hex << int(buf[i]) << std::dec;
                    // }
                    // std::cout << "\n";
                    
                    keccak_buffers.new_buffer(buf);
                    // nodes[i].print();

                    // leaf_table_inputs[i].hash_lo = w_lo<FieldType>(hash);
                    // leaf_table_inputs[i].hash_hi = w_hi<FieldType>(hash);
                    // leaf_table_inputs[i].value = n.content.data[1][index];
                    // leaf_table_inputs[i].index = index;
                }
            }


            for( std::size_t i = 0; i < KeccakTable::get_witness_amount(); i++){
                keccak_lookup_area.push_back(i);
            }
            context_type keccak_ct = context_object.subcontext( keccak_lookup_area, max_mpt_query_size + 2178, keccak_max_blocks);
            KeccakTable k_t = KeccakTable(keccak_ct, {input.rlc_challenge, keccak_buffers}, keccak_max_blocks);

            for (std::size_t i = 0; i < RLPTable::get_witness_amount(); i++) {
                rlp_lookup_area.push_back(i);
            }
            context_type rlp_ct = context_object.subcontext(rlp_lookup_area, max_mpt_query_size, 2178);
            RLPTable rlpt = RLPTable(rlp_ct);
            
            for (size_t i = 0; i < max_mpt_query_size; i++) {
                nodes[i].allocate_witness();
            }

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                for (size_t i = 0; i < max_mpt_query_size; i++) {
                    nodes[i].constraints();
                }
            }
        }
    };
}  // namespace nil::blueprint::bbf
