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
    class leaf_node  : public generic_component<FieldType, stage> {
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
        using node_inner_array = node_inner_array<FieldType, stage>;
        using node_header_array = node_header_array<FieldType, stage>;
        using node_inner_string = node_inner_string<FieldType, stage>;

        static zkevm_word_type calculate_keccak(std::vector<std::uint8_t> hash_input, std::size_t total_length) {
            std::vector<uint8_t> buffer(hash_input.begin(), hash_input.begin() + total_length);
            zkevm_word_type hash = nil::blueprint::zkevm_keccak_hash(buffer);
            return hash;
        }

        mpt_type trie_type;
        node_header_array header;

        node_inner_string key;
        node_inner_string value;

        TYPE not_padding;
        std::size_t rlp_encoding_index = 0;
        TYPE rlc_accumulator = 0;
        TYPE rlc_challenge;
            
        leaf_node(
            context_type &context_object,
            mpt_type _trie_t,
            TYPE _not_padding,
            TYPE _rlc_challenge
        ): generic_component<FieldType, stage>(context_object),
           trie_type(_trie_t),
           header(context_object, inner_node_type::array, _rlc_challenge),
           not_padding(_not_padding),
           key(context_object, inner_node_type::key, _trie_t, _rlc_challenge),
           value(context_object, _trie_t == mpt_type::storage_trie ? inner_node_type::storage_value : inner_node_type::array, _trie_t, _rlc_challenge),
           rlc_challenge(_rlc_challenge) {

            hash_input.resize(532);
        }


        void initialize() {
            _initialize_header();
            key.initialize();
            value.initialize();
        }

        void set_data(std::vector<zkevm_word_type> key_raw, std::vector<zkevm_word_type> value_raw) {
            key.set_data(key_raw);
            value.set_data(value_raw); 
              
            std::size_t internals_length = key.get_total_length() + value.get_total_length();

            header.set_data_length(internals_length);
        }

        void set_metadata() {
            // last argument doesn't matter because length is always more than one byte
            rlc_accumulator = header.get_total_length();
            header.set_metadata(hash_input, rlp_encoding_index, rlc_accumulator);
            key.set_metadata(hash_input, rlp_encoding_index, rlc_accumulator);
            value.set_metadata(hash_input, rlp_encoding_index, rlc_accumulator);
        }

        std::vector<uint8_t> calculate_and_sotore_hash() {
            this->store_hash(calculate_keccak(this->hash_input, this->rlp_encoding_index));
            return std::vector<uint8_t>(this->hash_input.begin(), this->hash_input.begin() + this->rlp_encoding_index);
        }

        void store_hash(zkevm_word_type hash) {
            this->header.hash_low = w_lo<FieldType>(hash);
            this->header.hash_high = w_hi<FieldType>(hash);
        }

        void print_leaf_node() {
            
            std::cout << "rlp prefix:\n" << std::endl;
            std::cout << "hash: "
                    << std::hex << header.hash_high << std::dec << "\t"
                    << std::hex << header.hash_low << std::dec << "\n";
            header.print();

            std::cout << "key prefix:\n";
            key.header.print();
            std::cout << "key:\n\tdata\tindex\n";
            for (size_t i = 0; i < key.raw.size(); i++) {
                std::cout << "\t"
                        << std::hex << key.data[i] << std::dec << "\t" 
                        << std::hex << key.index[i] << std::dec << std::endl;
            }
        
            std::cout << "value prefix:\n";
            value.header.print();
            std::cout << "value: \n";
            for (size_t i = 0; i < value.raw.size(); i++) {
                std::cout << "\t"
                        << std::hex << value.data[i] << std::dec << "\t" 
                        << std::hex << value.index[i] << std::dec << std::endl;
            }
            std::cout << "rlc: " << value.rlc[value.rlc.size()-1] << std::endl;
        }

        void allocate_witness(){
            std::size_t column_index = 0;
            std::size_t row_index = 0;
            allocate(rlc_challenge, column_index ++, row_index);
            header.allocate_witness(column_index, row_index);
            key.allocate_witness(column_index, row_index);
            value.allocate_witness(column_index, row_index);
            std::cout << "witnessesss " << column_index << std::endl;
        }

        void rlp_lookup_constraints() {
            header.rlp_lookup_constraints();
            key.rlp_lookup_constraints();
            value.rlp_lookup_constraints();
        }

        void keccak_lookup_constraint() {
            std::size_t leaf_data_size = value.rlc.size()-1;
            std::vector<TYPE> keccak_lookup = {
                1,
                value.rlc[leaf_data_size] * not_padding,
                header.hash_high,
                header.hash_low
            };
            lookup(keccak_lookup, "keccak_table");
        }

        void main_constraints() {
            TYPE initial_rlc = header.get_total_length_constraint();
            
            constrain(not_padding * (header.len - (key.get_total_length_constraint() + value.get_total_length_constraint())));
            // constrain(1 - header.prefix_first_exists);

            header.main_constraints(initial_rlc, 0, not_padding);
            TYPE key_initial_index = header.get_prefix_length();
            TYPE key_previous_rlc = header.prefix_rlc[2];
            key.main_constraints(key_previous_rlc, key_initial_index, not_padding);

            TYPE value_initial_index = key_initial_index + key.get_total_length_constraint();
            TYPE value_previous_rlc = key.rlc[key.rlc.size()-1];
            value.main_constraints(value_previous_rlc, value_initial_index, not_padding);
        }

        private:
        std::vector<std::uint8_t> hash_input;
        void _initialize_header() {
            header.initialize();
            store_hash(calculate_keccak({}, 0));
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
    class mpt_leaf : public generic_component<FieldType, stage> {
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
                    .rows = max_mpt_query_size + 2178};
        }

        static void allocate_public_inputs(context_type &context, input_type &input,
                                           std::size_t max_mpt_query_size) {}

        mpt_leaf(context_type &context_object, const input_type &input,
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

            std::vector<std::size_t> leaf_area;
            for( std::size_t i = 0; i < 2000; i++){
                leaf_area.push_back(i);
            }
            context_type leaf_ct = context_object.subcontext( leaf_area, 0, max_mpt_query_size);


            for (size_t i = 0; i < max_mpt_query_size; i++) {
                nodes.push_back(leaf_node<FieldType, stage>(leaf_ct, mpt_type::storage_trie, 1, input.rlc_challenge));
                // nodes[i].set_challenge(input.rlc_challenge);
            }
            
            
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                // leaf_table_inputs.resize(max_mpt_query_size);
                BOOST_ASSERT_MSG(input.queries.size() <= max_mpt_query_size, "number of queries exceeds!");
                keccak_buffers.new_buffer(std::vector<uint8_t>{});
                // initialize_node_rlp_data(nodes);
                // assignment
                for (size_t i = 0; i < input.queries.size(); i++) {
                    _leaf_node mn = input.queries[i].node;
                    std::size_t index = input.queries[i].index;
                    std::cout << "index " << input.queries[i].index << "\n";
                    std::vector<zkevm_word_type> key = mn.data[0];
                    std::vector<zkevm_word_type> value = mn.data[1];
                    // nodes[i].set_challenge(input.rlc_challenge);
                    nodes[i].initialize();
                    nodes[i].set_data(key, value);
                    nodes[i].set_metadata();

                    std::vector<std::uint8_t> buf = nodes[i].calculate_and_sotore_hash();
                    for (size_t i = 0; i < buf.size(); i++)
                    {
                        if (buf[i] <= 0x0F)
                            std::cout << "0" << std::hex << int(buf[i]) << std::dec;
                        else
                            std::cout << std::hex << int(buf[i]) << std::dec;
                    }
                    std::cout << "\n";
                    
                    keccak_buffers.new_buffer(buf);

                    // nodes[i].set_key_header(input.rlc_challenge);
                    // nodes[i].set_key_indices(key, input.rlc_challenge);
                    // nodes[i].set_value_header(value, input.rlc_challenge);
                    // nodes[i].set_value_indices(value, input.rlc_challenge);
                    // nodes[i].set_key_is_last();
                    // nodes[i].set_value_is_last();
                    // std::size_t total_length = get_leaf_key_length(key) + get_leaf_value_length(value);
                    // std::size_t rlp_encoding_index;
                    // std::vector<std::uint8_t> hash_input(532);
                    // TYPE rlc_accumulator;
                    // encode_node_data(n, total_length, rlp_encoding_index, hash_input, rlc_accumulator, input.rlc_challenge);
                    // encode_leaf_data(n.content, key, value, rlp_encoding_index, hash_input, rlc_accumulator, input.rlc_challenge);

                    // zkevm_word_type hash = calculate_keccak(hash_input, rlp_encoding_index);
                    // std::cout << "node hash: " << std::hex << hash << std::dec << std::endl;
                    // std::cout << "rlc: " << rlc_accumulator<< std::endl;
                    // std::vector<uint8_t> buffer(hash_input.begin(), hash_input.begin() + rlp_encoding_index);
                    // keccak_buffers.new_buffer(buffer);
                    // store_node_hash(n, hash);
                    // leaf_table_inputs[i].hash_lo = w_lo<FieldType>(hash);
                    // leaf_table_inputs[i].hash_hi = w_hi<FieldType>(hash);
                    // leaf_table_inputs[i].value = n.content.data[1][index];
                    // leaf_table_inputs[i].index = index;
                }
            }
            nodes[0].print_leaf_node();


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
                    nodes[i].rlp_lookup_constraints();
                    nodes[i].keccak_lookup_constraint();
                    nodes[i].main_constraints();
                }
                
            }

        }
    };
}  // namespace nil::blueprint::bbf
