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

namespace nil::blueprint::bbf {

    using child = typename std::vector<zkevm_word_type>;

    enum class mpt_type { account_trie, storage_trie };

    enum class inner_node_type { 
        nonce, 
        balance, 
        storage_root, 
        code_hash, 
        storage_value, 
        key,
        array 
    };
    // enum class element_type { string_element, array_element };
    

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


        class rlp_header {
            public:
            // mpt_type trie_type;
            inner_node_type node_type;
            std::array<TYPE, 3> prefix;
            std::array<TYPE, 3> prefix_rlc;
            TYPE second_prefix_padding; // if 1 second prefix does not exist
            TYPE third_prefix_padding; // if 1 third prefix does not exist
            std::array<TYPE, 3> prefix_index;
            TYPE len_low;
            TYPE len_high;
            TYPE hash_low;
            TYPE hash_high;

            std::size_t raw_data_length;
                
            rlp_header(
                // mpt_type _trie_t,
                inner_node_type _node_t
            ):  
            // trie_type(_trie_t),
                node_type(_node_t) {
                    // this->initialize();
                }
    
            void initialize() {
                second_prefix_padding = 1;
                third_prefix_padding = 1;
                prefix[0] = 0xC0;
            }

            void main_constraints(mpt_leaf<FieldType, stage> &comp, TYPE initial_index, TYPE not_padding) {
                comp.constrain(second_prefix_padding*(1 - second_prefix_padding));
                comp.constrain(prefix[1] * second_prefix_padding);
                comp.constrain(prefix[2] * third_prefix_padding);

                comp.constrain(prefix_index[0] - initial_index);
                comp.constrain(prefix_index[1] - (1 - second_prefix_padding) * (prefix_index[0] + 1));
                comp.constrain(prefix_index[2] - (1 - third_prefix_padding) * (prefix_index[1] + 1));

                comp.constrain(prefix_rlc[1] - ((1 - second_prefix_padding) * (prefix_rlc[0] * 53 + prefix[1]) + second_prefix_padding * prefix_rlc[0]));
                comp.constrain(prefix_rlc[2] - ((1 - third_prefix_padding) *  (prefix_rlc[1] * 53 + prefix[2]) + third_prefix_padding * prefix_rlc[1]));
            }
    
            void set_indices(std::vector<std::uint8_t> &hash_input, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator, 
                TYPE rlc_challenge, zkevm_word_type value0, bool initialize) {
                uint8_t const1, const2;

                if (node_type == inner_node_type::array) {
                    const1 = 0xC0;
                    const2 = 0xF7;
                } else {
                    const1 = 0x80;
                    const2 = 0xB8;
                }
                
                if (node_type != inner_node_type::array && raw_data_length == 1 && value0 <= 0x7F) {
                        prefix[0] = value0;
                        prefix_index[0] = rlp_encoding_index;
                        hash_input[rlp_encoding_index++] = uint8_t(value0);
                        second_prefix_padding = 1;
                        third_prefix_padding = 1;
                        prefix_index[1] = 0;
                        prefix_index[2] = 0;

                        prefix_rlc[0] = rlc_challenge + prefix[0];
                        prefix_rlc[1] = prefix_rlc[0];
                        prefix_rlc[2] = prefix_rlc[1];
                } else if (raw_data_length <= 55) {
                        prefix[0] = const1 + raw_data_length;
                        second_prefix_padding = 1;
                        third_prefix_padding = 1;
                        prefix_index[0] = rlp_encoding_index;
    
                        hash_input[rlp_encoding_index++] = uint8_t((const1 + raw_data_length) & 0xFF);
                        if (initialize)
                            prefix_rlc[0] = (raw_data_length+1) * rlc_challenge + prefix[0];
                        else
                            prefix_rlc[0] = rlc_accumulator * rlc_challenge + prefix[0];
                        rlc_accumulator = prefix_rlc[0];
                        prefix_rlc[1] = rlc_accumulator;
                        prefix_rlc[2] = rlc_accumulator;
                } else {
                    std::size_t length_length = 0;
                    std::size_t temp = raw_data_length;
                    second_prefix_padding = 0;

                    while(temp > 0) {
                        temp >>= 8;
                        length_length ++;
                    }
                    prefix[0] = const2 + length_length;
                    prefix_index[0] = rlp_encoding_index;
                    hash_input[rlp_encoding_index++] = const2 + length_length;

                    if (length_length == 1) {
                        third_prefix_padding = 1;
                        prefix[1] = raw_data_length;
                        prefix_index[1] = rlp_encoding_index;
                        hash_input[rlp_encoding_index++] = raw_data_length;
                        
                        // update rlc
                        if (initialize)
                            prefix_rlc[0] = (2 + raw_data_length) * rlc_challenge + prefix[0];
                        else
                            prefix_rlc[0] = rlc_accumulator * rlc_challenge + prefix[0];
                        prefix_rlc[1] = prefix_rlc[0] * rlc_challenge + prefix[1];
                        prefix_rlc[2] = prefix_rlc[1];
                    }
                    else if (len_high == 2) {
                        third_prefix_padding = 0;
                        prefix[1] = raw_data_length >> 8;
                        prefix_index[1] = rlp_encoding_index;
                        hash_input[rlp_encoding_index++] = raw_data_length >> 8;
                        prefix[2] = raw_data_length & 0xFF;
                        prefix_index[2] = rlp_encoding_index;
                        hash_input[rlp_encoding_index++] = raw_data_length - (raw_data_length & 0xFF);
                        
                        // update rlc
                        if (initialize)
                            prefix_rlc[0] = (3 + raw_data_length) * rlc_challenge + prefix[0];
                        else
                            prefix_rlc[0] = rlc_accumulator * rlc_challenge + prefix[0];
                        prefix_rlc[1] = prefix_rlc[0] * rlc_challenge + prefix[1];
                        prefix_rlc[2] = prefix_rlc[1] * rlc_challenge + prefix[1];
                    }
                    BOOST_ASSERT_MSG(length_length <= 2, "Length of length too big!");
                    rlc_accumulator = prefix_rlc[2];
                }
            }

            void set_data_length(std::size_t _raw_data_length) {
                if (this->node_type == inner_node_type::storage_value)
                    BOOST_ASSERT_MSG(_raw_data_length <= 32, "Data size exceeded 32 bytes for storage values!");
                else if (this->node_type == inner_node_type::array)
                    BOOST_ASSERT_MSG(_raw_data_length <= 110, "We only support array of up to 110 bytes!");
                else if (this->node_type == inner_node_type::nonce)
                    BOOST_ASSERT_MSG(_raw_data_length <= 8, "Data size exceeded 8 bytes for nonce!");
                else if (this->node_type == inner_node_type::balance)
                    BOOST_ASSERT_MSG(_raw_data_length <= 32, "Data size exceeded 32 bytes for balance!");
                else if (this->node_type == inner_node_type::storage_root)
                    BOOST_ASSERT_MSG(_raw_data_length <= 32, "Data size exceeded 32 bytes for storage hash!");
                else if (this->node_type == inner_node_type::code_hash)
                    BOOST_ASSERT_MSG(_raw_data_length <= 32, "Data size exceeded 32 bytes for code hash!");
                
                this->raw_data_length = _raw_data_length;
                this->len_low = this->raw_data_length & 0xFF;
                this->len_high = (this->raw_data_length >> 8) & 0xFF;
            }

            std::size_t get_total_length() {
                BOOST_ASSERT_MSG(this->node_type == inner_node_type::array, "wrong emthod is called!");
                if (this->raw_data_length <= 55) {
                    return this->raw_data_length + 1;
                } else {
                    std::size_t len_len=0;
                    std::size_t tmp = this->raw_data_length;
                    while (tmp > 0) {
                        len_len += 1;
                        tmp >>= 4;
                    }
                    return len_len + tmp;
                }
            }

            std::size_t get_total_length(TYPE first_byte) {
                BOOST_ASSERT_MSG(this->node_type != inner_node_type::array, "wrong emthod is called!");
                if (this->raw_data_length == 1 && first_byte <= 0x7F) {
                    return 1;
                } else if (this->raw_data_length <= 55) {
                    return this->raw_data_length + 1;
                } else {
                    std::size_t len_len=0;
                    std::size_t tmp = this->raw_data_length;
                    while (tmp > 0) {
                        len_len += 1;
                        tmp >>= 4;
                    }
                    return len_len + tmp;
                }
                // if ( this->key_type== inner_node_type::key) {
                //     BOOST_ASSERT_MSG(length <= 32, "leaf node key length exceeded!");
                // } else if (this->trie_type == mpt_type::account_trie) {
                //     // if (this->type == element_type::array_element) {
                //         BOOST_ASSERT_MSG(length <= 110, "leaf node value length exceeded!");
                //     // }
                // }
                // else if (this->trie_type == mpt_type::storage_trie) {
                //     BOOST_ASSERT_MSG(length <= 33, "leaf node value length exceeded!");
                // }
                // std::size_t length = get_rlp_encoded_length(first_byte, length);
            }
        
            void rlp_lookup_constraints(generic_component<FieldType, stage> &comp, TYPE first_element, TYPE first_element_flag) {
                // std::cout << "injaa " << std::hex << this->prefix[0] << std::dec << " "
                // << std::hex << this->prefix[1] * this->second_prefix_padding << std::dec << " "
                // << std::hex << this->prefix[2] * this->third_prefix_padding << std::dec << " "
                // << std::hex << first_element << std::dec << " "
                // << std::hex << first_element_flag << std::dec << " "
                // << int(this->node_type != inner_node_type::array) << " "
                // << std::hex << this->len_low << std::dec << " "
                // << std::hex << this->len_high << std::dec << " "
                // << std::hex << this->second_prefix_padding << std::dec << " "
                // << std::hex << this->third_prefix_padding << std::dec << " \n";
                std::vector<TYPE> node_rlp_lookup = {
                    this->prefix[0],
                    this->prefix[1],
                    this->prefix[2],
                    first_element,
                    first_element_flag,
                    this->node_type != inner_node_type::array,
                    this->len_low, 
                    this->len_high,
                    this->second_prefix_padding,
                    this->third_prefix_padding
                };
                comp.lookup(node_rlp_lookup, "rlp_table");
            }

            void allocate_witness(generic_component<FieldType, stage> &comp, std::size_t &column_index, std::size_t &row_index) {
                // rlp len
                comp.allocate(this->len_low, column_index ++, row_index);
                comp.allocate(this->len_high, column_index ++, row_index);
                comp.allocate(this->hash_low, column_index ++, row_index);
                comp.allocate(this->hash_high, column_index ++, row_index);
                comp.allocate(this->second_prefix_padding, column_index ++, row_index);
                comp.allocate(this->third_prefix_padding, column_index ++, row_index);
                // pefix
                comp.allocate(this->prefix[0], column_index ++, row_index);
                comp.allocate(this->prefix_rlc[0], column_index ++, row_index);
                comp.allocate(this->prefix[1], column_index ++, row_index);
                comp.allocate(this->prefix_rlc[1], column_index ++, row_index);
                comp.allocate(this->prefix_index[0], column_index ++, row_index);
                comp.allocate(this->prefix[2], column_index ++, row_index);
                comp.allocate(this->prefix_rlc[2], column_index ++, row_index);
                comp.allocate(this->prefix_index[1], column_index ++, row_index);
            }
        };
    
        class node_inner {
            public:
            rlp_header header;
            inner_node_type node_type;
            mpt_type trie_type;
            std::vector<TYPE> data;
            std::vector<TYPE> index;
            std::vector<TYPE> index_is_last_I;
            std::vector<TYPE> index_is_last_R;
            std::vector<TYPE> is_last;
            std::vector<TYPE> rlc;
            std::vector<zkevm_word_type> raw;
            TYPE first_element_flag; // if 0 prefix[0] must be data[0]
            TYPE first_element;
    
            // in case this node is of array_element type
            std::vector<node_inner> inners;
    
            node_inner(inner_node_type _n_type, mpt_type _trie_type): header(_n_type), node_type(_n_type), trie_type(_trie_type){
                if (_n_type == inner_node_type::array) {
                    if (_trie_type == mpt_type::account_trie) {
                        // TODO
                        this->inners.push_back(node_inner(inner_node_type::nonce, _trie_type));
                        this->inners.push_back(node_inner(inner_node_type::balance, _trie_type));
                        this->inners.push_back(node_inner(inner_node_type::storage_root, _trie_type));
                        this->inners.push_back(node_inner(inner_node_type::code_hash, _trie_type));
                    }
                } else {
                }
                data.resize(110);
                index.resize(110);
                index_is_last_I.resize(110);
                index_is_last_R.resize(110);
                is_last.resize(110);
                rlc.resize(110);
            }
    
            void initialize() {
                this->_initialize_header();
                this->_initialize_body();
            }

            void set_data(std::vector<zkevm_word_type> raw) {
                if (this->node_type == inner_node_type::array) {
                    // TODO
                } else {
                    this->_set_data(raw);
                    this->header.set_data_length(raw.size());
                }
            }

            std::size_t get_total_length() {
                if (this->node_type == inner_node_type::array) {
                    // TODO read length of all the internals
                    return this->header.get_total_length();
                } else {
                    return this->header.get_total_length(this->raw[0]);
                }
            }
    
            void set_indices(std::vector<std::uint8_t> &hash_input, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator, TYPE rlc_challenge) {
                this->header.set_indices(hash_input, rlp_encoding_index, rlc_accumulator, rlc_challenge, 0 ? this->node_type == inner_node_type::array : this->raw[0], false);
                if (this->node_type != inner_node_type::array) {
                    for (size_t j = 0; j < this->raw.size(); j++) {
                        this->index[j] = rlp_encoding_index;
                        hash_input[rlp_encoding_index++] = uint8_t(this->raw[j]);
    
                        this->rlc[j] = rlc_accumulator * rlc_challenge + this->raw[j];
                        rlc_accumulator = this->rlc[j];
                    }
                    for (size_t j = this->raw.size(); j < this->rlc.size(); j++) {
                        this->rlc[j] = rlc_accumulator;
                    }
                } else {
                    // TODO fix this
                }
            }
    
            void set_is_last() {
                // TODO fix type
                TYPE len = this->header.raw_data_length;
                for (size_t j = 0; j < this->data.size(); j++) {
                    if ( this->index[j] - this->index[0] == len - 1) {
                        this->index_is_last_I[j] = 0;
                    } else {
                        this->index_is_last_I[j] = 
                            (len - 1 - (this->index[j] - this->index[0])).inversed();
                    }
                    this->index_is_last_R[j] = 1 - 
                        (len - 1 - (this->index[j] - this->index[0])) 
                        * this->index_is_last_I[j];
                    std::cout << j << " " << this->index[j] << " "
                        << this->index_is_last_R[j] - (1 - this->index_is_last_I[j] * (len - (this->index[j] - this->index[0] + 1))) << " "
                        << this->index_is_last_R[j] << " "
                        << this->index_is_last_I[j] << " "
                        << len - (this->index[j] - this->index[0] + 1) << std::endl;
                }
            }

    
            void allocate_witness(mpt_leaf<FieldType, stage> &comp, std::size_t &column_index, std::size_t &row_index){
                this->header.allocate_witness(comp, column_index, row_index);

                for (std::size_t k = 0; k < 110; k++) {
                    comp.allocate(this->data[k], column_index++, row_index);
                    comp.allocate(this->rlc[k], column_index++, row_index);
                    comp.allocate(this->is_last[k], column_index++, row_index);
                    comp.allocate(this->index[k], column_index++, row_index);
                    comp.allocate(this->index_is_last_I[k], column_index++, row_index);
                    comp.allocate(this->index_is_last_R[k], column_index++, row_index);
                }

            }

            void rlp_lookup_constraints(mpt_leaf<FieldType, stage> &comp) {
                this->header.rlp_lookup_constraints(comp, this->first_element, this->first_element_flag);
            }

            void main_constraints(mpt_leaf<FieldType, stage> &comp, TYPE previous_rlc, TYPE initial_index, TYPE not_padding) {
                constraint_first_rlp_prefix_rlc(comp, previous_rlc, not_padding);
                this->header.main_constraints(comp, initial_index, not_padding);

                TYPE first_data_index = this->header.prefix_index[0] + 1 + 1 - this->header.second_prefix_padding + 1 - this->header.third_prefix_padding;
                comp.constrain(this->index[0] - first_data_index);
                comp.constrain(this->rlc[0] - (this->header.prefix_rlc[2] * 53 + this->data[0]));

                // comp.constrain(this->data[0] * this->is_last[0]);
                for (size_t i = 1; i < 110; i++) {
                    comp.constrain((1 - this->is_last[i]) * this->is_last[i]);
                    comp.constrain((1 - this->is_last[i]) * this->is_last[i-1]);
                    TYPE data_len = this->header.len_low + this->header.len_high * 0x100;
                    
                    comp.constrain(not_padding * (this->index_is_last_R[i] - (1 - 
                        this->index_is_last_I[i] * (data_len - (this->index[i] - this->index[0] + 1)))));
                    comp.constrain((data_len - (this->index[i] - this->index[0] + 1)) * this->index_is_last_R[i]);
                    comp.constrain(this->is_last[i] - this->index_is_last_R[i] - this->is_last[i-1]);
                    comp.constrain(this->index[i] * this->is_last[i-1]);
                    comp.constrain((this->index[i] - this->index[i-1] - 1) * (1 - this->is_last[i-1]));
                    comp.constrain(this->data[i] * this->is_last[i-1]);
                    comp.constrain(this->rlc[i] - (this->is_last[i-1] * this->rlc[i-1] + (1 - this->is_last[i-1]) * (this->rlc[i-1] * 53 + this->data[i])));
                }
            }

            void constraint_first_rlp_prefix_rlc(mpt_leaf<FieldType, stage> &comp, TYPE previous_rlc, TYPE not_padding) {
                comp.constrain(not_padding * (this->header.prefix_rlc[0] - (previous_rlc * 53 + this->header.prefix[0])));
            }

            private:
            void _initialize_header() {
                this->header.initialize();
            }
            void _initialize_body() {
                if (this->node_type == inner_node_type::array) {
                    for (auto &i : this->inners) {
                        i.initialize();
                    }
                } else {
                    for (size_t j = 0; j < this->data.size(); j++) {
                        this->data[j] = 0;
                        this->index[j] = 0;
                        this->is_last[j] = 1;
                    }
                    this->first_element_flag = 1;
                }
            }
            void _set_data(std::vector<zkevm_word_type> _raw) {
                this->raw = _raw;
                if (this->node_type!= inner_node_type::array) {
                    // if (this->type == inner_node_type::key) {
                    //     BOOST_ASSERT_MSG(this->raw.size() <= 33, "key length exceeds!");
                    // } else if (this->type == inner_node_type::nonce) {
                    //     // TODO placeholder for now
                    //     BOOST_ASSERT_MSG(this->raw.size() <= 110, "key length exceeds!");
                    // }                    
                    for (size_t j = 0; j < this->raw.size(); j++) {
                        // if (d[j] <= 0x0F)
                        //     std::cout <<"0" << std::hex << d[j] << std::dec;
                        // else
                        //     std::cout << std::hex << d[j] << std::dec;
                        this->data[j] = this->raw[j];
                        this->is_last[j] = 0;
                    }
                    if (this->raw.size() > 0) {
                        this->is_last[this->raw.size() - 1] = 1;
                    }
                    if (this->raw.size() == 0 || (this->raw.size() == 1 && this->raw[0] < 128)) {
                        if (this->raw.size() == 1)
                            this->first_element = this->raw[0];
                        this->first_element_flag = 1;
                    } else {
                        this->first_element_flag = 0;
                    }
                } else {
                    std::cout << "element type not supported yet!\n";
                }
            }
    
        };

        class leaf_node {
            using value_type = typename std::vector<zkevm_word_type>;
    
            static zkevm_word_type calculate_keccak(std::vector<std::uint8_t> hash_input, std::size_t total_length) {
                std::vector<uint8_t> buffer(hash_input.begin(), hash_input.begin() + total_length);
                zkevm_word_type hash = nil::blueprint::zkevm_keccak_hash(buffer);
                return hash;
            }
    
            public:
            mpt_type trie_type;
            rlp_header header;
    
            node_inner key;
            node_inner value;
    
            TYPE not_padding;
            std::size_t rlp_encoding_index = 0;
            TYPE rlc_accumulator = 0;
                
            leaf_node(
                mpt_type _trie_t,
                TYPE _not_padding
            ): trie_type(_trie_t),
               header(inner_node_type::array),
               not_padding(_not_padding),
               key(inner_node_type::key, _trie_t),
               value(_trie_t == mpt_type::storage_trie ? inner_node_type::storage_value : inner_node_type::array, _trie_t) {

                this->hash_input.resize(532);
            }
    
            void initialize() {
                if (stage == GenerationStage::ASSIGNMENT) {
                    this->_initialize_header();
                    this->key.initialize();
                    this->value.initialize();
                }
            }

            void set_data(std::vector<zkevm_word_type> key, std::vector<zkevm_word_type> value) {
                this->key.set_data(key);
                std::cout << "inja\n";
                this->value.set_data(value);                
                std::size_t internals_length = this->key.get_total_length() + this->value.get_total_length();

                std::cout << "unja\n";
                this->header.set_data_length(internals_length);
            }

            void set_indices(TYPE rlc_challenge) {
                // last argument doesn't matter because length is always more than one byte
                this->header.set_indices(this->hash_input, this->rlp_encoding_index, this->rlc_accumulator, rlc_challenge, 0, true);
                this->key.set_indices(this->hash_input, this->rlp_encoding_index, this->rlc_accumulator, rlc_challenge);
                this->value.set_indices(this->hash_input, this->rlp_encoding_index, this->rlc_accumulator, rlc_challenge);
                set_is_last();
            }

            void set_is_last() {
                this->key.set_is_last();
                this->value.set_is_last();
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
                
                std::cout << "rlp prefix:" << std::endl;
                std::cout << "\tdata\thash_hi\thash_lo\n";

                std::cout << "\t" << std::hex << this->header.prefix[0] << std::dec << "\t"
                        << std::hex << this->header.hash_high << std::dec << "\t"
                        << std::hex << this->header.hash_low << std::dec << "\t"
                        << std::hex << 0 << std::dec << std::endl;
                std::cout << "\t" << std::hex << this->header.prefix[1] << std::dec << "\t"
                        << std::hex << this->header.prefix_index[0] << std::dec << std::endl;
                std::cout << "\t" << std::hex << this->header.prefix[2] << std::dec << "\t"
                        << std::hex << this->header.prefix_index[1] << std::dec << std::endl;
                
                std::cout << "node rlp second prefix is last:\n "
                        << std::hex << this->header.second_prefix_padding << std::dec << std::endl;
                std::cout << "node rlp len low and high: \n"
                        << std::hex << this->header.len_low << std::dec << "\t"
                        << std::hex << this->header.len_high << std::dec << std::endl;
                
                std::cout << "key prefix: \n\tdata\tindex\n\t";
                std::cout << std::hex << this->key.header.prefix[0] << std::dec << "\t"
                        << std::hex << this->key.header.prefix_index[0] << std::dec << std::endl;
                std::cout << "second is last\tthird is last\tlen_low\tlen_high\tfirst_element_flag\tfirst_element\tfirst rlc\tsecond rlc\tthird rlc\n\t";
                std::cout << std::hex << this->key.header.second_prefix_padding << std::dec << "\t"
                        << std::hex << this->key.header.third_prefix_padding << std::dec << "\t\t"
                        << std::hex << this->key.header.len_low << std::dec << "\t"
                        << std::hex << this->key.header.len_high << std::dec << "\t\t"
                        << std::hex << this->key.first_element_flag << std::dec << "\t\t\t"
                        << std::hex << this->key.first_element << std::dec << "\t\t"
                        << std::hex << this->key.header.prefix_rlc[0] << std::dec << "\t\t" 
                        << std::hex << this->key.header.prefix_rlc[1] << std::dec << "\t\t"
                        << std::hex << this->key.header.prefix_rlc[2] << std::dec<< std::endl;


                std::cout << "key:\n\tdata\tindex\n";
                for (size_t i = 0; i < this->key.raw.size(); i++) {
                    std::cout << "\t"
                            << std::hex << this->key.data[i] << std::dec << "\t" 
                            << std::hex << this->key.index[i] << std::dec << std::endl;
                }
            
                std::cout << "value prefix: \n\tdata\tindex\n";
                std::cout << "\t" << std::hex << this->value.header.prefix[0] << std::dec << "\t" 
                        << std::hex << this->value.header.prefix_index[0] << std::dec << std::endl;
                std::cout << "\t" << std::hex << this->value.header.prefix[1] << std::dec << "\t"  
                        << std::hex << this->value.header.prefix_index[1] << std::dec << std::endl;

                std::cout << "second is last\tlen_high\tlen_low\tfirst_element_flag\tfirst_element\n\t";
                std::cout << std::hex << this->value.header.second_prefix_padding << std::dec << "\t"
                        << std::hex << this->value.header.len_high << std::dec << "\t"
                        << std::hex << this->value.header.len_low << std::dec << "\t"
                        << std::hex << this->value.first_element_flag << std::dec << "\t\t"
                        << std::hex << this->value.first_element << std::dec << std::endl;
                std::cout << "value: \n";
                for (size_t i = 0; i < this->value.raw.size(); i++) {
                    std::cout << "\t"
                            << std::hex << this->value.data[i] << std::dec << "\t" 
                            << std::hex << this->value.index[i] << std::dec << std::endl;
                }
                std::cout << "rlc: " << this->value.rlc[109] << std::endl;

                // std::cout << "data:\n";
                // for (size_t i = 0; i < this->key.data.size(); i++)
                // {
                //     std::cout << std::hex << this->key.data[i] << std::dec << " ";
                // }
                // std::cout << std::endl;
                
                // std::cout << "is_last:\n";
                // for (size_t i = 0; i < this->key.is_last.size(); i++)
                // {
                //     std::cout << std::hex << this->key.is_last[i] << std::dec << " ";
                // }
                // std::cout << std::endl;
                
            }
    
            void allocate_witness(nil::blueprint::bbf::mpt_leaf<FieldType, stage> &comp){
                std::size_t column_index = 0;
                std::size_t row_index = 0;
                this->header.allocate_witness(comp, column_index, row_index);
                this->key.allocate_witness(comp, column_index, row_index);
                this->value.allocate_witness(comp, column_index, row_index);
                std::cout << "witnessesss " << column_index << std::endl;
            }

            void rlp_lookup_constraints(mpt_leaf<FieldType, stage> &comp) {
                // comp.allocate(this->header.len_high, 2, 0);
                this->header.rlp_lookup_constraints(comp, 0, 0);
                this->key.rlp_lookup_constraints(comp);
                this->value.rlp_lookup_constraints(comp);
            }

            void keccak_lookup_constraint(mpt_leaf<FieldType, stage> &comp) {
                std::size_t leaf_data_size = this->value.rlc.size()-1;
                std::vector<TYPE> keccak_lookup = {
                    1,
                    this->value.rlc[leaf_data_size] * this->not_padding,
                    this->header.hash_high,
                    this->header.hash_low
                };
                comp.lookup(keccak_lookup, "keccak_table");
            }

            void main_constraints(mpt_leaf<FieldType, stage> &comp) {
                constraint_first_rlp_prefix_rlc(comp);
                
                comp.constrain(this->not_padding * (-(this->header.len_low + 0x100 * this->header.len_high) + 
                        (this->key.header.len_low + 0x100 * this->key.header.len_high + 
                         this->value.header.len_low + 0x100 * this->value.header.len_high + 3 - this->value.header.second_prefix_padding)));

                // node first rlp prefix is always keccak 0 index
                this->header.main_constraints(comp, 0, this->not_padding);
                TYPE key_initial_index = this->not_padding + (1 - this->header.second_prefix_padding) + (1 - this->header.third_prefix_padding);
                TYPE key_previous_rlc = this->header.prefix_rlc[2];
                this->key.main_constraints(comp, key_previous_rlc, key_initial_index, this->not_padding);

                TYPE value_initial_index = this->key.header.len_low + this->key.header.len_high * 0x100 + this->key.header.prefix_index[0] + 1 + 1 - this->key.header.second_prefix_padding;
                TYPE value_previous_rlc = this->key.rlc[this->key.rlc.size()-1];
                this->value.main_constraints(comp, value_previous_rlc, value_initial_index, this->not_padding);
            }

            void constraint_first_rlp_prefix_rlc(mpt_leaf<FieldType, stage> &comp) {
                comp.constrain(this->not_padding * (this->header.prefix_rlc[0] - 
                    /* total length */      ((1 + 1 - this->header.second_prefix_padding + 1 - this->header.third_prefix_padding + this->header.len_low + 0x100 * this->header.len_high)
                                            * 53 + this->header.prefix[0])));
            }

            private:
            std::vector<std::uint8_t> hash_input;
            void _initialize_header() {
                this->header.initialize();
                store_hash(calculate_keccak({}, 0));
            }
        };


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
                    .witnesses = 1362,
                    .public_inputs = 0,
                    .constants = 0,
                    .rows = max_mpt_query_size + 2178};
        }

        static void allocate_public_inputs(context_type &context, input_type &input,
                                           std::size_t max_mpt_query_size) {}


        // struct rlp_header {
        //     mpt_type trie_type;
        //     header_type node_type;
        //     std::array<TYPE, 3> prefix;
        //     std::array<TYPE, 3> prefix_rlc;
        //     TYPE second_prefix_padding;
        //     TYPE third_prefix_padding;
        //     std::array<TYPE, 2> prefix_index;
        //     TYPE len_low;
        //     TYPE len_high;
        // }
        // struct content_entry {
        //     mpt_type trie_type;
        //     header_type node_type;
        //     rlp_header header;
        //     std::array<TYPE, 110> data;
        //     std::array<TYPE, 110> index;
        //     std::array<TYPE, 110> index_is_last_I;
        //     std::array<TYPE, 110> index_is_last_R;
        //     std::array<TYPE, 110> is_last;
        //     std::array<TYPE, 110> rlc;
        //     // std::array<std::array<TYPE, 2>,   2> prefix;
        //     // std::array<std::array<TYPE, 2>,   2> prefix_index;
        //     // std::array<std::array<TYPE, 2>,   2> prefix_rlc;
        //     // std::array<TYPE, 2> second_prefix_padding;
        //     // lengths without considering rlp prefixes
        //     // std::array<TYPE, 2> len_low;
        //     // std::array<TYPE, 2> len_high;
        //     // first element flag for rlp lookup
        //     TYPE first_element_flag;
        //     TYPE first_element;
        // };


        // struct node_rlp_data {
        //     TYPE not_padding;
        //     rlp_header header;
            
        //     // the first rlp prefix is not last and its hash and index is known
        //     TYPE hash_low;
        //     TYPE hash_high;
        //     // the key-value stored in this node
        //     node_content content;

        //     node_rlp_data(header_type _h_t, mpt_type _m_t): header(_m_t, _h_t) {}
        // };

        // void initialize_node_rlp_data(std::vector<leaf_node> &nodes) {
        //     for (auto &node : nodes) {
        //         node.initialize_header();
        //     }
        // }

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
            std::vector<leaf_node> nodes;
            // leaf_node sag = leaf_node(mpt_type::storage_trie, 1);
            for (size_t i = 0; i < max_mpt_query_size; i++) {
                nodes.push_back(leaf_node(mpt_type::storage_trie, 1));
            }
            
            
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                leaf_table_inputs.resize(max_mpt_query_size);
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
                    nodes[i].initialize();
                    nodes[i].set_data(key, value);
                    nodes[i].set_indices(input.rlc_challenge);
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
            
            // allocation
            // for (std::size_t i = 0; i < max_mpt_query_size; i++) {

            // }
//                 size_t column_index = 0;

//                 // node
//                 allocate(nodes[i].not_padding, column_index ++, i);
                
//                 // rlp len
//                 allocate(nodes[i].len_low, column_index ++, i);
//                 allocate(nodes[i].len_high, column_index ++, i);
//                 allocate(nodes[i].hash_low, column_index ++, i);
//                 allocate(nodes[i].hash_high, column_index ++, i);
//                 // prefix
//                 allocate(nodes[i].prefix[0], column_index ++, i);
//                 allocate(nodes[i].prefix_rlc[0], column_index ++, i);
//                 allocate(nodes[i].second_prefix_padding, column_index ++, i);
//                 allocate(nodes[i].third_prefix_padding, column_index ++, i);
//                 allocate(nodes[i].prefix[1], column_index ++, i);
//                 allocate(nodes[i].prefix_rlc[1], column_index ++, i);
//                 allocate(nodes[i].prefix_index[0], column_index ++, i);
//                 allocate(nodes[i].prefix[2], column_index ++, i);
//                 allocate(nodes[i].prefix_rlc[2], column_index ++, i);
//                 allocate(nodes[i].prefix_index[1], column_index ++, i);

//                 // children
//                 for (std::size_t j = 0; j < 2; j++) {
//                     // rlp len
//                     allocate(nodes[i].content.len_low[j], column_index ++, i);
//                     allocate(nodes[i].content.len_high[j], column_index ++, i);
//                     // prefix
//                     allocate(nodes[i].content.prefix[j][0], column_index++, i);
//                     allocate(nodes[i].content.prefix_rlc[j][0], column_index++, i);
//                     allocate(nodes[i].content.prefix_index[j][0], column_index++, i);
//                     allocate(nodes[i].content.prefix[j][1], column_index++, i);
//                     allocate(nodes[i].content.prefix_rlc[j][1], column_index++, i);
//                     allocate(nodes[i].content.prefix_index[j][1], column_index++, i);
//                     allocate(nodes[i].content.second_prefix_padding[j], column_index++, i);
//                     allocate(nodes[i].content.first_element_flag[j], column_index++, i);

//                     // encoding
//                     for (std::size_t k = 0; k < 110; k++) {
//                         allocate(nodes[i].content.data[j][k], column_index++, i);
//                         allocate(nodes[i].content.rlc[j][k], column_index++, i);
//                         allocate(nodes[i].content.is_last[j][k], column_index++, i);
//                         allocate(nodes[i].content.index[j][k], column_index++, i);
//                         allocate(nodes[i].content.index_is_last_I[j][k], column_index++, i);
//                         allocate(nodes[i].content.index_is_last_R[j][k], column_index++, i);
//                     }
//                 }

//             }


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
                nodes[i].allocate_witness(*this);
            }

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                // for (size_t i = 0; i < max_mpt_query_size; i++)
                // {
                for (size_t i = 0; i < max_mpt_query_size; i++) {
                    nodes[i].rlp_lookup_constraints(*this);
                    nodes[i].keccak_lookup_constraint(*this);
                    nodes[i].main_constraints(*this);
                }



                // std::vector<TYPE> node_rlp_lookup = {
                //     n.header.prefix[0],
                //     n.header.prefix[1] * n.header.second_prefix_padding,
                //     n.header.prefix[2] * n.header.third_prefix_padding,
                //     0,
                //     0,
                //     n.header.node_type == element_type::string_element,
                //     n.header.len_low, 
                //     n.header.len_high,
                //     n.header.second_prefix_padding,
                //     n.header.third_prefix_padding
                // };
                // lookup(node_rlp_lookup, "rlp_table");

                // }
                
            }


//             for( std::size_t i = 0; i < MPTLeafTable::get_witness_amount(); i++){
//                 leaf_table_lookup_area.push_back(i);
//             }
//             context_type mpt_leaf_ct = context_object.subcontext( leaf_table_lookup_area, max_mpt_query_size + 2178 + keccak_max_blocks, max_mpt_query_size);
//             MPTLeafTable m_t = MPTLeafTable(mpt_leaf_ct, leaf_table_inputs, max_mpt_query_size);

//             if constexpr (stage == GenerationStage::CONSTRAINTS) {
//                 node_rlp_data n = nodes[0];
//                 node_content c = n.content;
//                 std::size_t leaf_data_size = n.content.data[0].size();
//                 std::vector<TYPE> node_rlp_lookup = {
//                     n.prefix[0], 
//                     n.prefix[1],
//                     n.prefix[2],
//                     0,
//                     0,
//                     0,
//                     n.len_low, 
//                     n.len_high,
//                     n.second_prefix_padding,
//                     n.third_prefix_padding
//                 };

//                 std::vector<TYPE> key_rlp_lookup = {
//                     c.prefix[0][0],
//                     c.prefix[0][1],
//                     0,
//                     c.first_element[0],
//                     c.first_element_flag[0],
//                     1,
//                     c.len_low[0], 
//                     c.len_high[0],
//                     // 1,
//                     c.second_prefix_padding[0],
//                     1
//                 };

//                 std::vector<TYPE> value_rlp_lookup = {
//                     c.prefix[1][0],
//                     c.prefix[1][1],
//                     0,
//                     c.first_element[1],
//                     c.first_element_flag[1],
//                     1,
//                     c.len_low[1], 
//                     c.len_high[1],
//                     c.second_prefix_padding[1],
//                     1
//                 };

//                 std::vector<TYPE> keccak_lookup = {
//                     1,
//                     c.rlc[1][leaf_data_size-1] * n.not_padding,
//                     n.hash_high,
//                     n.hash_low
//                 };
//                 context_object.relative_lookup(context_object.relativize(node_rlp_lookup, 0), "rlp_table", 0, max_mpt_query_size - 1);
//                 context_object.relative_lookup(context_object.relativize(key_rlp_lookup, 0), "rlp_table", 0, max_mpt_query_size - 1);
//                 context_object.relative_lookup(context_object.relativize(value_rlp_lookup, 0), "rlp_table", 0, max_mpt_query_size - 1);
//                 context_object.relative_lookup(context_object.relativize(keccak_lookup, 0), "keccak_table", 0, max_mpt_query_size - 1);
                
//                 std::vector<TYPE> consts;
//                 consts.push_back(context_object.relativize((n.second_prefix_padding*(1 - n.second_prefix_padding)), 0));
//                 consts.push_back(context_object.relativize((n.prefix[1] * n.second_prefix_padding), 0));
//                 consts.push_back(context_object.relativize((n.prefix[2] * n.third_prefix_padding), 0));
//                 consts.push_back(context_object.relativize((c.second_prefix_padding[1] * (1 - c.second_prefix_padding[1])), 0));
//                 consts.push_back(context_object.relativize((c.second_prefix_padding[0] * (1 - c.second_prefix_padding[0])), 0));
//                 consts.push_back(context_object.relativize((n.not_padding * (n.prefix_rlc[0] - 
// /* total length */      ((1 + 1 - n.second_prefix_padding + 1 - n.third_prefix_padding + n.len_low + 0x100 * n.len_high)
//                         * 53 + n.prefix[0]))), 0));

//                 consts.push_back(context_object.relativize((n.prefix_rlc[1] - ((1 - n.second_prefix_padding) * (n.prefix_rlc[0] * 53 + n.prefix[1]) + n.second_prefix_padding * n.prefix_rlc[0])), 0));
//                 consts.push_back(context_object.relativize((n.prefix_rlc[2] - ((1 - n.third_prefix_padding) *  (n.prefix_rlc[1] * 53 + n.prefix[2]) + n.third_prefix_padding * n.prefix_rlc[1])), 0));

//                 consts.push_back(context_object.relativize((n.not_padding * (-(n.len_low + 0x100 * n.len_high)
//                         + c.len_low[0] + 0x100 * c.len_high[0] 
//                         + c.len_low[1] + 0x100 * c.len_high[1] 
//                         + 3 - c.second_prefix_padding[1])), 0));

//                 // node first rlp prefix is always keccak 0 index
//                 consts.push_back(context_object.relativize((n.prefix_index[0] - (1 - n.second_prefix_padding)), 0));
//                 consts.push_back(context_object.relativize((n.prefix_index[1] * n.third_prefix_padding + (2-n.prefix_index[1])*(1-n.third_prefix_padding)), 0));
//                 for (size_t k = 0; k < 2; k++) {
//                     if (k == 0) {
//                         consts.push_back(context_object.relativize(c.prefix_index[k][0] - n.not_padding - (1 - n.second_prefix_padding) + (1 - n.third_prefix_padding), 0));
//                         consts.push_back(context_object.relativize(c.prefix_rlc[k][0] - (n.prefix_rlc[2] * 53 + c.prefix[0][0]), 0));
//                     } else {
//                         consts.push_back(context_object.relativize(c.prefix_index[k][0] - 
//                             (c.len_low[k-1] + c.len_high[k-1] * 0x100 + c.prefix_index[k-1][0] + n.not_padding - c.second_prefix_padding[k-1] + 1), 0));
//                         consts.push_back(context_object.relativize(c.prefix_rlc[k][0] - (c.rlc[k-1][leaf_data_size-1] * 53 + c.prefix[k][0]), 0));
//                     }
//                     consts.push_back(context_object.relativize(c.prefix_index[k][1] - (1 - c.second_prefix_padding[k]) * (c.prefix_index[k][0] + n.not_padding), 0));
//                     consts.push_back(context_object.relativize(c.prefix_rlc[k][1] - ((1 - c.second_prefix_padding[k]) * (c.prefix_rlc[k][0] * 53 + c.prefix[k][1]) + c.second_prefix_padding[k] * c.prefix_rlc[k][0]), 0));
//                     consts.push_back(context_object.relativize(c.index[k][0] - (1 - c.second_prefix_padding[k]) - c.prefix_index[k][0] - n.not_padding, 0));
//                     consts.push_back(context_object.relativize(c.rlc[k][0] - (c.prefix_rlc[k][1] * 53 + c.data[k][0]), 0));

//                     consts.push_back(context_object.relativize(c.data[k][0] * c.is_last[k][0], 0));
//                     for (size_t i = 1; i < leaf_data_size; i++) {
//                         consts.push_back(context_object.relativize((1 - c.is_last[k][i]) * c.is_last[k][i], 0));
//                         consts.push_back(context_object.relativize((1 - c.is_last[k][i]) * c.is_last[k][i-1], 0));
                        
//                         consts.push_back(context_object.relativize(n.not_padding * (c.index_is_last_R[k][i] - (1 - 
//                             c.index_is_last_I[k][i] * ((c.len_low[k] + c.len_high[k] * 0x100) - (c.index[k][i] - c.index[k][0] + 1)))), 0));
//                         consts.push_back(context_object.relativize(((c.len_low[k] + c.len_high[k] * 0x100) - (c.index[k][i] - c.index[k][0] + 1)) * c.index_is_last_R[k][i], 0));
//                         consts.push_back(context_object.relativize(c.is_last[k][i] - c.index_is_last_R[k][i] - c.is_last[k][i-1], 0));
//                         consts.push_back(context_object.relativize(c.index[k][i] * c.is_last[k][i-1], 0));
//                         consts.push_back(context_object.relativize((c.index[k][i] - c.index[k][i-1] - 1) * (1 - c.is_last[k][i-1]), 0));
//                         consts.push_back(context_object.relativize(c.data[k][i] * c.is_last[k][i-1], 0));
//                         consts.push_back(context_object.relativize(c.rlc[k][i] - (c.is_last[k][i-1] * c.rlc[k][i-1] + (1 - c.is_last[k][i-1]) * (c.rlc[k][i-1] * 53 + c.data[k][i])), 0));
//                     }
//                 }
//                 for (size_t i = 0; i < consts.size(); i++) {
//                     context_object.relative_constrain(consts[i], 0, max_mpt_query_size - 1);
//                 }
//             }
        }
        
        // std::size_t get_leaf_key_length(std::vector<zkevm_word_type> key) {
        //     TYPE key_first_byte = key[0];
        //     size_t key_length = key.size();
        //     BOOST_ASSERT_MSG(key_length <= 32, "leaf node key length exceeded!");
        //     return get_rlp_encoded_length(key_first_byte, key_length);
        // }
        
        // std::size_t get_leaf_value_length(std::vector<zkevm_word_type> value) {
        //     TYPE value_first_byte = value[0];
        //     size_t value_length = value.size();
        //     BOOST_ASSERT_MSG(value_length <= 110, "leaf node value length exceeded!");
        //     return get_rlp_encoded_length(value_first_byte, value_length);
        // }

        // void encode_node_data(node_rlp_data &node, std::size_t total_length, std::size_t &rlp_encoding_index, std::vector<std::uint8_t> &hash_input, TYPE &rlc_accumulator, TYPE rlc_challenge) {
        //     rlp_encoding_index = 0;
        //     if (total_length > 55) {
        //         std::size_t length_length = 0;
        //         std::size_t temp = total_length;

        //         while(temp > 0) {
        //             temp >>= 8;
        //             length_length ++;
        //         }
        //         node.prefix[0] = 0xF7 + length_length;
        //         node.prefix[1] = total_length;
        //         node.prefix[2] = 0;
        //         node.prefix_index[0] = rlp_encoding_index+1;

        //         node.second_prefix_padding = 0;
        //         node.third_prefix_padding = 1;

        //         hash_input[rlp_encoding_index++] = 0xF7 + length_length;
        //         hash_input[rlp_encoding_index++] = total_length;

        //         node.prefix_rlc[0] = (total_length+2) * rlc_challenge + node.prefix[0];
        //         rlc_accumulator = node.prefix_rlc[0];
        //         node.prefix_rlc[1] = rlc_accumulator * rlc_challenge + node.prefix[1];
        //         rlc_accumulator = node.prefix_rlc[1];
        //         node.prefix_rlc[2] = rlc_accumulator;
        //     } else {
        //         node.prefix[0] = 0xC0 + total_length;
        //         node.second_prefix_padding = 1;
        //         node.third_prefix_padding = 1;
        //         node.prefix_index[0] = 0;

        //         hash_input[rlp_encoding_index++] = uint8_t((0xC0 + total_length) & 0xFF);
        //         node.prefix_rlc[0] = (total_length+1) * rlc_challenge + node.prefix[0];
        //         rlc_accumulator = node.prefix_rlc[0];
        //         node.prefix_rlc[1] = rlc_accumulator;
        //         node.prefix_rlc[2] = rlc_accumulator;
        //     }

        //     node.len_low = total_length & 0xFF;
        //     node.len_high = (total_length >> 8) & 0xFF;
        //     node.not_padding = 1;
        // }

        // void encode_leaf_data(node_content &content, std::vector<zkevm_word_type> key, std::vector<zkevm_word_type> value, std::size_t& rlp_encoding_index, std::vector<std::uint8_t> &hash_input, TYPE &rlc_accumulator, TYPE rlc_challenge) {
        //     std::vector<std::vector<zkevm_word_type>> data = {key, value}; 
        //     for (size_t i = 0; i < data.size(); i++) {
        //         // std::cout <<"    value = ";
        //         auto d = data[i];
        //         for (size_t j = 0; j < d.size(); j++) {
        //             // if (d[j] <= 0x0F)
        //             //     std::cout <<"0" << std::hex << d[j] << std::dec;
        //             // else
        //             //     std::cout << std::hex << d[j] << std::dec;
        //             content.data[i][j] = d[j];
        //             content.is_last[i][j] = 0;
        //         }
        //         if (d.size() > 0) {
        //             content.is_last[i][d.size() - 1] = 1;
        //         }
        //         if (d.size() == 0 || (d.size() == 1 && d[0] < 128)) {
        //             if (d.size() == 1)
        //                 content.first_element[i] = d[0];
        //             content.first_element_flag[i] = 1;
        //         } else {
        //             content.first_element_flag[i] = 0;
        //         }
        //         // std::cout << " size: " << d.size();
        //         // std::cout << std::endl;
        //     }
        //     // std::cout << "]" << std::endl;

        //     if (key.size() == 1) { // first byte of key in leaf nodes is always less than 0x7F due to leaf node encoding
        //         // TODO child_prefix_is_last[nodenum][0][0] must be true
        //     } else if (key.size() <= 33) {
        //         content.prefix[0][0] = 0x80 + key.size();
        //         content.second_prefix_padding[0] = 1;
        //         content.prefix_index[0][0] = rlp_encoding_index;

        //         hash_input[rlp_encoding_index++] = uint8_t(0x80 + key.size());

        //         content.prefix_rlc[0][0] = rlc_accumulator * rlc_challenge + content.prefix[0][0];
        //         rlc_accumulator = content.prefix_rlc[0][0];
        //         content.prefix_rlc[0][1] = rlc_accumulator;
        //     }

        //     content.len_low[0] = key.size();
        //     content.len_high[0] = 0;
        //     // maximum lengths: 
        //     //      rlp encoded leaf node = 144 + 2 bytes
        //     //      key = 33 bytes
        //     //      value = 108 bytes
        //     //      rlp encoded key = 34 bytes
        //     //      rlp encoded value = 110 bytes


        //     for (size_t j = 0; j < key.size(); j++) {
        //         content.index[0][j] = rlp_encoding_index;
        //         hash_input[rlp_encoding_index++] = uint8_t(key[j]);

        //         content.rlc[0][j] = rlc_accumulator * rlc_challenge + content.data[0][j];
        //         rlc_accumulator = content.rlc[0][j];
        //     }
        //     for (size_t j = key.size(); j < content.rlc[0].size(); j++) {
        //         content.rlc[0][j] = rlc_accumulator;
        //     }

        //     if (value.size() == 1 && value[0] <= 0x7F) {
        //         // TODO
        //     } else if (value.size() <= 55) {
        //         content.prefix[1][0] = 0x80 + value.size();
        //         content.prefix_index[1][0] = rlp_encoding_index;
        //         hash_input[rlp_encoding_index++] = uint8_t(0x80 + value.size());

        //         content.prefix_rlc[1][0] = rlc_accumulator * rlc_challenge + content.prefix[1][0];
        //         rlc_accumulator = content.prefix_rlc[1][0];
        //         content.prefix_rlc[1][1] = rlc_accumulator;
        //     } else {
        //         content.prefix[1][0] = 0xB8;
        //         content.prefix_index[1][0] = rlp_encoding_index;
        //         content.prefix[1][1] = value.size();
        //         content.prefix_index[1][1] = rlp_encoding_index+1;
        //         content.second_prefix_padding[1] = 0;
                
        //         hash_input[rlp_encoding_index++] = uint8_t(0xB8);
        //         hash_input[rlp_encoding_index++] = value.size();

        //         content.prefix_rlc[1][0] = rlc_accumulator * rlc_challenge + content.prefix[1][0];
        //         rlc_accumulator = content.prefix_rlc[1][0];
        //         content.prefix_rlc[1][1] = rlc_accumulator * rlc_challenge + content.prefix[1][1];
        //         rlc_accumulator = content.prefix_rlc[1][1];
        //     }

        //     content.len_low[1] = value.size();
        //     content.len_high[1] = 0;

        //     for (size_t j = 0; j < value.size(); j++) {
        //         content.index[1][j] = rlp_encoding_index;
        //         hash_input[rlp_encoding_index++] = uint8_t(value[j]);

        //         content.rlc[1][j] = rlc_accumulator * rlc_challenge + content.data[1][j];
        //         rlc_accumulator = content.rlc[1][j];
        //     }
        //     for (size_t j = value.size(); j < content.rlc[1].size(); j++) {
        //         content.rlc[1][j] = rlc_accumulator;
        //     }


        //     for (size_t k = 0; k < 2; k++) {
        //         TYPE len = content.len_low[k] + content.len_high[k] * 0x100;
        //         for (size_t j = 0; j < 110; j++) {
        //             if ( content.index[k][j] - content.index[k][0] == len - 1) {
        //                 content.index_is_last_I[k][j] = 0;
        //             } else {
        //                 content.index_is_last_I[k][j] = 
        //                     (len - 1 - (content.index[k][j] - content.index[k][0])).inversed();
        //             }
        //             content.index_is_last_R[k][j] = 1 - 
        //                 (len - 1 - (content.index[k][j] - content.index[k][0])) 
        //                 * content.index_is_last_I[k][j];
        //         }
        //     }
        // }


        // void print_leaf_node(node_rlp_data &node, zkevm_word_type hash, size_t key_data_len, size_t value_data_len) {
        //     node_content content = node.content;
        //     TYPE hash_low = w_lo<FieldType>(hash);
        //     TYPE hash_high = w_hi<FieldType>(hash);

        //     std::cout << "rlp prefix:" << std::endl;
        //     std::cout << "\tdata\tindex\n";

        //     std::cout << "\t" << std::hex << node.prefix[0] << std::dec << "\t"
        //               << std::hex << hash_high << std::dec << "\t"
        //               << std::hex << hash_low << std::dec << "\t"
        //               << std::hex << 0 << std::dec << std::endl;
        //     std::cout << "\t" << std::hex << node.prefix[1] << std::dec << "\t"
        //               << std::hex << node.prefix_index[0] << std::dec << std::endl;
        //     std::cout << "\t" << std::hex << node.prefix[2] << std::dec << "\t"
        //               << std::hex << node.prefix_index[1] << std::dec << std::endl;
            
        //     std::cout << "node rlp second prefix is last:\n "
        //               << std::hex << node.second_prefix_padding << std::dec << std::endl;
        //     std::cout << "node rlp len low and high: \n"
        //               << std::hex << node.len_low << std::dec << "\t"
        //               << std::hex << node.len_high << std::dec << std::endl;
            
        //     std::cout << "key prefix: \n\tdata\tindex\n\t";
        //     std::cout << std::hex << content.prefix[0][0] << std::dec << "\t"
        //               << std::hex << content.prefix_index[0][0] << std::dec << std::endl;
        //     std::cout << "second is last\tlen_low\tlen_high\tfirst_element_flag\tfirst_element\n\t";
        //     std::cout << std::hex << content.second_prefix_padding[0] << std::dec << "\t"
        //               << std::hex << content.len_low[0] << std::dec << "\t"
        //               << std::hex << content.len_high[0] << std::dec << "\t\t"
        //               << std::hex << content.first_element_flag[0] << std::dec << "\t\t"
        //               << std::hex << content.first_element[0] << std::dec << std::endl;


        //     std::cout << "key:\n\tdata\tindex\n";
        //     for (size_t i = 0; i < key_data_len; i++) {
        //         std::cout << "\t"
        //                   << std::hex << content.data[0][i] << std::dec << "\t" 
        //                   << std::hex << content.index[0][i] << std::dec << std::endl;
        //     }
        
        //     std::cout << "value prefix: \n\tdata\tindex\n";
        //     std::cout << "\t" << std::hex << content.prefix[1][0] << std::dec << "\t" 
        //               << std::hex << content.prefix_index[1][0] << std::dec << std::endl;
        //     std::cout << "\t" << std::hex << content.prefix[1][1] << std::dec << "\t"  
        //               << std::hex << content.prefix_index[1][1] << std::dec << std::endl;

        //     std::cout << "second is last\tlen_high\tlen_low\tfirst_element_flag\tfirst_element\n\t";
        //     std::cout << std::hex << content.second_prefix_padding[1] << std::dec << "\t"
        //               << std::hex << content.len_high[1] << std::dec << "\t"
        //               << std::hex << content.len_low[1] << std::dec << "\t"
        //               << std::hex << content.first_element_flag[1] << std::dec << "\t\t"
        //               << std::hex << content.first_element[1] << std::dec << std::endl;
        //     std::cout << "value: \n";
        //     for (size_t i = 0; i < value_data_len; i++) {
        //         std::cout << "\t"
        //                   << std::hex << content.data[1][i] << std::dec << "\t" 
        //                   << std::hex << content.index[1][i] << std::dec << std::endl;
        //     }
        // }
    };
}  // namespace nil::blueprint::bbf
