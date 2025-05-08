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


    template<typename FieldType, GenerationStage stage>
    class node_header: public generic_component<FieldType, stage> {
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

      struct input_type {};

        using typename generic_component<FieldType, stage>::table_params;
        using typename generic_component<FieldType, stage>::TYPE;
        // mpt_type trie_type;
        inner_node_type node_type;
        std::array<TYPE, 3> prefix;
        std::array<TYPE, 3> prefix_rlc;
        TYPE prefix_first_exists;
        TYPE prefix_second_exists; // if 1 second prefix does not exist
        TYPE prefix_third_exists; // if 1 third prefix does not exist
        TYPE prefix_second_flag;
        TYPE prefix_second_image;
        std::array<TYPE, 3> prefix_index;
        TYPE len;
        TYPE len_image;
        TYPE hash_low;
        TYPE hash_high;
        TYPE rlc_challenge;

        std::size_t raw_data_length;
        
        node_header(
            context_type &context_object,
            // mpt_type _trie_t,
            inner_node_type _node_t,
            TYPE _rlc_challenge
        ): generic_component<FieldType, stage>(context_object, false),
        node_type(_node_t) {
            rlc_challenge = _rlc_challenge;
        }
        // void set_challenge(TYPE &_rlc_challenge) {
        //     rlc_challenge = _rlc_challenge;
        // }

        void initialize() {
            prefix_first_exists = 1;
            prefix_second_exists = 0;
            prefix_third_exists = 0;
            prefix_second_flag = 1;
            prefix_second_image = 0;
            len = 0;
            len_image = 0;
            prefix[0] = 0xC0;
        }

        void main_constraints(TYPE previous_rlc, TYPE initial_index, TYPE not_padding) {
            constrain(prefix[0] * (1 - prefix_first_exists));
            constrain(prefix[1] * (1 - prefix_second_exists));
            constrain(prefix[2] * (1 - prefix_third_exists));

            constrain(prefix_index[0] - prefix_first_exists * initial_index);
            constrain(prefix_index[1] - prefix_second_exists * (prefix_index[0] + 1));
            constrain(prefix_index[2] - prefix_third_exists * (prefix_index[1] + 1));
            
            constrain(prefix_rlc[0] - (prefix_first_exists * (previous_rlc * 53 + prefix[0]) + (1 - prefix_first_exists) * previous_rlc));
            constrain(prefix_rlc[1] - (prefix_second_exists * (prefix_rlc[0] * 53 + prefix[1]) + (1 - prefix_second_exists) * prefix_rlc[0]));
            constrain(prefix_rlc[2] - (prefix_third_exists *  (prefix_rlc[1] * 53 + prefix[2]) + (1 - prefix_third_exists) * prefix_rlc[1]));
        }

        void set_metadata(std::vector<std::uint8_t> &hash_input, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            BOOST_ASSERT_MSG(node_type == inner_node_type::array, "wrong method is called!");
            BOOST_ASSERT_MSG(raw_data_length <= 65535, "data length more than 65535 bytes!");
            if (raw_data_length < 56) {
                // array encoding with length less than 56 bytes
                prefix[0] = 0xC0 + raw_data_length;
                prefix[1] = 0;
                prefix[2] = 0;

                prefix_rlc[0] = rlc_accumulator * rlc_challenge + prefix[0];
                rlc_accumulator = prefix_rlc[0];
                prefix_rlc[1] = rlc_accumulator;
                prefix_rlc[2] = rlc_accumulator;

                prefix_first_exists = 1;
                prefix_second_exists = 0;
                prefix_third_exists = 0;
                prefix_second_flag = 1;
                prefix_second_image = prefix[1];

                prefix_index[0] = rlp_encoding_index;
                prefix_index[1] = 0;
                prefix_index[2] = 0;
                len_image = raw_data_length;

                hash_input[rlp_encoding_index++] = uint8_t(0xC0 + raw_data_length);

            } else if (raw_data_length >= 56 && raw_data_length < 256) {
                // array encoding with length between 56 and 255
                prefix[0] = 0xF7 + 1;
                prefix[1] = raw_data_length;
                prefix[2] = 0;

                prefix_rlc[0] = rlc_accumulator * rlc_challenge + prefix[0];
                rlc_accumulator = prefix_rlc[0];
                prefix_rlc[1] = rlc_accumulator * rlc_challenge + prefix[1];
                prefix_rlc[2] = prefix_rlc[1];

                prefix_first_exists = 1;
                prefix_second_exists = 1;
                prefix_third_exists = 0;
                prefix_second_flag = 1;
                prefix_second_image = prefix[1];

                prefix_index[0] = rlp_encoding_index;
                prefix_index[1] = rlp_encoding_index+1;
                prefix_index[2] = 0;
                len_image = raw_data_length;

                hash_input[rlp_encoding_index++] = 0xF7 + 1;
                hash_input[rlp_encoding_index++] = uint8_t(raw_data_length);
            } else {
                // array encoding with length between 256 and 65535
                prefix[0] = 0xF7 + 2;
                prefix[1] = raw_data_length & 0xFF;
                prefix[2] = raw_data_length >> 8;

                prefix_rlc[0] = rlc_accumulator * rlc_challenge + prefix[0];
                rlc_accumulator = prefix_rlc[0];
                prefix_rlc[1] = rlc_accumulator * rlc_challenge + prefix[1];
                rlc_accumulator = prefix_rlc[1];
                prefix_rlc[2] = rlc_accumulator * rlc_challenge + prefix[2];

                prefix_first_exists = 1;
                prefix_second_exists = 1;
                prefix_third_exists = 1;
                prefix_second_flag = 0;
                prefix_second_image = 0;

                prefix_index[0] = rlp_encoding_index;
                prefix_index[1] = rlp_encoding_index+1;
                prefix_index[2] = 0;
                len_image = 0;

                hash_input[rlp_encoding_index++] = 0xF7 + 2;
                hash_input[rlp_encoding_index++] = uint8_t(raw_data_length & 0xFF);
                hash_input[rlp_encoding_index++] = uint8_t(raw_data_length >> 8);
            }
            rlc_accumulator = prefix_rlc[0];
        }

        void set_metadata(std::vector<std::uint8_t> &hash_input, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator, 
            zkevm_word_type first_element) {
            
            BOOST_ASSERT_MSG(node_type != inner_node_type::array, "wrong method is called!");
            BOOST_ASSERT_MSG(raw_data_length <= 65535, "data length more than 65535 bytes!");

            if (raw_data_length == 0) {
                // string encoding with zero length
                prefix[0] = 0x80;
                prefix[1] = 0;
                prefix[2] = 0;

                prefix_rlc[0] = rlc_challenge * rlc_challenge + prefix[0];
                prefix_rlc[1] = prefix_rlc[0];
                prefix_rlc[2] = prefix_rlc[1];

                prefix_first_exists = 1;
                prefix_second_exists = 1;
                prefix_third_exists = 0;
                prefix_second_flag = 1;
                prefix_second_image = prefix[1];

                prefix_index[0] = 1;
                prefix_index[1] = 0;
                prefix_index[2] = 0;
                len_image = raw_data_length;

                hash_input[rlp_encoding_index++] = 0x80;
            } if (raw_data_length == 1 && first_element <= 0x7F) {
                // string encoding with single bytes and value less than 128
                prefix[0] = 0;
                prefix[1] = 0;
                prefix[2] = 0;

                prefix_rlc[0] = rlc_challenge;
                prefix_rlc[1] = rlc_challenge;
                prefix_rlc[2] = rlc_challenge;

                prefix_first_exists = 0;
                prefix_second_exists = 0;
                prefix_third_exists = 0;
                prefix_second_flag = 1;
                prefix_second_image = prefix[1];

                prefix_index[0] = 0;
                prefix_index[1] = 0;
                prefix_index[2] = 0;
                len_image = raw_data_length;
            } else if (raw_data_length == 1) {
                // string encoding with single bytes and value between 128 and 256
                prefix[0] = 0x80 + 1;
                prefix[1] = 0;
                prefix[2] = 0;

                prefix_rlc[0] = rlc_challenge * rlc_challenge + prefix[0];
                prefix_rlc[1] = prefix_rlc[0];
                prefix_rlc[2] = prefix_rlc[1];

                prefix_first_exists = 1;
                prefix_second_exists = 0;
                prefix_third_exists = 0;
                prefix_second_flag = 1;
                prefix_second_image = prefix[1];

                prefix_index[0] = rlp_encoding_index;
                prefix_index[1] = 0;
                prefix_index[2] = 0;
                len_image = raw_data_length;
                
                hash_input[rlp_encoding_index++] = 0x80 + 1;
            } else if (raw_data_length >= 2 && raw_data_length < 56) {
                // string encoding with length between 2 to 55 bytes
                prefix[0] = 0x80 + raw_data_length;
                prefix[1] = 0;
                prefix[2] = 0;

                prefix_rlc[0] = rlc_accumulator * rlc_challenge + prefix[0];
                rlc_accumulator = prefix_rlc[0];
                prefix_rlc[1] = rlc_accumulator;
                prefix_rlc[2] = rlc_accumulator;

                prefix_first_exists = 1;
                prefix_second_exists = 0;
                prefix_third_exists = 0;
                prefix_second_flag = 1;
                prefix_second_image = prefix[1];

                prefix_index[0] = rlp_encoding_index;
                prefix_index[1] = 0;
                prefix_index[2] = 0;
                len_image = raw_data_length;

                hash_input[rlp_encoding_index++] = uint8_t(0x80 + raw_data_length);

            } else if (raw_data_length >= 56 && raw_data_length < 256) {
                // string encoding with length between 56 and 255
                prefix[0] = 0xB7 + 1;
                prefix[1] = raw_data_length;
                prefix[2] = 0;

                prefix_rlc[0] = rlc_accumulator * rlc_challenge + prefix[0];
                rlc_accumulator = prefix_rlc[0];
                prefix_rlc[1] = rlc_accumulator * rlc_challenge + prefix[1];
                rlc_accumulator = prefix_rlc[1];
                prefix_rlc[2] = rlc_accumulator;

                prefix_first_exists = 1;
                prefix_second_exists = 1;
                prefix_third_exists = 0;
                prefix_second_flag = 1;
                prefix_second_image = prefix[1];

                prefix_index[0] = rlp_encoding_index;
                prefix_index[1] = rlp_encoding_index+1;
                prefix_index[2] = 0;
                len_image = raw_data_length;

                hash_input[rlp_encoding_index++] = uint8_t(0xB7 + 1);
                hash_input[rlp_encoding_index++] = uint8_t(raw_data_length);

            } 
            
            rlc_accumulator = prefix_rlc[0];
        }

        void set_data_length(std::size_t _raw_data_length) {
            if (node_type == inner_node_type::storage_value)
                BOOST_ASSERT_MSG(_raw_data_length <= 32, "Data size exceeded 32 bytes for storage values!");
            else if (node_type == inner_node_type::array)
                BOOST_ASSERT_MSG(_raw_data_length <= 110, "We only support array of up to 110 bytes!");
            else if (node_type == inner_node_type::nonce)
                BOOST_ASSERT_MSG(_raw_data_length <= 8, "Data size exceeded 8 bytes for nonce!");
            else if (node_type == inner_node_type::balance)
                BOOST_ASSERT_MSG(_raw_data_length <= 32, "Data size exceeded 32 bytes for balance!");
            else if (node_type == inner_node_type::storage_root)
                BOOST_ASSERT_MSG(_raw_data_length <= 32, "Data size exceeded 32 bytes for storage hash!");
            else if (node_type == inner_node_type::code_hash)
                BOOST_ASSERT_MSG(_raw_data_length <= 32, "Data size exceeded 32 bytes for code hash!");

            raw_data_length = _raw_data_length;
            len = raw_data_length;
        }

        std::size_t get_total_length() {
            BOOST_ASSERT_MSG(node_type == inner_node_type::array, "wrong method is called!");
            if (raw_data_length <= 55) {
                return raw_data_length + 1;
            } else {
                std::size_t len_len=0;
                std::size_t tmp = raw_data_length;
                while (tmp > 0) {
                    len_len += 1;
                    tmp >>= 4;
                }
                return len_len + raw_data_length + 1;
            }
        }

        std::size_t get_total_length(TYPE first_element) {
            BOOST_ASSERT_MSG(node_type != inner_node_type::array, "wrong method is called!");
            if (raw_data_length == 1 && first_element <= 0x7F) {
                return 1;
            } else if (raw_data_length <= 55) {
                return raw_data_length + 1;
            } else {
                std::size_t len_len=0;
                std::size_t tmp = raw_data_length;
                while (tmp > 0) {
                    len_len += 1;
                    tmp >>= 4;
                }
                return len_len + raw_data_length + 1;
            }
        }

        TYPE get_prefix_length() {
            return prefix_first_exists + prefix_second_exists + prefix_third_exists;
        }
    
        TYPE get_total_length_constraint() {
            return len + get_prefix_length();
        }


        void rlp_lookup_constraints(TYPE first_element_image, TYPE first_element, TYPE first_element_flag) {
            std::vector<TYPE> node_rlp_lookup = {
                prefix[0],
                prefix_second_image,
                prefix[2],
                prefix_second_flag,
                first_element_flag,
                first_element_image,
                node_type != inner_node_type::array,
                len_image
            };
            lookup(node_rlp_lookup, "rlp_table");
            constrain(prefix_second_flag * (prefix_second_image - prefix[1]));
            if (node_type != inner_node_type::array)
                constrain(first_element_flag * (first_element_image - first_element));
            constrain((1 - prefix_third_exists) * (len - len_image));
        }

        void allocate_witness(std::size_t &column_index, std::size_t &row_index) {
            // rlp len
            allocate(len, column_index ++, row_index);
            allocate(len_image, column_index ++, row_index);
            allocate(hash_low, column_index ++, row_index);
            allocate(hash_high, column_index ++, row_index);
            allocate(prefix_first_exists, column_index ++, row_index);
            allocate(prefix_second_exists, column_index ++, row_index);
            allocate(prefix_third_exists, column_index ++, row_index);
            allocate(prefix_second_flag, column_index ++, row_index);
            allocate(prefix_second_image, column_index ++, row_index);
            // pefix
            for (size_t i = 0; i < 3; i++) {
                allocate(prefix[i], column_index ++, row_index);
                allocate(prefix_rlc[i], column_index ++, row_index);
                allocate(prefix_index[i], column_index ++, row_index);
            }
        }
    
        void print() {
            std::cout << "\tdata\tindex\n";
            std::cout << "\t" << std::hex << prefix[0] << std::dec << "\t"
                    << std::hex << prefix_index[0] << std::dec << std::endl;
            std::cout << "\t" << std::hex << prefix[1] << std::dec << "\t"
                    << std::hex << prefix_index[1] << std::dec << std::endl;
            std::cout << "\t" << std::hex << prefix[2] << std::dec << "\t"
                    << std::hex << prefix_index[2] << std::dec << std::endl;
            
            std::cout << "prefix exists: " << 
                    std::hex << prefix_first_exists << std::dec << " " <<
                    std::hex << prefix_second_exists << std::dec << " " <<
                    std::hex << prefix_third_exists << std::dec << std::endl;
            std::cout << "second prefix flag:\t second prefix image\n"
                       << std::hex << prefix_second_flag << std::dec << "\t"
                       << std::hex << prefix_second_image << std::dec << std::endl;
            std::cout << "len and len_image: \n"
                    << std::hex << len << std::dec << "\t"
                    << std::hex << len_image<< std::dec << std::endl;
        }
    };

    template<typename FieldType, GenerationStage stage>
    class node_inner: public generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

      public:
      struct input_type {};
        using typename generic_component<FieldType, stage>::table_params;
        using typename generic_component<FieldType, stage>::TYPE;
        node_header<FieldType, stage> header;
        inner_node_type node_type;
        mpt_type trie_type;
        std::vector<TYPE> data;
        std::vector<TYPE> index;
        std::vector<TYPE> is_last_I;
        std::vector<TYPE> is_last_R;
        std::vector<TYPE> is_last;
        std::vector<TYPE> rlc;
        std::vector<zkevm_word_type> raw;
        TYPE first_element_image;
        TYPE first_element_flag;
        TYPE rlc_challenge;

        // in case this node is of array_element type
        std::vector<node_inner> inners;

        node_inner( 
            context_type &context_object,
            inner_node_type _n_type, 
            mpt_type _trie_type,
            TYPE _rlc_challenge):
            generic_component<FieldType, stage>(context_object, false),
            header(context_object, _n_type, _rlc_challenge), 
            node_type(_n_type), 
            trie_type(_trie_type),
            rlc_challenge(_rlc_challenge) {
            BOOST_ASSERT_MSG(_n_type != inner_node_type::array, "no array yet!");
            if (_n_type == inner_node_type::array) {
                if (_trie_type == mpt_type::account_trie) {
                    // TODO
                    inners.push_back(node_inner(context_object, inner_node_type::nonce, _trie_type, rlc_challenge));
                    inners.push_back(node_inner(context_object, inner_node_type::balance, _trie_type, rlc_challenge));
                    inners.push_back(node_inner(context_object, inner_node_type::storage_root, _trie_type, rlc_challenge));
                    inners.push_back(node_inner(context_object, inner_node_type::code_hash, _trie_type, rlc_challenge));
                }
            } else {
            }
            data.resize(110);
            index.resize(110);
            is_last_I.resize(110);
            is_last_R.resize(110);
            is_last.resize(110);
            rlc.resize(110);
        }


        // static context_type& get_context(context_type &context_object, std::size_t start) {
        //     std::vector<std::size_t> leaf_area;
        //     for( std::size_t i = 0; i < 2000; i++){
        //         leaf_area.push_back(i);
        //     }
        //     return context_object.subcontext( leaf_area, start+1, 1);
        // }

        // void set_challenge(TYPE &_rlc_challenge) {
        //     rlc_challenge = _rlc_challenge;
        //     header.set_challenge(rlc_challenge);
        //     if (node_type == inner_node_type::array) {
        //         for (auto &i : inners) {
        //             i.set_challenge(rlc_challenge);
        //         }
        //     } 
        // }

        void initialize() {
            _initialize_header();
            _initialize_body();
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

        void set_metadata(std::vector<std::uint8_t> &hash_input, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            this->header.set_metadata(hash_input, rlp_encoding_index, rlc_accumulator, this->raw[0]);
            if (this->node_type != inner_node_type::array) {
                for (size_t j = 0; j < raw.size(); j++) {
                    index[j] = rlp_encoding_index;
                    hash_input[rlp_encoding_index++] = uint8_t(raw[j]);

                    rlc[j] = rlc_accumulator * rlc_challenge + raw[j];
                    rlc_accumulator = rlc[j];
                }
                for (size_t j = raw.size(); j < rlc.size(); j++) {
                    rlc[j] = rlc_accumulator;
                }
            } else {
                // TODO fix this
            }
        }

        void set_is_last() {
            // TODO fix type
            BOOST_ASSERT_MSG(node_type != inner_node_type::array, "wrong method is called!");
            TYPE len = header.raw_data_length;
            for (size_t j = 0; j < data.size(); j++) {
                if ( index[j] - index[0] == len - 1) {
                    is_last_I[j] = 0;
                } else {
                    is_last_I[j] = 
                        (len - 1 - (index[j] - index[0])).inversed();
                }
                is_last_R[j] = 1 - 
                    (len - 1 - (index[j] - index[0])) 
                    * is_last_I[j];
                // std::cout << j << " " << this->index[j] << " "
                //     << this->is_last_R[j] - (1 - this->is_last_I[j] * (len - (this->index[j] - this->index[0] + 1))) << " "
                //     << this->is_last_R[j] << " "
                //     << this->is_last_I[j] << " "
                //     << len - (this->index[j] - this->index[0] + 1) << std::endl;
            }
        }

        void allocate_witness(std::size_t &column_index, std::size_t &row_index){
            header.allocate_witness(column_index, row_index);
            allocate(first_element_image, column_index++, row_index);
            allocate(first_element_flag, column_index++, row_index);

            for (std::size_t k = 0; k < data.size(); k++) {
                allocate(data[k], column_index++, row_index);
                allocate(rlc[k], column_index++, row_index);
                allocate(is_last[k], column_index++, row_index);
                allocate(index[k], column_index++, row_index);
                allocate(is_last_I[k], column_index++, row_index);
                allocate(is_last_R[k], column_index++, row_index);
            }
        }

        void rlp_lookup_constraints() {
            header.rlp_lookup_constraints(first_element_image, data[0], first_element_flag);
        }

        TYPE get_total_length_constraint() {
                return header.get_total_length_constraint();
        }

        void main_constraints(TYPE previous_rlc, TYPE initial_index, TYPE not_padding) {
            if (node_type == inner_node_type::array) {
            // constrain(not_padding * (header.len_low + header.len_high * 0x100 - (key.get_total_length_constraint() + value.get_total_length_constraint())));
            } else {
                
                header.main_constraints(previous_rlc, initial_index, not_padding);

                TYPE first_data_index = initial_index + header.get_prefix_length();
                constrain(index[0] - first_data_index);
                constrain(rlc[0] - (header.prefix_rlc[2] * 53 + data[0]));

                // comp.constrain(this->data[0] * this->is_last[0]);
                for (size_t i = 1; i < data.size(); i++) {
                    constrain((1 - is_last[i]) * is_last[i]);
                    constrain((1 - is_last[i]) * is_last[i-1]);
                    
                    constrain(not_padding * (is_last_R[i] - (1 - 
                        is_last_I[i] * (header.len - (index[i] - index[0] + 1)))));
                    constrain((header.len - (index[i] - index[0] + 1)) * is_last_R[i]);
                    constrain(is_last[i] - is_last_R[i] - is_last[i-1]);
                    constrain(index[i] * is_last[i-1]);
                    constrain((index[i] - index[i-1] - 1) * (1 - is_last[i-1]));
                    constrain(data[i] * is_last[i-1]);
                    constrain(rlc[i] - (is_last[i-1] * rlc[i-1] + (1 - is_last[i-1]) * (rlc[i-1] * 53 + data[i])));
                }
            }
        }

        private:
        void _initialize_header() {
            header.initialize();
        }
        void _initialize_body() {
            if (node_type == inner_node_type::array) {
                for (auto &i : inners) {
                    i.initialize();
                }
            } else {
                for (size_t j = 0; j < data.size(); j++) {
                    data[j] = 0;
                    index[j] = 0;
                    is_last[j] = 1;
                }
            }
        }
        void _set_data(std::vector<zkevm_word_type> _raw) {
            raw = _raw;
            if (node_type != inner_node_type::array) {
                // if (this->type == inner_node_type::key) {
                //     BOOST_ASSERT_MSG(this->raw.size() <= 33, "key length exceeds!");
                // } else if (this->type == inner_node_type::nonce) {
                //     // TODO placeholder for now
                //     BOOST_ASSERT_MSG(this->raw.size() <= 110, "key length exceeds!");
                // }                    
                for (size_t j = 0; j < raw.size(); j++) {
                    // if (d[j] <= 0x0F)
                    //     std::cout <<"0" << std::hex << d[j] << std::dec;
                    // else
                    //     std::cout << std::hex << d[j] << std::dec;
                    data[j] = raw[j];
                    is_last[j] = 0;
                }
                if (raw.size() > 0) {
                    is_last[raw.size() - 1] = 1;
                }
                if (raw.size() == 1 && raw[0] < 128) {
                    first_element_flag = 1;
                    first_element_image = raw[0];
                }
                else {
                    first_element_flag = 0;
                    first_element_image = 0;
                }
            } else {
                std::cout << "element type not supported yet!\n";
            }
        }

    };
    
    
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

        static zkevm_word_type calculate_keccak(std::vector<std::uint8_t> hash_input, std::size_t total_length) {
            std::vector<uint8_t> buffer(hash_input.begin(), hash_input.begin() + total_length);
            zkevm_word_type hash = nil::blueprint::zkevm_keccak_hash(buffer);
            return hash;
        }

        mpt_type trie_type;
        node_header<FieldType, stage> header;

        node_inner<FieldType, stage> key;
        node_inner<FieldType, stage> value;

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

        // static context_type& get_context(context_type &context_object, std::size_t start) {
        //     std::vector<std::size_t> leaf_area;
        //     for( std::size_t i = 0; i < 2000; i++){
        //         leaf_area.push_back(i);
        //     }
        //     context_type n = context_object.subcontext( leaf_area, start+1, 1);
        //     return *n;
        // }

        // void set_challenge(TYPE _rlc_challenge) {
        //     rlc_challenge = _rlc_challenge;
        //     header.set_challenge(rlc_challenge);
        //     key.set_challenge(rlc_challenge);
        //     value.set_challenge(rlc_challenge);
        // }

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
            header.rlp_lookup_constraints(0, 0, 0);
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
