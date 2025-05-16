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

namespace nil::blueprint::bbf {

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

    template<typename T>
    class rlp_parser {};
    
    template<typename T>
    class rlp_encoder: rlp_parser<T> {
        public:
        virtual void encode_data(std::size_t raw_data_length, std::size_t &rlp_encoding_index, T &rlc_accumulator, bool initialize_rlc=false) {
            throw "Method not implemented!";
        }
        virtual void encode_data(std::vector<zkevm_word_type> &raw, std::size_t &rlp_encoding_index, T &rlc_accumulator, bool initialize_rlc=false) {
            throw "Method not implemented!";
        }
    };
    
    template<typename T>
    class rlp_decoder: rlp_parser<T> {
        public:
        virtual void peek_and_decode_data(std::vector<zkevm_word_type> &raw, std::size_t &rlp_encoding_index, T &rlc_accumulator) {
            throw "Method not implemented!";
        }
    };



    std::size_t get_rlp_size(std::vector<zkevm_word_type> raw) {
        std::size_t data_len = raw.size();
        if (data_len == 0)
            return 1;
        if (data_len == 1 && raw[0] < 128)
            return 1;
        if (data_len < 56)
            return data_len + 1;
        else {
            std::size_t len_len = 0;
            while (data_len > 0)
            {
                len_len ++;
                data_len >>=8;
            }
            return raw.size() + len_len + 1;
        }
    }


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
        using typename generic_component<FieldType, stage>::table_params;
        using typename generic_component<FieldType, stage>::TYPE;
        // mpt_type trie_type;
        inner_node_type node_type;
        std::array<TYPE, 3> prefix;
        std::array<TYPE, 3> prefix_rlc;
        std::array<TYPE, 3> prefix_exists;
        
        TYPE prefix_1_flag;
        TYPE prefix_1_image;
        std::array<TYPE, 3> prefix_index;
        TYPE len;
        TYPE len_image;
        TYPE len_is_zero;
        TYPE len_I;
        TYPE len_is_one;
        TYPE len_minus_one_I;
        TYPE rlc_challenge;

        std::uint8_t rlp_constant;
        
        node_header(
            context_type &context_object,
            // mpt_type _trie_t,
            inner_node_type _node_t,
            TYPE _rlc_challenge,
            std::uint8_t _rlp_constant
        ): generic_component<FieldType, stage>(context_object, false),
        node_type(_node_t),
        rlp_constant(_rlp_constant),
        ct(context_object) {
            rlc_challenge = _rlc_challenge;
        }
        // void set_challenge(TYPE &_rlc_challenge) {
        //     rlc_challenge = _rlc_challenge;
        // }

        void initialize() {
            prefix_exists[0] = 1;
            prefix_exists[1] = 0;
            prefix_exists[2] = 0;
            prefix_1_flag = 1;
            prefix_1_image = 0;
            len = 0;
            len_image = 0;
            prefix[0] = rlp_constant;
        }

        void main_constraints(TYPE previous_rlc, TYPE initial_index, TYPE not_padding) {
            constrain(prefix[0] * (1 - prefix_exists[0]));
            constrain(prefix[1] * (1 - prefix_exists[1]));
            constrain(prefix[2] * (1 - prefix_exists[2]));

            constrain(prefix_index[0] - prefix_exists[0] * initial_index);
            constrain(prefix_index[1] - prefix_exists[1] * (prefix_index[0] + 1));
            constrain(prefix_index[2] - prefix_exists[2] * (prefix_index[1] + 1));
            
            constrain(prefix_rlc[0] - (prefix_exists[0] * (previous_rlc * 53 + prefix[0]) + (1 - prefix_exists[0]) * previous_rlc));
            constrain(prefix_rlc[1] - (prefix_exists[1] * (prefix_rlc[0] * 53 + prefix[1]) + (1 - prefix_exists[1]) * prefix_rlc[0]));
            constrain(prefix_rlc[2] - (prefix_exists[2] *  (prefix_rlc[1] * 53 + prefix[2]) + (1 - prefix_exists[2]) * prefix_rlc[1]));
        }

        TYPE get_prefix_length() {
            return prefix_exists[0] + prefix_exists[1] + prefix_exists[2];
        }
    
        TYPE get_total_length_constraint() {
            return len + get_prefix_length();
        }

        void allocate_witness(std::size_t &column_index, std::size_t &row_index) {
            // rlp len
            allocate(len, column_index ++, row_index);
            allocate(len_image, column_index ++, row_index);
            allocate(len_is_zero, column_index ++, row_index);
            allocate(len_I, column_index ++, row_index);
            allocate(len_is_one, column_index ++, row_index);
            allocate(len_minus_one_I, column_index ++, row_index);
            allocate(prefix_1_flag, column_index ++, row_index);
            allocate(prefix_1_image, column_index ++, row_index);
            // pefix
            for (size_t i = 0; i < 3; i++) {
                allocate(prefix[i], column_index ++, row_index);
                allocate(prefix_rlc[i], column_index ++, row_index);
                allocate(prefix_index[i], column_index ++, row_index);
                allocate(prefix_exists[i], column_index ++, row_index);
            }
        }
    
        void print() {
            std::cout << "\tdata\tindex\trlc\n";
            std::cout << "\t" << std::hex << prefix[0] << std::dec << "\t"
                      << std::hex << prefix_index[0] << std::dec << "\t"
                      << std::hex << prefix_rlc[0] << std::dec << std::endl;
            std::cout << "\t" << std::hex << prefix[1] << std::dec << "\t"
                      << std::hex << prefix_index[1] << std::dec << "\t"
                      << std::hex << prefix_rlc[1] << std::dec << std::endl;
            std::cout << "\t" << std::hex << prefix[2] << std::dec << "\t"
                      << std::hex << prefix_index[2] << std::dec << "\t"
                      << std::hex << prefix_rlc[2] << std::dec << std::endl;
            
            std::cout << "prefix exists: " << 
                    std::hex << prefix_exists[0] << std::dec << " " <<
                    std::hex << prefix_exists[1] << std::dec << " " <<
                    std::hex << prefix_exists[2] << std::dec << std::endl;
            std::cout << "second prefix flag:\t second prefix image\n"
                       << std::hex << prefix_1_flag << std::dec << "\t"
                       << std::hex << prefix_1_image << std::dec << std::endl;
            std::cout << "len\tlen_I\tlen_is_one\tlen_is_zero\tlen_image: \n"
                    << std::hex << len << std::dec << "\t"
                    << std::hex << len_I<< std::dec <<  "\t"
                    << std::hex << len_is_one<< std::dec << "\t\t"
                    << std::hex << len_is_zero << std::dec << "\t\t\t"
                    << std::hex << len_image<< std::dec <<std::dec <<std::endl;
        }

        std::size_t get_total_length() {
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                TYPE total_len = len + get_prefix_length();
                return static_cast<std::size_t>(total_len.data.base());
            } else {
                return 0;
            }
        }

        virtual ~node_header(){}

    protected:

        context_type &ct; // :(

        void _set_length_info() {
            // if (node_type == inner_node_type::storage_value)
            //     BOOST_ASSERT_MSG(raw_data_length <= 32, "Data size exceeded 32 bytes for storage values!");
            // else if (node_type == inner_node_type::array)
            //     BOOST_ASSERT_MSG(raw_data_length <= 110, "We only support array of up to 110 bytes!");
            // else if (node_type == inner_node_type::nonce)
            //     BOOST_ASSERT_MSG(raw_data_length <= 8, "Data size exceeded 8 bytes for nonce!");
            // else if (node_type == inner_node_type::balance)
            //     BOOST_ASSERT_MSG(raw_data_length <= 32, "Data size exceeded 32 bytes for balance!");
            // else if (node_type == inner_node_type::storage_root)
            //     BOOST_ASSERT_MSG(raw_data_length <= 32, "Data size exceeded 32 bytes for storage hash!");
            // else if (node_type == inner_node_type::code_hash)
            //     BOOST_ASSERT_MSG(raw_data_length <= 32, "Data size exceeded 32 bytes for code hash!");
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                if (prefix_exists[2] == 0) {
                    prefix_1_flag = 1;
                    len_image = len;
                    prefix_1_image = prefix[1];
                } else {
                    prefix_1_flag = 0;
                    len_image = 0;
                    prefix_1_image = 0;
                }

                if (len == 0) {
                    len_is_zero = 1;
                } else {
                    len_is_zero = 0;
                    len_I = len.inversed();
                }

                if (len == 1) {
                    len_is_one = 1;
                } else {
                    len_is_one = 0;
                    len_minus_one_I = (len - 1).inversed();
                }
            }
        }

        void _set_prefix_rlc_and_index(std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            for (size_t i = 0; i < 3; i++) {
                if (prefix_exists[i] == 1) {
                    prefix_rlc[i] = rlc_challenge * rlc_accumulator + prefix[i];
                    rlc_accumulator = prefix_rlc[i];
                    prefix_index[i] = rlp_encoding_index++;
                } else {
                    prefix_rlc[i] = rlc_accumulator;
                    prefix_index[i] = 0;
                }
            }
            rlc_accumulator = prefix_rlc[2];
        }

        void _rlp_lookup_constraints(TYPE first_element_image, TYPE first_element, TYPE first_element_flag) {
            std::vector<TYPE> node_rlp_lookup = {
                prefix[0],
                prefix_1_image,
                prefix[2],
                prefix_1_flag,
                first_element_flag,
                first_element_image,
                node_type != inner_node_type::array,
                len_image
            };
            lookup(node_rlp_lookup, "rlp_table");
            constrain(prefix_1_flag * (prefix_1_image - prefix[1]));
            constrain((1 - prefix_exists[2]) * (len - len_image));
        }
    };

    template<typename FieldType, GenerationStage stage>
    class node_header_decoder: public node_header<FieldType, stage>, rlp_decoder<typename generic_component<FieldType, stage>::TYPE> {
        using typename generic_component<FieldType, stage>::context_type;
        public:
        using typename generic_component<FieldType, stage>::TYPE;
        using node_header = node_header<FieldType, stage>;
        

        node_header_decoder(
            context_type &context_object,
            // mpt_type _trie_t,
            inner_node_type _node_t,
            TYPE _rlc_challenge,
            std::uint8_t _rlp_constant
        ): node_header(context_object, _node_t, _rlc_challenge, _rlp_constant) {}

        void peek_and_decode_data(std::vector<zkevm_word_type> &_raw, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {            
            this->_peek_and_decode_data(_raw, rlp_encoding_index, rlc_accumulator);
            this->_set_prefix_rlc_and_index(rlp_encoding_index, rlc_accumulator);
            this->_set_length_info();
            // return std::vector<std::uint8_t>(_raw.begin() + prefix_len, _raw.end());
        }

        protected:
        virtual void _peek_and_decode_data(std::vector<zkevm_word_type> &_raw, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {            
            throw "Method not implemented!";
        }

        void _peek_and_decode_data_non_single(std::vector<zkevm_word_type> &_raw, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {            
            BOOST_ASSERT_MSG(_raw.size() <= 65535, "data length more than 65535 bytes!");
            BOOST_ASSERT_MSG(_raw.size() >= 1, "data length zero!");
            
            if (_raw[0] >= this->rlp_constant && _raw[0] <= this->rlp_constant + 55) {
                // BOOST_ASSERT_MSG(_raw.size() >= _raw[0] - rlp_constant + 1, "Error in RLP decoding!");
                this->prefix[0] = _raw[0];
                this->prefix[1] = 0;
                this->prefix[2] = 0;
                this->prefix_exists[0] = 1;
                this->prefix_exists[1] = 0;
                this->prefix_exists[2] = 0;
                this->len = this->prefix[0] - this->rlp_constant;
                _raw.erase(_raw.begin());
            } else if (_raw[0] >= this->rlp_constant + 56 && _raw[0] <= this->rlp_constant + 56 + 7) {
                zkevm_word_type len_len = _raw[0] - this->rlp_constant - 55;
                this->prefix[0] = _raw[0];
                this->prefix_exists[0] = 1;
                _raw.erase(_raw.begin());
                if (len_len == 1) {
                    this->prefix[1] = _raw[1];
                    this->prefix[2] = 0;
                    this->prefix_exists[1] = 1;
                    this->prefix_exists[2] = 0;
                    this->len = _raw[1];
                    _raw.erase(_raw.begin());
                } else if (len_len == 2) {
                    this->prefix[1] = _raw[1];
                    this->prefix[2] = _raw[2];
                    this->prefix_exists[1] = 1;
                    this->prefix_exists[2] = 1;
                    this->len = (_raw[1] << 8) + _raw[2];
                    _raw.erase(_raw.begin());
                } else {
                    throw "Error in RLP decoding4!";
                }
            } else {
                throw "Error in RLP decoding5!";
            }
        }

        void _set_prefix_rlc_and_index(std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            for (size_t i = 0; i < 3; i++) {
                if (this->prefix_exists[i] == 1) {
                    this->prefix_rlc[i] = this->rlc_challenge * rlc_accumulator + this->prefix[i];
                    rlc_accumulator = this->prefix_rlc[i];
                    this->prefix_index[i] = rlp_encoding_index++;
                } else {
                    this->prefix_rlc[i] = rlc_accumulator;
                    this->prefix_index[i] = 0;
                }
            }
            rlc_accumulator = this->prefix_rlc[2];
        }
    };

    template<typename FieldType, GenerationStage stage>
    class node_header_encoder: public node_header<FieldType, stage>, rlp_encoder<typename generic_component<FieldType, stage>::TYPE> {
        using typename generic_component<FieldType, stage>::context_type;

        public:
        using typename generic_component<FieldType, stage>::TYPE;
        using node_header = node_header<FieldType, stage>;
        

        node_header_encoder(
            context_type &context_object,
            // mpt_type _trie_t,
            inner_node_type _node_t,
            TYPE _rlc_challenge,
            std::uint8_t _rlp_constant
        ): node_header(context_object, _node_t, _rlc_challenge, _rlp_constant) {}

        void encode_data(std::size_t raw_data_length, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator, bool initialize_rlc=false) { 
            BOOST_ASSERT_MSG(raw_data_length <= 65535, "data length more than 65535 bytes!");
            this->_encode_data(raw_data_length);
            if (initialize_rlc)
                rlc_accumulator = this->get_total_length();
            this->_set_prefix_rlc_and_index(rlp_encoding_index, rlc_accumulator);
            this->_set_length_info();
        }
      
        void encode_data(std::vector<zkevm_word_type> &raw, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator, bool initialize_rlc=false) { 
            BOOST_ASSERT_MSG(raw.size() <= 65535, "data length more than 65535 bytes!");
            this->_encode_data(raw);
            if (initialize_rlc)
                rlc_accumulator = this->get_total_length();
            this->_set_prefix_rlc_and_index(rlp_encoding_index, rlc_accumulator);
            this->_set_length_info();
        }  
        protected:

        void _encode_non_single(std::size_t raw_data_length) {
            if (raw_data_length < 56) {
                this->prefix[0] = this->rlp_constant + raw_data_length;
                this->prefix[1] = 0;
                this->prefix[2] = 0;
                this->prefix_exists[0] = 1;
                this->prefix_exists[1] = 0;
                this->prefix_exists[2] = 0;
            } else {
                std::size_t len_len=0;
                std::size_t tmp = raw_data_length;
                this->prefix_exists[0] = 1;
                this->prefix_exists[1] = 1;
                while (tmp > 0) {
                    len_len += 1;
                    tmp >>= 8;
                }
                this->prefix[0] = this->rlp_constant + 55 + len_len;
                if (len_len == 1) {
                    this->prefix[1] = raw_data_length;
                    this->prefix[2] = 0;
                    this->prefix_exists[2] = 0;

                } else if (len_len == 2) {
                    this->prefix[1] = raw_data_length >> 8;
                    this->prefix[2] = raw_data_length & 0xFF;
                    this->prefix_exists[2] = 1;
                } else {
                    throw "Error in RLP decoding6!";
                }
            }
            this->len = raw_data_length;
        }

        void virtual _encode_data(std::size_t raw_data_length) {
            throw "Method not implemented!";
        }

        void virtual _encode_data(std::vector<zkevm_word_type> &_raw) {
            throw "Method not implemented!";
        }
    };

    template<typename FieldType, GenerationStage stage>
    class node_header_array_decoder: public node_header_decoder<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;

      public:
        using typename generic_component<FieldType, stage>::TYPE;
        using node_header = node_header<FieldType, stage>;
 
        node_header_array_decoder(
            context_type &context_object,
            // mpt_type _trie_t,
            TYPE _rlc_challenge
        ): node_header(context_object, inner_node_type::array, _rlc_challenge, 0xC0) {
        }

        void rlp_lookup_constraints() {
            this->_rlp_lookup_constraints(0, 0, 0);
        }

        void _peek_and_decode_data(std::vector<zkevm_word_type> &_raw, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {            
            this->_peek_and_decode_data_non_single(_raw, rlp_encoding_index, rlc_accumulator);
        }

        ~node_header_array_decoder(){}
    };

    template<typename FieldType, GenerationStage stage>
    class node_header_array_encoder: public node_header_encoder<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
      public:
        using typename generic_component<FieldType, stage>::TYPE;
        using node_header_encoder = node_header_encoder<FieldType, stage>;

        node_header_array_encoder(
            context_type &context_object,
            // mpt_type _trie_t,
            TYPE _rlc_challenge
        ): node_header_encoder(context_object, inner_node_type::array, _rlc_challenge, 0xC0) {
        }
        
        void _encode_data(std::size_t raw_data_length) { 
            BOOST_ASSERT_MSG(raw_data_length <= 65535, "data length more than 65535 bytes!");
            this->_encode_non_single(raw_data_length);
        }

        void rlp_lookup_constraints() {
            this->_rlp_lookup_constraints(0, 0, 0);
        }

        ~node_header_array_encoder(){}
    };

    template<typename FieldType, GenerationStage stage>
    class node_header_string_decoder: public node_header_decoder<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;

        public:

        using typename generic_component<FieldType, stage>::table_params;
        using typename generic_component<FieldType, stage>::TYPE;
        using node_header = node_header<FieldType, stage>;
        using node_header_decoder =node_header_decoder<FieldType, stage>;


        node_header_string_decoder(
            context_type &context_object,
            // mpt_type _trie_t,
            inner_node_type _node_t,
            TYPE _rlc_challenge
        ): node_header_decoder(context_object, _node_t, _rlc_challenge, 0x80) {}

        void _peek_and_decode_data(std::vector<zkevm_word_type> &_raw, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            BOOST_ASSERT_MSG(_raw.size() <= 65535, "data length more than 65535 bytes!");
            if ( _raw.size() == 1 && _raw[0] <= 0x7F) {
                // string encoding with single bytes and value less than 128
                this->prefix[0] = 0;
                this->prefix[1] = 0;
                this->prefix[2] = 0;

                this->prefix_exists[0] = 0;
                this->prefix_exists[1] = 0;
                this->prefix_exists[2] = 0;
                this->len = 1;
                this->_set_prefix_rlc_and_index(rlp_encoding_index, rlc_accumulator);
                this->_set_length_info();
            }  else {
                this->_peek_and_decode_data_non_single(_raw, rlp_encoding_index, rlc_accumulator);
            }
        }
    
        void rlp_lookup_constraints(TYPE first_element_image, TYPE first_element, TYPE first_element_flag) {
            this->ct.constrain(first_element_flag * (first_element - first_element_image), "");
            this->_rlp_lookup_constraints(first_element_image, first_element, first_element_flag);
        }

        ~node_header_string_decoder(){}

    };

    template<typename FieldType, GenerationStage stage>
    class node_header_string_encoder: public node_header_encoder<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;

        public:

        using typename generic_component<FieldType, stage>::table_params;
        using typename generic_component<FieldType, stage>::TYPE;

        using node_header_encoder = node_header_encoder<FieldType, stage>;


        node_header_string_encoder(
            context_type &context_object,
            // mpt_type _trie_t,
            inner_node_type _node_t,
            TYPE _rlc_challenge
        ): node_header_encoder(context_object, _node_t, _rlc_challenge, 0x80) {}

        void _encode_data(std::vector<zkevm_word_type> &_raw) { 
            std::size_t raw_data_length = _raw.size();
            BOOST_ASSERT_MSG(raw_data_length <= 65535, "data length more than 65535 bytes!");
            if ( raw_data_length == 1 && _raw[0] <= 0x7F) {
                // string encoding with single bytes and value less than 128
                this->prefix[0] = 0;
                this->prefix[1] = 0;
                this->prefix[2] = 0;

                this->prefix_exists[0] = 0;
                this->prefix_exists[1] = 0;
                this->prefix_exists[2] = 0;
                this->len = 1;
            } else {
                this->_encode_non_single(_raw.size());
            }
        }
    
        void rlp_lookup_constraints(TYPE first_element_image, TYPE first_element, TYPE first_element_flag) {
            this->ct.constrain(first_element_flag * (first_element - first_element_image), "");
            this->_rlp_lookup_constraints(first_element_image, first_element, first_element_flag);
        }

        ~node_header_string_encoder(){}
    };
}  // namespace nil::blueprint::bbf
