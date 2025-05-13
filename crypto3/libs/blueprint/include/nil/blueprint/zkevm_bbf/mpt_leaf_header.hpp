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
            prefix_exists[0] = 1;
            prefix_exists[1] = 0;
            prefix_exists[2] = 0;
            prefix_1_flag = 1;
            prefix_1_image = 0;
            len = 0;
            len_image = 0;
            prefix[0] = 0xC0;
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
            if (raw_data_length == 0) {
                len_is_zero = 1;
            } else {
                len_is_zero = 0;
                len_I = len.inversed();
            }

            if (raw_data_length == 1) {
                len_is_one = 1;
            } else {
                len_is_one = 0;
                len_minus_one_I = (len - 1).inversed();
            }
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
            std::cout << "\tdata\tindex\n";
            std::cout << "\t" << std::hex << prefix[0] << std::dec << "\t"
                    << std::hex << prefix_index[0] << std::dec << std::endl;
            std::cout << "\t" << std::hex << prefix[1] << std::dec << "\t"
                    << std::hex << prefix_index[1] << std::dec << std::endl;
            std::cout << "\t" << std::hex << prefix[2] << std::dec << "\t"
                    << std::hex << prefix_index[2] << std::dec << std::endl;
            
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

        virtual ~node_header(){}
    
        // virtual void set_metadata(std::vector<std::uint8_t> &hash_input, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
        //     throw "Method not implemented! 1";
        // }

        // virtual void set_metadata(std::vector<std::uint8_t> &hash_input, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator, zkevm_word_type first_element) {
        //     throw "Method not implemented! 2";
        // }

        // virtual void rlp_lookup_constraints(TYPE first_element_image, TYPE first_element, TYPE first_element_flag) {
        //     throw "Method not implemented! 3";
        // }

        // virtual void rlp_lookup_constraints() {
        //     throw "Method not implemented! 4";
        // }

        // virtual std::size_t get_total_length() {
        //     throw "Method not implemented! 5";
        // }

        // virtual std::size_t get_total_length(zkevm_word_type first_element) {
        //     throw "Method not implemented! 6";
        // }
    
    protected:
        void _set_metadata(std::vector<std::uint8_t> &hash_input, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator, uint8_t const1, uint8_t const2) {            
            BOOST_ASSERT_MSG(raw_data_length <= 65535, "data length more than 65535 bytes!");

            if (raw_data_length < 56) {
                prefix[0] = const1 + raw_data_length;
                prefix[1] = 0;
                prefix[2] = 0;
                prefix_exists[0] = 1;
                prefix_exists[1] = 0;
                prefix_exists[2] = 0;
                prefix_1_flag = 1;
                hash_input[rlp_encoding_index] = const1 + raw_data_length;
            } else {
                std::size_t len_len=0;
                std::size_t tmp = raw_data_length;

                prefix_exists[0] = 1;
                prefix_exists[1] = 1;
                while (tmp > 0) {
                    len_len += 1;
                    tmp >>= 8;
                }
                prefix[0] = const2 + len_len;
                hash_input[rlp_encoding_index] = const2 + len_len;
                if (len_len == 1) {
                    prefix[1] = raw_data_length;
                    prefix[2] = 0;
                    prefix_exists[2] = 0;
                    prefix_1_flag = 1;
                    hash_input[rlp_encoding_index + 1] = raw_data_length;
                } else {
                    prefix[1] = raw_data_length >> 8;
                    prefix[2] = raw_data_length & 0xFF;
                    prefix_exists[2] = 1;
                    prefix_1_flag = 0;
                    hash_input[rlp_encoding_index + 1] = raw_data_length >> 8;
                    hash_input[rlp_encoding_index + 2] = raw_data_length & 0xFF;
                }
            }
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
            
            if (prefix_1_flag == 1) {
                len_image = raw_data_length;
                prefix_1_image = prefix[1];
            } else {
                len_image = 0;
                prefix_1_image = 0;
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

        std::size_t _get_total_length() {
            if (raw_data_length <= 55) {
                return raw_data_length + 1;
            } else {
                std::size_t len_len=0;
                std::size_t tmp = raw_data_length;
                while (tmp > 0) {
                    len_len += 1;
                    tmp >>= 8;
                }
                return len_len + raw_data_length + 1;
            }
        }
    };

 


    template<typename FieldType, GenerationStage stage>
    class node_header_array: public node_header<FieldType, stage> {
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
        using node_header = node_header<FieldType, stage>;

 
        node_header_array(
            context_type &context_object,
            // mpt_type _trie_t,
            TYPE _rlc_challenge
        ): node_header(context_object, inner_node_type::array, _rlc_challenge) {
        }
        
        void set_metadata(std::vector<std::uint8_t> &hash_input, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) { 
            BOOST_ASSERT_MSG(this->raw_data_length <= 65535, "data length more than 65535 bytes!");
            std::uint8_t const1, const2;
            const1 = 0xC0;
            const2 = 0xF7;
            this->_set_metadata(hash_input, rlp_encoding_index, rlc_accumulator, const1, const2);
        }

        std::size_t get_total_length() {
            return this->_get_total_length();
        }

        void rlp_lookup_constraints() {
            this->_rlp_lookup_constraints(0, 0, 0);
        }

        virtual ~node_header_array(){}

    };

 

    template<typename FieldType, GenerationStage stage>
    class node_header_string: public node_header<FieldType, stage> {
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
        using node_header = node_header<FieldType, stage>;

 
        node_header_string(
            context_type &context_object,
            // mpt_type _trie_t,
            inner_node_type _node_t,
            TYPE _rlc_challenge
        ): node_header(context_object, _node_t, _rlc_challenge) {
        }
        

        void set_metadata(std::vector<std::uint8_t> &hash_input, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator, zkevm_word_type first_element) {
            BOOST_ASSERT_MSG(this->raw_data_length <= 65535, "data length more than 65535 bytes!");

            if (this->raw_data_length == 1 && first_element <= 0x7F) {
                // string encoding with single bytes and value less than 128
                this->prefix[0] = 0;
                this->prefix[1] = 0;
                this->prefix[2] = 0;

                this->prefix_rlc[0] = this->rlc_challenge;
                this->prefix_rlc[1] = this->rlc_challenge;
                this->prefix_rlc[2] = this->rlc_challenge;

                this->prefix_exists[0] = 0;
                this->prefix_exists[1] = 0;
                this->prefix_exists[2] = 0;
                this->prefix_1_flag = 1;
                this->prefix_1_image = this->prefix[1];

                this->prefix_index[0] = 0;
                this->prefix_index[1] = 0;
                this->prefix_index[2] = 0;
                this->len_image = this->raw_data_length;
            } else {
                std::uint8_t const1, const2;
                const1 = 0x80;
                const2 = 0xB7;
                this->_set_metadata(hash_input, rlp_encoding_index, rlc_accumulator, const1, const2);
            }
        }

        std::size_t get_total_length(zkevm_word_type first_element) {
            if (this->raw_data_length == 1 && first_element <= 0x7F)
                return 1;
            else 
                return this->_get_total_length();
        }
    
        void rlp_lookup_constraints(TYPE first_element_image, TYPE first_element, TYPE first_element_flag) {
            constrain(first_element_flag * (first_element - first_element_image));
            this->_rlp_lookup_constraints(first_element_image, first_element, first_element_flag);
        }

        virtual ~node_header_string(){}


    };
}  // namespace nil::blueprint::bbf
