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
#include <nil/blueprint/zkevm_bbf/big_field/subcomponents/keccak_table.hpp>
#include <nil/blueprint/zkevm_bbf/mpt_leaf.hpp>

namespace nil::blueprint::bbf {

    enum class mpt_type { account_trie, storage_trie };

    // interface classes for RLP:
    template<typename T>
    class string_rlp_encoder{
        public:
        virtual void peek_and_encode_data(std::vector<zkevm_word_type> &raw, std::size_t &rlp_encoding_index, T &rlc_accumulator, bool initialize_rlc=false) {
            throw "Method not implemented!";
        }
    };

    template<typename T>
    class array_rlp_encoder{
        public:
        virtual void peek_and_encode_data(std::size_t raw_data_length, std::size_t &rlp_encoding_index, T &rlc_accumulator, bool initialize_rlc=false) {
            throw "Method not implemented!";
        }
    };

    template<typename T>
    class rlp_decoder {
        public:
        virtual void peek_and_decode_data(std::vector<zkevm_word_type> &raw, std::size_t &rlp_encoding_index, T &rlc_accumulator) {
            throw "Method not implemented!";
        }
    };

// ----------------------------------------------------------------------------

    std::size_t get_rlp_length(std::vector<zkevm_word_type> raw) {
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

    std::size_t get_max_rlp_length(std::size_t data_len) {
        std::vector<zkevm_word_type> raw;
        for (size_t i = 0; i < data_len; i++) raw.push_back(0xFF);
        return get_rlp_length(raw);
    }

    template<typename FieldType, GenerationStage stage>
    class node_header: public generic_component<FieldType, stage>, rlp_decoder<typename generic_component<FieldType, stage>::TYPE> {
      public:
        using typename generic_component<FieldType, stage>::context_type;
        using RLPTable = typename bbf::rlp_table<FieldType, stage>;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;

        using typename generic_component<FieldType, stage>::TYPE;
        std::array<TYPE, 3> prefix;
        std::array<TYPE, 3> prefix_rlc;
        std::array<TYPE, 3> prefix_exists;

        TYPE prefix_1_flag;
        TYPE prefix_1_image;
        std::array<TYPE, 3> prefix_index;
        TYPE len;
        TYPE len_image;
        TYPE rlc_challenge;

        std::uint8_t rlp_constant;

        node_header(
            context_type &context_object,
            std::uint8_t _rlp_constant
        ): generic_component<FieldType, stage>(context_object, false),
        rlp_constant(_rlp_constant),
        ct(context_object) {}

        void set_rlc_challenge(TYPE _rlc_challenge) {
            rlc_challenge = _rlc_challenge;
        }

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

        void main_constraints(TYPE previous_rlc, TYPE initial_index, TYPE rlc_challenge) {
            constrain(prefix[0] * (1 - prefix_exists[0]));
            constrain(prefix[1] * (1 - prefix_exists[1]));
            constrain(prefix[2] * (1 - prefix_exists[2]));

            constrain(prefix_index[0] - prefix_exists[0] * initial_index);
            constrain(prefix_index[1] - prefix_exists[1] * (prefix_index[0] + 1));
            constrain(prefix_index[2] - prefix_exists[2] * (prefix_index[1] + 1));

            constrain(prefix_rlc[0] - (prefix_exists[0] * (previous_rlc * rlc_challenge + prefix[0]) + (1 - prefix_exists[0]) * previous_rlc), "fdsjfdsjf");
            constrain(prefix_rlc[1] - (prefix_exists[1] * (prefix_rlc[0] * rlc_challenge + prefix[1]) + (1 - prefix_exists[1]) * prefix_rlc[0]));
            constrain(prefix_rlc[2] - (prefix_exists[2] *  (prefix_rlc[1] * rlc_challenge + prefix[2]) + (1 - prefix_exists[2]) * prefix_rlc[1]));
        }

        TYPE get_prefix_length() {
            return prefix_exists[0] + prefix_exists[1] + prefix_exists[2];
        }

        TYPE get_total_length_constraint() {
            return len + get_prefix_length();
        }

        void allocate_witness(std::size_t &column_index, std::size_t &row_index) {
            allocate(len, column_index ++, row_index);
            allocate(len_image, column_index ++, row_index);
            allocate(prefix_1_flag, column_index ++, row_index);
            allocate(prefix_1_image, column_index ++, row_index);
            for (size_t i = 0; i < 3; i++) {
                allocate(prefix[i], column_index ++, row_index);
                allocate(prefix_rlc[i], column_index ++, row_index);
                allocate(prefix_index[i], column_index ++, row_index);
                allocate(prefix_exists[i], column_index ++, row_index);
            }
        }

        std::string print() {
            std::stringstream ss;

            ss << "\tdata\tindex\trlc\n";
            ss << "\t" << std::hex << prefix[0] << std::dec << "\t"
                      << std::hex << prefix_index[0] << std::dec << "\t"
                      << std::hex << prefix_rlc[0] << std::dec << std::endl;
            ss << "\t" << std::hex << prefix[1] << std::dec << "\t"
                      << std::hex << prefix_index[1] << std::dec << "\t"
                      << std::hex << prefix_rlc[1] << std::dec << std::endl;
            ss << "\t" << std::hex << prefix[2] << std::dec << "\t"
                      << std::hex << prefix_index[2] << std::dec << "\t"
                      << std::hex << prefix_rlc[2] << std::dec << std::endl;

            ss << "\tprefix exists: " <<
                    std::hex << prefix_exists[0] << std::dec << " " <<
                    std::hex << prefix_exists[1] << std::dec << " " <<
                    std::hex << prefix_exists[2] << std::dec << std::endl;
            ss << "\tsecond prefix flag:\tsecond prefix image\n\t"
                       << std::hex << prefix_1_flag << std::dec << "\t\t\t"
                       << std::hex << prefix_1_image << std::dec << std::endl;
            ss << "\tlen\tlen_image:\n\t"
                    << std::hex << len << std::dec << "\t"
                    // << std::hex << len_is_one<< std::dec << "\t\t"
                    // << std::hex << len_is_zero << std::dec << "\t\t"
                    << std::hex << len_image<< std::dec <<std::dec <<std::endl;
            return ss.str();
        }

        std::size_t get_total_length() {
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                TYPE total_len = len + get_prefix_length();
                return static_cast<std::size_t>(total_len.to_integral());
            } else {
                return 0;
            }
        }

        virtual ~node_header(){}


        void peek_and_decode_data(std::vector<zkevm_word_type> &_raw, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            this->_peek_and_decode_data(_raw, rlp_encoding_index, rlc_accumulator);
            this->_set_prefix_rlc_and_index(rlp_encoding_index, rlc_accumulator);
            this->_set_length_info();
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
                _raw.erase(_raw.begin());

                this->prefix[1] = 0;
                this->prefix[2] = 0;
                this->prefix_exists[0] = 1;
                this->prefix_exists[1] = 0;
                this->prefix_exists[2] = 0;
                this->len = this->prefix[0] - this->rlp_constant;
            } else if (_raw[0] >= this->rlp_constant + 56 && _raw[0] <= this->rlp_constant + 56 + 2) { // RLP supports +7 but our values must fit in 2 bytes of length
                zkevm_word_type len_len = _raw[0] - this->rlp_constant - 55;
                this->prefix[0] = _raw[0];
                _raw.erase(_raw.begin());
                this->prefix_exists[0] = 1;
                if (len_len == 1) {
                    this->prefix[1] = _raw[0];
                    _raw.erase(_raw.begin());
                    this->prefix[2] = 0;
                    this->prefix_exists[1] = 1;
                    this->prefix_exists[2] = 0;
                    this->len = this->prefix[1];
                } else if (len_len == 2) {
                    this->prefix[1] = _raw[0]; // _raw[0] is already popped!
                    this->prefix[2] = _raw[1];
                    this->prefix_exists[1] = 1;
                    this->prefix_exists[2] = 1;
                    this->len = (_raw[0] << 8) + _raw[1];
                    _raw.erase(_raw.begin());
                    _raw.erase(_raw.begin());
                } else {
                    throw "Error in RLP decoding4!";
                }
            } else {
                throw "Error in RLP decoding5!";
            }
        }

        context_type &ct; // :(

        void _set_length_info() {
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

        void _rlp_lookup_constraints(TYPE first_element_image, TYPE first_element, TYPE first_element_flag, TYPE node_type) {
            std::vector<TYPE> node_rlp_lookup = {
                prefix[0],
                prefix_1_image,
                prefix[2],
                prefix_1_flag,
                first_element_flag,
                first_element_image,
                node_type, // 0 for array and 1 for string
                len_image
            };
            lookup(node_rlp_lookup, "rlp_table");
            constrain(prefix_1_flag * (prefix_1_image - prefix[1]));
            constrain((1 - prefix_exists[2]) * (len - len_image));
        }



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

        void _after_peek_and_encode_data(std::size_t &rlp_encoding_index, TYPE &rlc_accumulator, bool initialize_rlc=false) {
            if (initialize_rlc)
                rlc_accumulator = this->get_total_length();
            this->_set_prefix_rlc_and_index(rlp_encoding_index, rlc_accumulator);
            this->_set_length_info();
        }
    };


    template<typename FieldType, GenerationStage stage>
    class node_header_array: public node_header<FieldType, stage>,
                            public array_rlp_encoder<typename generic_component<FieldType, stage>::TYPE> {
        using typename generic_component<FieldType, stage>::context_type;
      public:
        using typename generic_component<FieldType, stage>::TYPE;
        using node_header = node_header<FieldType, stage>;

        node_header_array(
            context_type &context_object
        ): node_header(context_object, 0xC0){}

        void rlp_lookup_constraints() {
            this->_rlp_lookup_constraints(0, 0, 0, 0);
        }

        void peek_and_encode_data(std::size_t raw_data_length, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator, bool initialize_rlc=false) {
            _peek_and_encode_data(raw_data_length);
            this->_after_peek_and_encode_data(rlp_encoding_index, rlc_accumulator, initialize_rlc);
        }

        ~node_header_array(){}

        protected:

        void _peek_and_encode_data(std::size_t raw_data_length) {
            BOOST_ASSERT_MSG(raw_data_length <= 65535, "data length more than 65535 bytes!");
            this->_encode_non_single(raw_data_length);
        }

        void _peek_and_decode_data(std::vector<zkevm_word_type> &_raw, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            this->_peek_and_decode_data_non_single(_raw, rlp_encoding_index, rlc_accumulator);
        }
    };


    template<typename FieldType, GenerationStage stage>
    class node_header_string: public node_header<FieldType, stage>,
                              public string_rlp_encoder<typename generic_component<FieldType, stage>::TYPE> {
        using typename generic_component<FieldType, stage>::context_type;

        public:
        using typename generic_component<FieldType, stage>::TYPE;
        using node_header =node_header<FieldType, stage>;

        node_header_string(
            context_type &context_object
        ): node_header(context_object, 0x80) {}

        void rlp_lookup_constraints(TYPE first_element_image, TYPE first_element, TYPE first_element_flag) {
            this->ct.constrain(first_element_flag * (first_element - first_element_image), "");
            this->_rlp_lookup_constraints(first_element_image, first_element, first_element_flag, 1);
        }

        void peek_and_encode_data(std::vector<zkevm_word_type> &raw, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator, bool initialize_rlc=false) {
            _peek_and_encode_data(raw);
            this->_after_peek_and_encode_data(rlp_encoding_index, rlc_accumulator, initialize_rlc);
        }

        ~node_header_string(){}

        protected:
        void _peek_and_decode_data(std::vector<zkevm_word_type> &_raw, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            BOOST_ASSERT_MSG(_raw.size() <= 65535, "data length more than 65535 bytes!");
            if (_raw[0] <= 0x7F) {
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

        void _peek_and_encode_data(std::vector<zkevm_word_type> &_raw) {
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
    };

}  // namespace nil::blueprint::bbf
