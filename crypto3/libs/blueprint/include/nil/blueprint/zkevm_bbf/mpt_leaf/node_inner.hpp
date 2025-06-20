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

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/util.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/rlp_table.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/subcomponents/keccak_table.hpp>
#include <nil/blueprint/zkevm_bbf/mpt_leaf.hpp>
#include <nil/blueprint/zkevm_bbf/mpt_leaf/node_header.hpp>
#include <nil/blueprint/zkevm_bbf/mpt_leaf/utils.hpp>

namespace nil::blueprint::bbf {

    enum class query_type { single_byte_query, full_value_query, no_query };
    enum class padding_type { right_padding, left_padding };

    template<typename FieldType, GenerationStage stage>
    class node_inner: public generic_component<FieldType, stage> {
      public:
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;

        using typename generic_component<FieldType, stage>::TYPE;
        using node_header = node_header<FieldType, stage>;

        node_header* header;
        query_type q_type;

        TYPE rlc_challenge;

        node_inner(
            context_type &context_object,
            query_type _q_type
        ): generic_component<FieldType, stage>(context_object, false)
         , q_type(_q_type)
         , ct(context_object) {}

        void initialize() {
            _initialize_header();
            _initialize_body();
        }

        void main_constraints(TYPE previous_rlc, TYPE initial_index, TYPE rlc_challenge) {
            header->main_constraints(previous_rlc, initial_index, rlc_challenge);
            this->_main_constraints(initial_index, rlc_challenge);
        }

        virtual void set_rlc_challenge(TYPE _rlc_challenge) {
            header->set_rlc_challenge(_rlc_challenge);
            rlc_challenge = _rlc_challenge;
        }

        virtual void query_constraints(TYPE query_offset, TYPE query_selector, TYPE node_selector) {
            throw "Method not implemented!";
        }

        TYPE get_total_length_constraint() {
            return header->get_total_length_constraint();
        }

        virtual std::vector<zkevm_word_type> empty() {
            throw "Method not implemented!";
        }

        virtual void allocate_witness(std::size_t &column_index, std::size_t &row_index){
            throw "Method not implemented!";
        }

        virtual std::size_t extra_rows_count() {
            throw "Method not implemented!";
        }

        virtual void peek_and_encode_data(std::vector<zkevm_word_type> &raw, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            throw "Method not implemented!";
        }

        virtual void peek_and_decode_data(std::vector<zkevm_word_type> &raw, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            throw "Method not implemented!";
        }

        std::string virtual print() {
            throw "Method not implemented!";
        }

        virtual std::vector<TYPE> set_query_data(std::size_t offset, std::size_t selector) {
            throw "Method not implemented!";
        }

        virtual void rlp_lookup_constraints() {
            throw "Method not implemented!";
        }

        virtual TYPE last_rlc() {
            throw "Method not implemented!";
        }

        virtual TYPE first_data() {
            throw "Method not implemented!";
        }

        virtual TYPE get_query_value_len() {
            throw "Method not implemented!";
        }

        virtual TYPE query_selector_is_found() {
            throw "Method not implemented!";
        }

        virtual std::vector<TYPE> get_query_value() {
            throw "Method not implemented!";
        }

        virtual std::size_t get_max_length() {
            throw "Method not implemented!";
        }

        protected:
        context_type &ct;
        void _initialize_header() {
            header->initialize();
        }

        virtual void _initialize_body() {
            throw "Method not implemented!";
        }

        virtual void _main_constraints(TYPE initial_index, TYPE rlc_challenge) {
            throw "Method not implemented!";
        }

        // void _constrain_all_rows(TYPE c, std::string constrain_name="") {
        //     if constexpr (stage == GenerationStage::CONSTRAINTS)
        //         this->ct.relative_constrain(this->ct.relativize(c, 1), 0, 1, constrain_name);
        // }
    };


    template<typename FieldType, GenerationStage stage>
    class node_inner_string: public node_inner<FieldType, stage> {
    public:
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;

        using typename generic_component<FieldType, stage>::TYPE;
        using node_header_string = node_header_string<FieldType, stage>;
        using node_inner = node_inner<FieldType, stage>;
        using optimized_selector = optimized_selector<FieldType, stage>;

        node_inner_string(
            context_type &context_object,
            std::size_t _max_data_length,
            query_type _q_type = query_type::no_query,
            bool _is_fixed_length = false,
            padding_type _padding = padding_type::right_padding
        ): node_inner(context_object, _q_type)
         , max_data_len(_max_data_length)
         , is_fixed_length(_is_fixed_length)
         , padding(_padding)
         , len_selector(context_object, _max_data_length + 1)
         , offset_selector(context_object, _max_data_length) {
            h = new node_header_string(context_object);
            this->header = h;

            data.resize(max_data_len);
            index.resize(max_data_len);
            rlc.resize(max_data_len);
        }

        std::size_t get_max_length() {
            if (this->q_type == query_type::single_byte_query)
                return 1;
            else if (this->q_type == query_type::full_value_query)
                return this->max_data_len;
            else
                throw "non-query node doesn't have query length!";
        }

        std::size_t extra_rows_count() {
            return 0;
        }

        std::string print() {
            std::stringstream ss;
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                ss << h->print();
                auto raw_data_length = static_cast<std::uint64_t>(h->len.to_integral());
                ss << "\trlc_challenge: " << this->rlc_challenge << std::endl;
                ss << "\tdata\tindex\tselector\tfinished\trlc " << std::endl;
                for (size_t i = 0; i < data.size(); i++) {
                    ss << "\t"
                        << std::hex << data[i] << std::dec << "\t"
                        << std::hex << index[i] << std::dec <<"\t"
                        << std::hex << offset_selector.get_selector(i) << std::dec <<"\t\t"
                        << std::hex << len_selector.selector_accumulator(i+1) << std::dec <<"\t\t"
                        << std::hex << rlc[i] << std::dec << "\t"
                        << std::endl;
                }
                std::cout << "len selector:\n";
                len_selector.print();
                std::cout << "offset selector:\n";
                offset_selector.print();
            }
            return ss.str();
        }

        TYPE last_rlc() {
            return rlc[rlc.size() - 1];
        }

        TYPE first_data() {
            return this->header->prefix_exists[0] * this->header->prefix[0] + (1 - this->header->prefix_exists[0]) * data[0];
        }

        void allocate_witness(std::size_t &column_index, std::size_t &row_index){
            h->allocate_witness(column_index, row_index);
            allocate(first_element_image, column_index++, row_index);
            allocate(first_element_flag, column_index++, row_index);
            for (std::size_t k = 0; k < data.size(); k++) {
                allocate(data[k], column_index++, row_index);
                allocate(rlc[k], column_index++, row_index);
                if (!is_fixed_length) {
                    allocate(index[k], column_index++, row_index);
                }
            }
            if (this->q_type == query_type::single_byte_query)
                offset_selector.allocate_witness(column_index, row_index);
            if (!is_fixed_length)
                len_selector.allocate_witness(column_index, row_index);
        }

        void rlp_lookup_constraints() {
            h->rlp_lookup_constraints(this->first_element_image, this->data[0], this->first_element_flag);
        }

        void peek_and_decode_data(std::vector<zkevm_word_type> &raw, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            h->peek_and_decode_data(raw, rlp_encoding_index, rlc_accumulator);
            this->_peek_and_set_data(raw, rlp_encoding_index, rlc_accumulator);
        }

        void peek_and_encode_data(std::vector<zkevm_word_type> &raw, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            h->peek_and_encode_data(raw, rlp_encoding_index, rlc_accumulator, false);
            this->_peek_and_set_data(raw, rlp_encoding_index, rlc_accumulator);
        }

        TYPE get_query_value_len() {
            if (this->q_type == query_type::single_byte_query)
                return 1;
            return this->header->len;
        }

        std::vector<TYPE> set_query_data(std::size_t offset, std::size_t selector) {
            // we don't need selector here
            if (this->q_type == query_type::single_byte_query) {
                BOOST_ASSERT_MSG(offset < max_data_len, "Query offset exceeded the data size!");
                TYPE query_value = padded_data()[offset];
                offset_selector.set_data(offset);
                return {query_value};
            } 
            else if (this->q_type == query_type::full_value_query)
                return padded_data();
            else 
                throw "Setting qurey data for non-query node!";
        }

        void query_constraints(TYPE query_offset, TYPE query_selector, TYPE node_selector) {
            if (this->q_type == query_type::single_byte_query)
                offset_selector.constraints(query_offset, false);
        }

        TYPE query_selector_is_found() {
            if (this->q_type == query_type::single_byte_query)
                return offset_selector.selector_is_found();
            return 1;
        }

        std::vector<TYPE> padded_data() {
            std::vector<TYPE> padded(max_data_len);
            if (padding == padding_type::right_padding) {
                for (size_t i = 0; i < padded.size(); i++)
                    padded[i] = data[i] * (1 - len_selector.selector_accumulator(i));
                return padded;
            }
            if (is_fixed_length == true)
                return data;
            for (size_t i = 0; i < max_data_len; i++) {
                padded[i] = 0;
                for (size_t j = 0; j <= i; j++)
                    padded[i] += data[j] * len_selector.get_selector(max_data_len - i + j);
            }
            return padded;
        }

        std::vector<TYPE> get_query_value() {
            std::vector<TYPE> padded = padded_data();
            if (this->q_type == query_type::single_byte_query) {
                TYPE value_sum;
                for (size_t i = 0; i < max_data_len; i++)
                    value_sum += offset_selector.get_selector(i) * padded[i];
                return {value_sum};
            } 
            else if (this->q_type == query_type::full_value_query)
                return padded;
            else 
                throw "Non-query node doesn't have query value!";
        }

        std::vector<zkevm_word_type> empty() {
            return {};
        }

    protected:
        node_header_string* h;
        std::vector<TYPE> data;
        std::vector<TYPE> index;
        std::vector<TYPE> rlc;
        TYPE first_element_image;
        TYPE first_element_flag;
        std::size_t max_data_len;
        bool is_fixed_length;
        optimized_selector len_selector;
        optimized_selector offset_selector;
        padding_type padding;

        void _initialize_body() {
            for (size_t j = 0; j < data.size(); j++) {
                data[j] = 0;
                index[j] = 0;
            }
            len_selector.initialize();
        }

        void _peek_and_set_data(std::vector<zkevm_word_type> &raw, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            this->_peek_data(raw, rlp_encoding_index, rlc_accumulator);
            this->_set_index_and_rlc(rlp_encoding_index, rlc_accumulator);
            this->_set_selector_data();
        }

        void _peek_data(std::vector<zkevm_word_type> &raw, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                auto raw_data_length = static_cast<std::uint64_t>(this->header->len.to_integral());
                BOOST_ASSERT_MSG(raw.size() >= raw_data_length, "Error in RLP decoding3!");

                for (size_t j = 0; j < raw_data_length; j++) {
                    data[j] = raw[0];
                    raw.erase(raw.begin());
                }

                if (raw_data_length == 1) {
                    first_element_flag = 1;
                    first_element_image = data[0];
                } else {
                    first_element_flag = 0;
                    first_element_image = 0;
                }
            }
        }

        void _set_selector_data() {
            if constexpr  (stage == GenerationStage::ASSIGNMENT) {
                auto index = static_cast<std::uint64_t>(h->len.to_integral());
                len_selector.set_data(index);
            }
        }

        void _set_index_and_rlc(std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                auto raw_data_length = static_cast<std::uint64_t>(h->len.to_integral());
                if (this->is_fixed_length)
                    raw_data_length = this->max_data_len;
                for (size_t j = 0; j < raw_data_length; j++) {
                    index[j] = rlp_encoding_index++;
                    rlc[j] = rlc_accumulator * this->rlc_challenge + this->data[j];
                    rlc_accumulator = rlc[j];
                }
                for (size_t j = raw_data_length; j < rlc.size(); j++) {
                    rlc[j] = rlc_accumulator;
                }
            }
        }

        void _main_constraints(TYPE initial_index, TYPE rlc_challenge) {
            TYPE first_data_index = initial_index + this->header->get_prefix_length();
            if (is_fixed_length) {
                constrain(h->len - max_data_len, "Length must be fixed!");
                constrain(rlc[0] - (h->prefix_rlc[2] * rlc_challenge + data[0]), "RLC of first data element is wrong!");
            } else {
                len_selector.constraints(h->len);

                TYPE len_is_zero = len_selector.get_selector(0);
                constrain(len_is_zero * index[0] +
                    (1 - len_is_zero) * (index[0] - first_data_index), "Determine initial index based on whether RLP length is zero or not!");
                // constrain(len_is_zero * data[0]);
                constrain(len_is_zero * (rlc[0] - h->prefix_rlc[2]) +
                    (1 - len_is_zero) * (rlc[0] - (h->prefix_rlc[2] * rlc_challenge + data[0])), "Determine initial RLC based on whether RLP length is zero or not!");

            }

            for (size_t i = 1; i < 2; i++) {
                if (is_fixed_length) {
                    constrain(rlc[i] - (rlc[i-1] * rlc_challenge + data[i]), "For fixed length strings RLC should always accumulate!");
                } else {
                    TYPE data_finished = len_selector.selector_accumulator(i); // not including this column
                    constrain( data_finished * index[i] +
                        (1 - data_finished) * (i+9) * (index[i-1] + 1 - index[i]), "Index must increase if data is not finished!");
                    // we no longer enforce the data to be empty. node_inner_key use the empty space for key prefix
                    // constrain(data[i] * data_finished);
                    constrain(rlc[i] - (data_finished * rlc[i-1] + (1 - data_finished) * (rlc[i-1] * rlc_challenge + data[i])), "Data RLC is wrong!");
                }
            }
            for (size_t i = 0; i < data.size(); i++)
                lookup(data[i], "chunk_16_bits/8bits");
        }
    };



    template<typename FieldType, GenerationStage stage>
    class node_inner_key: public node_inner_string<FieldType, stage> {
    public:
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;

        using typename generic_component<FieldType, stage>::TYPE;
        using node_inner_string = node_inner_string<FieldType, stage>;
        using optimized_selector = optimized_selector<FieldType, stage>;

        std::size_t original_key_size;
        std::size_t trie_key_size = 32; // later change this for transaction/receipt trie
        TYPE prefix_has_last_nibble;
        std::vector<TYPE> original_key;

        node_inner_key(
            context_type &context_object,
            mpt_type _trie_t
        ): node_inner_string(
            context_object, 
            33,  // 32 bytes is the hash output and one byte is for the leaf-node prefix
            query_type::no_query, 
            false, 
            padding_type::right_padding),
            trie_type(_trie_t) {
                if (_trie_t == mpt_type::storage_trie) {
                    original_key_size = 32;
                } else if (_trie_t == mpt_type::account_trie) {
                    original_key_size = 20;
                } else
                    throw "Unknown trie type!";
                original_key.resize(original_key_size);
                original_key_rlc.resize(original_key_size);
                prefix_length_selector = new optimized_selector(context_object, trie_key_size + 1);
            }

        std::string print() {
            std::stringstream ss;
            ss << "node inner key:";

            TYPE selector = 1;
            TYPE trie_id = 1;
            TYPE child_nibble_present = prefix_has_last_nibble;
            TYPE parent_length = prefix_length_selector->get_value() * 2 + child_nibble_present - 1;
            ss << "\tparent lookup info:\n";
            ss << "\t\tchild_nibble_present " << child_nibble_present << std::endl;
            ss << "\t\tparent_length " << parent_length << std::endl;
            ss << "\t\taccumulated key: ";

               
            std::vector<TYPE> child(trie_key_size);
            for (size_t i = 0; i < trie_key_size; i++) {
                for (size_t j = i + 1; j < trie_key_size; j++) {
                    child[trie_key_size - j + i] += this->data[trie_key_size + 1 - j + i] * prefix_length_selector->get_selector(j);
                }
            }

            for (size_t i = 0; i < trie_key_size - 1; i++) {
                if constexpr (stage == GenerationStage::ASSIGNMENT)
                    if (child[i] < 0x10)
                        ss << "0";
                ss << std::hex << child[i] << std::dec;
            }
            ss << std::endl;
            ss << "\t\tlast byte: " << std::hex << child[trie_key_size - 1] << std::dec << std::endl;



            ss << "\tprefix last nibble: " << prefix_last_nibble << std::endl;
            ss << "\tkey first nibble: " << key_first_nibble << std::endl;
            ss << "\tprefix has last nibble: " << prefix_has_last_nibble << std::endl;
            ss << "\tprefix length: " << prefix_length_selector->get_value() << std::endl;
            ss << "\tkey prefix:\n";
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                std::size_t len = static_cast<std::uint32_t>(this->h->len.to_integral());
                for (size_t i = len; i < trie_key_size + 1 ;i++)
                    ss << std::hex << this->data[i] << std::dec << " ";
                ss << std::endl;
            }
            ss << node_inner_string::print();
            return ss.str();
        }

        void set_key_prefix(std::vector<zkevm_word_type> _original_key) {
            BOOST_ASSERT_MSG(this->h->len > 0, "Key is at least one byte!");
            BOOST_ASSERT_MSG(_original_key.size() == original_key_size, "Original key's length is wrong!");

            for (size_t i = 0; i < _original_key.size(); i++)
                original_key[i] = _original_key[i];
            
            std::vector<std::uint8_t> buffer(_original_key.begin(), _original_key.end());
            std::array<std::uint8_t, 32> trie_key = w_to_8(nil::blueprint::zkevm_keccak_hash(buffer));

            original_key_rlc[0] = this->rlc_challenge * original_key_size + original_key[0];
            for (size_t i = 1; i < original_key_size; i++)
                original_key_rlc[i] = original_key_rlc[i-1] * this->rlc_challenge + original_key[i];
            

            std::stringstream ss;
            ss << "trie key:\n";
            for (size_t i = 0; i < trie_key.size(); i++)
                ss << std::hex << int(trie_key[i]) << std::dec << " ";
            ss << std::endl;
            BOOST_LOG_TRIVIAL(debug) << ss.str();

            std::uint32_t first_byte = static_cast<std::uint32_t>(this->data[0].to_integral());
            std::size_t prefix_length;
            TYPE control_nibble = first_byte >> 4;
            key_first_nibble = first_byte & 0xF;
            std::size_t len = static_cast<std::uint32_t>(this->h->len.to_integral());
            if (control_nibble == 2) {
                BOOST_ASSERT_MSG(key_first_nibble == 0, "Wrong key first nibble!");
                prefix_last_nibble = 0;
                key_first_nibble = 0;
                prefix_length = trie_key.size() - (len - 1);
            } else if (control_nibble == 3) {
                prefix_length = trie_key.size() - len;
                BOOST_ASSERT_MSG(prefix_length < trie_key.size(), "Wrong key size!");
                prefix_last_nibble = (trie_key[prefix_length] >> 4) & 0xF;
            }
            prefix_length_selector->set_data(prefix_length);
            
            prefix_has_last_nibble = control_nibble - 2;

            for (size_t i = trie_key_size + 1 - prefix_length; i < trie_key_size + 1; i++)
                this->data[i] = trie_key[i - trie_key_size - 1 + prefix_length];
        }

        void allocate_witness(std::size_t &column_index, std::size_t &row_index){
            node_inner_string::allocate_witness(column_index, row_index);

            allocate(prefix_last_nibble, column_index++, row_index);
            allocate(key_first_nibble, column_index++, row_index);
            allocate(prefix_has_last_nibble, column_index++, row_index);
            for (size_t i = 0; i < original_key.size(); i++)
                allocate(original_key[i], column_index ++, row_index); 
            for (size_t i = 0; i < original_key_rlc.size(); i++)
                allocate(original_key_rlc[i], column_index ++, row_index);
            
            prefix_length_selector->allocate_witness(column_index, row_index);
        }

        std::optional<std::vector<std::uint8_t>> get_keccak_buffer() {
            if (trie_type == mpt_type::account_trie || trie_type == mpt_type::storage_trie) {
                std::vector<std::uint8_t> buffer;
                for (size_t i = 0; i < original_key.size(); i++)
                    buffer.push_back(static_cast<std::uint64_t>(original_key[i].to_integral()));
                return buffer;
            }
            return std::nullopt;
        }

        std::pair<std::vector<zkevm_word_type>, std::vector<zkevm_word_type>> empty_key() {
            std::vector<zkevm_word_type> original_key;
            if (this->trie_type == mpt_type::storage_trie)
                for (size_t i = 0; i < 32; i++)
                    original_key.push_back(0x00);
            else if (this->trie_type == mpt_type::account_trie)
                for (size_t i = 0; i < 20; i++)
                    original_key.push_back(0x00);
            else
                throw "Unknown trie type!";
                
            std::vector<std::uint8_t> buffer(original_key.begin(), original_key.end());
            std::vector<zkevm_word_type> trie_key(33);
            trie_key[0] = 0x20;
            int i = 1;
            for (auto &w : w_to_8(nil::blueprint::zkevm_keccak_hash(buffer))) {
                trie_key[i] = zkevm_word_type(w);
                i++;
            }
            return {trie_key, original_key};
        }

        TYPE get_prefix_length() {
            return prefix_length_selector->get_value();
        }

        std::vector<TYPE> get_accumulated_key() {
            std::vector<TYPE> accumulated_key(trie_key_size);
            for (size_t i = 0; i < trie_key_size; i++) {
                for (size_t j = i + 1; j < trie_key_size; j++) {
                    accumulated_key[trie_key_size - j + i] += this->data[trie_key_size + 1 - j + i] * prefix_length_selector->get_selector(j);
                }
            }
            return accumulated_key;
        }

    protected:
        mpt_type trie_type;
        std::vector<TYPE> original_key_rlc;
        // std::vector<TYPE> key_prefix;
        optimized_selector* prefix_length_selector;
        TYPE prefix_last_nibble;
        TYPE key_first_nibble;

        void _initialize_body() {
            node_inner_string::_initialize_body();
            prefix_length_selector->initialize();
        }

        void _main_constraints(TYPE initial_index, TYPE rlc_challenge) {
            TYPE control_nibble = prefix_has_last_nibble + 2;
            constrain(prefix_has_last_nibble * (prefix_has_last_nibble - 1), "incorrect control nibble!");
            constrain(this->data[0] - control_nibble * 0x10 - key_first_nibble, "incorrect first key data!");
            constrain((1 - prefix_has_last_nibble) * key_first_nibble, "key_first_nibble must be zero if key doesn't have a nibble!");
            constrain(prefix_length_selector->get_value() - ( 
                prefix_has_last_nibble * (trie_key_size - this->h->len)
                + (1 - prefix_has_last_nibble) * (trie_key_size - this->h->len + 1))
                , "Prefix length should be calculated based on both prefix_has_last_nibble and key's rlp header length"
            );

            constrain(original_key_rlc[0] - (original_key_size * rlc_challenge + original_key[0]), "Wrong initial RLC in original key!");
            for (size_t i = 1; i < original_key_size; i++)
                constrain(original_key_rlc[i] - (original_key_rlc[i-1] * rlc_challenge + original_key[i]), "Wrong RLC in original key!");
            
            for (size_t i = 0; i < original_key_size; i++)
                lookup(original_key[i], "chunk_16_bits/8bits");


            // 32 must be changed for transaction and receipt tries
            std::array<TYPE, 32> trie_key;
            for (size_t i = 0; i < trie_key_size; i++) {
                for (size_t j = i + 1; j < trie_key_size; j++) {
                    trie_key[i] += this->data[trie_key_size + 1 - j + i] * prefix_length_selector->get_selector(j);
                }
                trie_key[i] += (prefix_has_last_nibble * (prefix_last_nibble * 0x10 + key_first_nibble) + (1 - prefix_has_last_nibble) * this->data[1]) * prefix_length_selector->get_selector(i);
                for (size_t j = 0; j < i; j++) {
                    trie_key[i] += this->data[i - j] * (prefix_has_last_nibble * prefix_length_selector->get_selector(j)) + (1 - prefix_has_last_nibble) * prefix_length_selector->get_selector(j) * this->data[i - j + 1];
                }
            }

            auto keccak_tuple = chunks8_to_chunks16<TYPE>(trie_key);
            keccak_tuple.emplace(keccak_tuple.begin(), original_key_rlc[original_key_size-1]);
            lookup(keccak_tuple, "keccak_table");
            
            node_inner_string::_main_constraints(initial_index, rlc_challenge);
        }
    
    };




    template<typename FieldType, GenerationStage stage>
    class node_inner_array: public node_inner<FieldType, stage> {
      public:
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;

        using typename generic_component<FieldType, stage>::TYPE;
        using node_header_array = node_header_array<FieldType, stage>;
        using node_inner = node_inner<FieldType, stage>;
        using node_inner_string = node_inner_string<FieldType, stage>;

        std::vector<node_inner*> inners;
        std::vector<TYPE> selectors;

        static node_inner_array* new_node_inner_array(context_type &context_object, mpt_type trie_type, query_type _q_type) {
            node_inner_array* n = new node_inner_array(context_object, _q_type);
            std::vector<std::size_t> lengths;
            std::vector<bool> is_fixed;
            std::vector<padding_type> paddings;
            if (trie_type == mpt_type::account_trie) {
                lengths = {
                    8,  // nonce
                    32, // balance
                    32, // storage hash
                    32, // byte code hash
                };
                is_fixed = {
                    false,
                    false,
                    true,
                    true
                };
                paddings = {
                    padding_type::left_padding,
                    padding_type::left_padding,
                    padding_type::right_padding,
                    padding_type::right_padding
                };
            } else {
                throw "Unknown trie type!";
            }
            for (size_t i = 0; i < lengths.size(); i++)
                n->add_inner(lengths[i], is_fixed[i], paddings[i]);
            return n;
        }

        node_inner_array(
            context_type &context_object,
            query_type _q_type
        ):
            node_inner(
                context_object,
                _q_type
            ), ct(context_object) {
            h = new node_header_array(context_object);
            this->header = h;
        }

        std::size_t get_max_length() {
            if (this->q_type == query_type::single_byte_query)
                return 1;
            else if (this->q_type == query_type::full_value_query) {
                std::size_t max = 0;
                for (auto &i : inners) {
                    if (i->get_max_length() > max)
                        max = i->get_max_length();
                }
                return max;
            } else
                throw "non-query node doesn't have query length!";
        }

        void set_rlc_challenge(TYPE _rlc_challenge) {
            for (auto &i : inners)
                i->set_rlc_challenge(_rlc_challenge);
            node_inner::set_rlc_challenge(_rlc_challenge);
        }

        std::size_t extra_rows_count() {
            std::size_t rows = 0;
            for (auto &i : this->inners)
                rows += i->extra_rows_count();
            return rows;
        }

        TYPE last_rlc() {
            return inners[inners.size()-1]->last_rlc();
        }

        std::string print() {
            std::stringstream ss;
            ss << "array:\n";
            ss << h->print();
            for (size_t i = 0; i < inners.size(); i++) {
                ss << "inner " << i << " selector " << selectors[i] << ":"<< std::endl;
                ss << inners[i]->print();
            }
            return ss.str();
        }

        TYPE first_data() {
            return h->prefix[0];
        }

        void allocate_witness(std::size_t &column_index, std::size_t &row_index) {
            h->allocate_witness(column_index, row_index);
            for (size_t i = 0; i < inners.size(); i++) {
                inners[i]->allocate_witness(column_index, row_index);
            }
            for (size_t i = 0; i < selectors.size(); i++) {
                allocate(selectors[i], column_index++, row_index);
            }

        }

        void peek_and_decode_data(std::vector<zkevm_word_type> &raw, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            h->peek_and_decode_data(raw, rlp_encoding_index, rlc_accumulator);
            for (auto &i : inners)
                i->peek_and_decode_data(raw, rlp_encoding_index, rlc_accumulator);
        }

        std::vector<zkevm_word_type> empty() {
            return {0xC0};
        }

        std::vector<TYPE> set_query_data(std::size_t offset, std::size_t selector) {
            BOOST_ASSERT_MSG(selector < inners.size(), "Query selector is wrong!");
            selectors[selector] = 1;
            // left padding with zero
            std::vector<TYPE> value_inner = inners[selector]->set_query_data(offset, 1);
            if (this->q_type == query_type::full_value_query) {
                std::vector<TYPE> value(this->get_max_length());
                value.clear();
                value.resize(this->get_max_length());
                std::size_t shift = value.size() - value_inner.size();
                for (size_t i = shift; i < value.size(); i++)
                    value[i] = value_inner[i - shift];
                return value;
            } else if (this->q_type == query_type::single_byte_query) {
                return value_inner;
            } else {
                throw "Setting query data for non-query node!";
            }
        }

        TYPE get_query_value_len() {
            // TODO remove this when query type is full value
            TYPE sum = 0;
            for (size_t i = 0; i < selectors.size(); i++)
                sum += selectors[i] * inners[i]->get_query_value_len();
            return sum;
        }

        TYPE query_selector_is_found() {
            TYPE sum = 0;
            for (size_t i = 0; i < selectors.size(); i++)
                sum += selectors[i] * inners[i]->query_selector_is_found();
            return sum;
        }

        std::vector<TYPE> get_query_value() {
            std::vector <TYPE> values;
            if (this->q_type == query_type::single_byte_query) {
                values.push_back(0);
                for (size_t i = 0; i < selectors.size(); i++)
                    values[0] += selectors[i] * inners[i]->get_query_value()[0];
            } else if (this->q_type == query_type::full_value_query) {
                values.resize(this->get_max_length());
                for (size_t i = 0; i < selectors.size(); i++) {
                    std::vector<TYPE> value_inner = inners[i]->get_query_value();
                    std::size_t shift = values.size() - value_inner.size();
                    for (size_t j = shift; j < values.size(); j++){
                        values[j] += selectors[i] * value_inner[j - shift];
                    }
                }
            }
            return values;
        }

        void query_constraints(TYPE query_offset, TYPE query_selector, TYPE node_selector) {
            for (auto &i : inners)
                i->query_constraints(query_offset, 1, node_selector);
            for (size_t i = 0; i < selectors.size(); i++) {
                constrain(selectors[i] * (1 - selectors[i]), "Query selector must be binary!");
                constrain(selectors[i] * (query_selector - i));
            }
        }

        void add_inner(std::size_t length, bool is_fixed_length, padding_type padding) {
            inners.push_back(new node_inner_string(
                ct,
                length,
                this->q_type,
                is_fixed_length,
                padding
            ));
            selectors.resize(selectors.size() + 1);
            selectors[selectors.size() - 1] = 0;
        }

    protected:
        node_header_array* h;
        context_type &ct; // :(

        void _initialize_body() {
            for (auto &i : inners) {
                i->initialize();
            }
        }

        void _main_constraints(TYPE initial_index, TYPE rlc_challenge) {
            TYPE total_len;
            for (auto &i : inners)
                total_len += i->get_total_length_constraint();
            constrain(h->len - total_len, "Array node's rlp length must be sum of all of its inner nodes' length!");

            TYPE next_index, previous_rlc;
            for (size_t i = 0; i < this->inners.size(); i++) {
                if (i == 0) {
                    previous_rlc = h->prefix_rlc[2];
                    next_index = h->get_prefix_length() + initial_index;
                } else {
                    next_index = next_index + this->inners[i-1]->get_total_length_constraint();
                    previous_rlc = this->inners[i-1]->last_rlc();
                }
                this->inners[i]->main_constraints(previous_rlc, next_index, rlc_challenge);
            }
        }

        void rlp_lookup_constraints() {
            h->rlp_lookup_constraints();
            for (size_t i = 0; i < 1; i++){
                this->inners[i]->rlp_lookup_constraints();
            }
        }
    };



    template<typename FieldType, GenerationStage stage>
    class node_inner_container: public node_inner<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;

    public:
        using typename generic_component<FieldType, stage>::TYPE;
        using node_inner = node_inner<FieldType, stage>;
        using node_inner_string = node_inner_string<FieldType, stage>;
        using node_header_string = node_header_string<FieldType, stage>;
        using node_inner_array = node_inner_array<FieldType, stage>;

        node_inner* inner;
        mpt_type trie_type;

        TYPE first_element_flag;
        TYPE first_element_image;
        node_header_string* h;

        node_inner_container(
            context_type &context_object,
            mpt_type _trie_type,
            query_type _q_type
        ): node_inner( context_object, _q_type)
         , trie_type(_trie_type) {
            h = new node_header_string(context_object);
            this->header = h;
            if (_trie_type == mpt_type::storage_trie)
                inner = new node_inner_string(
                    context_object,
                    get_max_rlp_length(32),
                    _q_type,
                    false,
                    padding_type::left_padding
                );
            else
                inner = node_inner_array::new_node_inner_array(context_object, _trie_type, _q_type);

        }

        void set_rlc_challenge(TYPE _rlc_challenge) {
            inner->set_rlc_challenge(_rlc_challenge);
            node_inner::set_rlc_challenge(_rlc_challenge);
        }

        std::size_t extra_rows_count() {
            return 0;
        }

        std::string print() {
            std::stringstream ss;
            ss << "container:\n";
            ss << this->header->print();
            ss << "\tfirst element image\tfirst element flag\n\t" << first_element_image << "\t\t\t" << first_element_flag << std::endl;
            ss << "inner:\n";
            ss << this->inner->print();
            return ss.str();
        }

        TYPE last_rlc() {
            return this->inner->last_rlc();
        }

        void allocate_witness(std::size_t &column_index, std::size_t &row_index){
            h->allocate_witness(column_index, row_index);
            allocate(first_element_image, column_index++, row_index);
            allocate(first_element_flag, column_index++, row_index);
            this->inner->allocate_witness(column_index, row_index);
        }

        void rlp_lookup_constraints() {
            this->h->rlp_lookup_constraints(
                first_element_image,
                this->inner->first_data(),
                first_element_flag);
            this->inner->rlp_lookup_constraints();
        }

        std::vector<zkevm_word_type> empty() {
            if (trie_type == mpt_type::storage_trie)
                return {0x80};
            else if (trie_type == mpt_type::account_trie)
                return {
                    0xf8,
                    0x44,
                    0x80,
                    0x80,
                    0xa0,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0xa0,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00
                };
                // TODO fix this
            else
                throw "Unknown trie type!";
        }
        
        void peek_and_encode_data(std::vector<zkevm_word_type> &raw, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            h->peek_and_encode_data(raw, rlp_encoding_index, rlc_accumulator, false);
            inner->peek_and_decode_data(raw, rlp_encoding_index, rlc_accumulator);
            if (inner->header->get_total_length() == 1) {
                first_element_flag = 1;
                first_element_image = inner->first_data();
            } else {
                first_element_flag = 0;
                first_element_image = 0;
            }
        }

        TYPE get_query_value_len() {
            return inner->get_query_value_len();
        }

        std::vector<TYPE> set_query_data(std::size_t query_offset, std::size_t query_selector) {
            return inner->set_query_data(query_offset, query_selector);
        }

        void query_constraints(TYPE query_offset, std::vector<TYPE> query_value, TYPE query_selector, TYPE query_value_len, TYPE node_selector) {
            this->inner->query_constraints(query_offset, query_selector, node_selector);
            std::vector<TYPE> inner_value = inner->get_query_value();
            BOOST_ASSERT_MSG(inner_value.size() == query_value.size(), "Value has incorrect length!");
            if (this->q_type == query_type::single_byte_query) {
                constrain(1 - inner->query_selector_is_found(), "Query offset exceeded the max length!");
                constrain(query_value_len - inner->get_query_value_len(), "Query value length is incorrect!");
            }
            for (size_t i = 0; i < query_value.size(); i++)
                constrain(query_value[i] - inner_value[i], "Query value is incorrect!");
        }

        std::size_t get_max_length() {
            return inner->get_max_length();
        }

    protected:
        void _initialize_body() {
            this->inner->initialize();
        }

        void _main_constraints(TYPE initial_index, TYPE rlc_challenge) {
            TYPE first_data_index = initial_index + this->header->get_prefix_length();
            this->inner->main_constraints(this->header->prefix_rlc[2], first_data_index, rlc_challenge);
        }
    };

}  // namespace nil::blueprint::bbf
