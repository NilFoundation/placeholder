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
         , q_type(_q_type){}

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

        virtual void print() {
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
        void _initialize_header() {
            header->initialize();
        }

        virtual void _initialize_body() {
            throw "Method not implemented!";
        }

        virtual void _main_constraints(TYPE initial_index, TYPE rlc_challenge) {
            throw "Method not implemented!";
        }
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
         , len_selector(context_object, _max_data_length+1)
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

        void print() {
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                h->print();
                auto raw_data_length = static_cast<std::uint64_t>(h->len.to_integral());
                std::cout << "\trlc_challenge: " << this->rlc_challenge << std::endl;
                std::cout << "\tdata\tindex\tselector\tfinished\trlc " << std::endl;
                for (size_t i = 0; i < data.size(); i++) {
                    std::cout << "\t"
                        << std::hex << data[i] << std::dec << "\t"
                        << std::hex << index[i] << std::dec <<"\t"
                        << std::hex << offset_selector.get_selector(i) << std::dec <<"\t\t"
                        << std::hex << len_selector.selector_accumulator(i+1) << std::dec <<"\t\t"
                        << std::hex << rlc[i] << std::dec << "\t"
                         << std::endl;
                }
                // std::cout << "len selector:\n";
                // len_selector.print();
                // std::cout << "offset selector:\n";
                // offset_selector.print();
            }
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
            if (padding == padding_type::right_padding)
                return data;
            if (is_fixed_length == true)
                return data;
            std::vector<TYPE> padded(max_data_len);
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
        // std::vector<TYPE> len_selector_x;
        // std::vector<TYPE> len_selector_y;
        std::vector<TYPE> rlc;
        // std::vector<TYPE> offset_selector;
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
            // offset_selector.initialize();
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

        void _constrain_is_zero(TYPE is_zero, TYPE inverse, TYPE X, TYPE selector=1) {
            constrain(selector * (is_zero - (1 - X * inverse)));
            constrain(selector * (X * is_zero));
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
                    (1 - len_is_zero) * (index[0] - first_data_index));
                constrain(len_is_zero * data[0]);
                constrain(len_is_zero * (rlc[0] - h->prefix_rlc[2]) +
                    (1 - len_is_zero) * (rlc[0] - (h->prefix_rlc[2] * rlc_challenge + data[0])));
            }

            for (size_t i = 1; i < data.size(); i++) {
                if (is_fixed_length) {
                    constrain(rlc[i] - (rlc[i-1] * rlc_challenge + data[i]), "For fixed length strings RLC should always accumulate!");
                } else {
                    TYPE data_finished = len_selector.selector_accumulator(i); // not including this column
                    constrain( data_finished * index[i] +
                        (1 - data_finished) * (index[i] - index[i-1] - 1));
                    constrain(data[i] * data_finished);
                    constrain(rlc[i] - (data_finished * rlc[i-1] + (1 - data_finished) * (rlc[i-1] * rlc_challenge + data[i])), "Data RLC is wrong!");
                }
            }
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

        void print() {
            std::cout << "array:\n";
            h->print();
            for (size_t i = 0; i < inners.size(); i++) {
                std::cout << "inner " << i << " selector " << selectors[i] << ":"<< std::endl;
                inners[i]->print();
            }

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
            constrain(h->len - total_len);

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
            for (size_t i = 0; i < this->inners.size(); i++){
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

        void print() {
            std::cout << "container:\n";
            this->header->print();
            std::cout << "\tfirst element image\tfirst element flag\n\t" << first_element_image << "\t\t\t" << first_element_flag << std::endl;
            std::cout << "inner:\n";
            this->inner->print();
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

            if (this->trie_type != mpt_type::storage_trie || this->q_type == query_type::single_byte_query)
                constrain(inner->query_selector_is_found() - 1, "Query offset exceeded the max length!");
            for (size_t i = 0; i < query_value.size(); i++)
                constrain(query_value[i] - inner_value[i], "Query value is incorrect!");
            if (this->q_type == query_type::single_byte_query)
                constrain(query_value_len - inner->get_query_value_len(), "Query value length is incorrect!");
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
