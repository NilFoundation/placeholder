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
        bool have_query_constraint;

        TYPE rlc_challenge;

        node_inner(
            context_type &context_object,
            bool _have_query_constraint = false
        ):
            generic_component<FieldType, stage>(context_object, false),
            have_query_constraint(_have_query_constraint) {

        }

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

        virtual TYPE set_query_data(std::size_t offset, std::size_t selector) {
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
            throw "Method not implemented4!";
        }

        virtual TYPE query_selector_is_found() {
            throw "Method not implemented4!";
        }

        virtual TYPE get_query_value() {
            throw "Method not implemented4!";
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

        optimized_selector len_selector;
        optimized_selector offset_selector;

        // optimized_selector<FieldType, stage> offset_selector;

        node_inner_string(
            context_type &context_object,
            std::size_t _max_data_length,
            bool _have_query_constraints = false,
            bool _is_fixed_length = false
        ): node_inner(
            context_object,
            _have_query_constraints
        ), max_data_len(_max_data_length)
         , is_fixed_length(_is_fixed_length)
         , len_selector(context_object, _max_data_length+1)
         , offset_selector(context_object, _max_data_length) {
            h = new node_header_string(context_object);
            this->header = h;

            data.resize(max_data_len);
            index.resize(max_data_len);
            rlc.resize(max_data_len);
        }

        std::size_t extra_rows_count() {
            return 0;
        }

        void print() {
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                h->print();
                auto raw_data_length = static_cast<std::uint64_t>(h->len.to_integral());
                std::cout << "\trlc_challenge: " << this->rlc_challenge << " query value: " << get_query_value() << std::endl;
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
            if (this->have_query_constraint)
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
            return this->header->len;
        }

        TYPE set_query_data(std::size_t offset, std::size_t selector) {
            // we don't need selector here
            BOOST_ASSERT_MSG(offset < max_data_len, "Query offset exceeded the data size!");
            TYPE query_value = data[offset];
            offset_selector.set_data(offset);
            return query_value;
        }

        void query_constraints(TYPE query_offset, TYPE query_selector, TYPE node_selector) {
            offset_selector.constraints(query_offset, false);
        }

        TYPE query_selector_is_found() {
            return offset_selector.selector_is_found();
        }

        TYPE get_query_value() {
            TYPE value_sum;
            for (size_t i = 0; i < max_data_len; i++)
                value_sum += offset_selector.get_selector(i) * data[i];
            return value_sum;
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

        static node_inner_array* new_node_inner_array(context_type &context_object, mpt_type trie_type) {
            node_inner_array* n = new node_inner_array(context_object);
            std::vector<std::size_t> lengths;
            std::vector<bool> is_fixed;
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
            } else {
                throw "Unknown trie type!";
            }
            for (size_t i = 0; i < lengths.size(); i++)
                n->add_inner(lengths[i], is_fixed[i]);
            return n;
        }

        node_inner_array(
            context_type &context_object
        ):
            node_inner(
                context_object
            ), ct(context_object) {
            h = new node_header_array(context_object);
            this->header = h;
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
            std::cout << "array:\nquery val: " << get_query_value() << std::endl;
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

        TYPE set_query_data(std::size_t offset, std::size_t selector) {
            BOOST_ASSERT_MSG(selector < inners.size(), "Query selector is wrong!");
            selectors[selector] = 1;
            return inners[selector]->set_query_data(offset, 1);
        }

        TYPE get_query_value_len() {
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

        TYPE get_query_value() {
            TYPE sum = 0;
            for (size_t i = 0; i < selectors.size(); i++)
                sum += selectors[i] * inners[i]->get_query_value();
            return sum;
        }

        void query_constraints(TYPE query_offset, TYPE query_selector, TYPE node_selector) {
            for (auto &i : inners)
                i->query_constraints(query_offset, 1, node_selector);
            for (size_t i = 0; i < selectors.size(); i++) {
                constrain(selectors[i] * (1 - selectors[i]), "Query selector must be binary!");
                constrain(selectors[i] * (query_selector - i), "Query selector must be binary 2!");
            }
        }

        void add_inner(std::size_t length, bool is_fixed_length) {
            inners.push_back(new node_inner_string(
                ct,
                length,
                true,
                is_fixed_length
            ));
            selectors.resize(selectors.size() + 1);
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
            mpt_type _trie_type
        ): node_inner(
            context_object
            ), trie_type(_trie_type)
             {

            h = new node_header_string(context_object);
            this->header = h;
            if (_trie_type == mpt_type::storage_trie)
                inner = new node_inner_string(
                    context_object,
                    get_max_rlp_length(32),
                    true
                );
            else
                inner = node_inner_array::new_node_inner_array(context_object, _trie_type);

        }

        void set_rlc_challenge(TYPE _rlc_challenge) {
            inner->set_rlc_challenge(_rlc_challenge);
            node_inner::set_rlc_challenge(_rlc_challenge);
        }

        std::size_t extra_rows_count() {
            return 0;
        }

        void print() {
            std::cout << "container:\nquery val: " << inner->get_query_value() << std::endl;
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
            inner->get_query_value_len();
            return inner->get_query_value_len();
        }

        TYPE set_query_data(std::size_t query_offset, std::size_t query_selector) {
            return inner->set_query_data(query_offset, query_selector);
        }

        void query_constraints(TYPE query_offset, TYPE query_value, TYPE query_selector, TYPE query_value_len, TYPE node_selector) {
            this->inner->query_constraints(query_offset, query_selector, node_selector);

            constrain(inner->query_selector_is_found() - 1, "Query offset exceeded the max length!");
            constrain(inner->get_query_value() - query_value, "Query value is incorrect!");
            constrain(query_value_len - inner->get_query_value_len(), "Query value length is incorrect!");
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
