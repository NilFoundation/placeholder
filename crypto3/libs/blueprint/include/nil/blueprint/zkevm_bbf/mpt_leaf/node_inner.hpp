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
#include <nil/blueprint/zkevm_bbf/mpt_leaf/node_header.hpp>

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
        // inner_node_type node_type;
        // mpt_type trie_type;

        TYPE rlc_challenge;

        node_inner(
            context_type &context_object,
            // inner_node_type _n_type,
            // mpt_type _trie_type,
            TYPE _rlc_challenge,
            bool _have_query_constraint = false
        ):
            generic_component<FieldType, stage>(context_object, false),
            // node_type(_n_type),
            // trie_type(_trie_type),
            rlc_challenge(_rlc_challenge),
            have_query_constraint(_have_query_constraint) {

        }

        void initialize() {
            _initialize_header();
            _initialize_body();
        }

        void main_constraints(TYPE previous_rlc, TYPE initial_index) {
            header->main_constraints(previous_rlc, initial_index);
            this->_main_constraints(initial_index);
        }

        // virtual void query_constraints() {
        //     throw "Method not implemented!";
        // }

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

        virtual void print() {
            throw "Method not implemented!";
        }

        virtual TYPE set_query_data(std::size_t offset) {
            throw "Method not implemented!";
        }

        virtual void rlp_lookup_constraints() {
            throw "Method not implemented!";
        }

        virtual TYPE last_rlc() {
            throw "Method not implemented!";
        }

        protected:
        void _initialize_header() {
            header->initialize();
        }

        virtual void _initialize_body() {
            throw "Method not implemented!";
        }

        virtual void _main_constraints(TYPE initial_index) {
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


        std::vector<TYPE> data;
        std::vector<TYPE> index;
        std::vector<TYPE> remainder_I;
        std::vector<TYPE> is_last_byte;
        std::vector<TYPE> data_finished;
        std::vector<TYPE> rlc;
        TYPE first_element_image;
        TYPE first_element_flag;
        // TYPE query_offset;
        TYPE query_value;
        TYPE query_found;
        // TYPE query_selector;
        std::vector<TYPE> is_offset_byte;
        std::vector<TYPE> offset_reminder_I;
        std::size_t max_data_len;

        node_inner_string(
            context_type &context_object,
            // inner_node_type _n_type,
            // mpt_type _trie_type,
            TYPE _rlc_challenge,
            std::size_t _max_data_length,
            bool _have_query_constraints = false
        ): node_inner(
            context_object,
            // _n_type,
            // _trie_type,
            _rlc_challenge,
            _have_query_constraints
        ), max_data_len(_max_data_length) {
            h = new node_header_string(context_object, _rlc_challenge);
            this->header = h;

            data.resize(max_data_len);
            index.resize(max_data_len);
            remainder_I.resize(max_data_len);
            is_last_byte.resize(max_data_len);
            is_offset_byte.resize(max_data_len);
            offset_reminder_I.resize(max_data_len);
            data_finished.resize(max_data_len);
            rlc.resize(max_data_len);
        }

        std::size_t extra_rows_count() {
            return 0;
        }

        void print() {
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                h->print();
                auto raw_data_length = static_cast<std::uint64_t>(h->len.data.base());
                std::cout << "\tquery_value: " << query_value << std::endl;
                std::cout << "\tdata\tindex\tis_offset" << std::endl;
                for (size_t i = 0; i < raw_data_length; i++) {
                    std::cout << "\t"
                        << std::hex << this->data[i] << std::dec << "\t"
                        << std::hex << this->index[i] << std::dec <<"\t"
                        << std::hex << this->is_offset_byte[i] << std::dec <<"\t"
                        // << std::hex << this->offset_reminder_I[i] << std::dec << "\t"
                         << std::endl;
                }
            }
        }

        TYPE last_rlc() {
            return rlc[rlc.size() - 1];
        }

        void allocate_witness(std::size_t &column_index, std::size_t &row_index){
            h->allocate_witness(column_index, row_index);
            allocate(first_element_image, column_index++, row_index);
            allocate(first_element_flag, column_index++, row_index);
            if (this->have_query_constraint) {
                // allocate(query_offset, column_index++, row_index);
                allocate(query_value, column_index++, row_index);
                allocate(query_found, column_index++, row_index);
                // allocate(node_query_selector, column_index++, row_index);
            }
            for (std::size_t k = 0; k < data.size(); k++) {
                allocate(data[k], column_index++, row_index);
                allocate(rlc[k], column_index++, row_index);
                allocate(data_finished[k], column_index++, row_index);
                allocate(index[k], column_index++, row_index);
                allocate(remainder_I[k], column_index++, row_index);
                allocate(is_last_byte[k], column_index++, row_index);
                if (this->have_query_constraint) {
                    allocate(is_offset_byte[k], column_index++, row_index);
                    allocate(offset_reminder_I[k], column_index++, row_index);
                }
            }
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

        TYPE set_query_data(std::size_t offset) {
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                // BOOST_ASSERT_MSG(offset < max_data_len, "Query offset exceeded the data size!");
                auto raw_data_length = static_cast<std::uint64_t>(h->len.data.base());
                if (offset >= max_data_len) {
                    query_value = 0;
                    query_found = 0;
                }
                else {
                    query_value = data[offset];
                    query_found = 1;
                }
                
                for (size_t i = 0; i < max_data_len; i++) {
                    if (offset == i) {
                        is_offset_byte[i] = 1;
                        offset_reminder_I[i] = 0;
                    } else {
                        is_offset_byte[i] = 0;
                        offset_reminder_I[i] = (TYPE(offset) - i).inversed();
                    }
                }
            }
            return query_value;
        }

        void query_constraints(TYPE query_offset, TYPE node_selector) {
            TYPE value_sum;
            TYPE is_offset_sum;
            for (size_t i = 0; i < max_data_len; i++) {
                value_sum += is_offset_byte[i] * data[i];
                _constrain_is_zero(is_offset_byte[i], offset_reminder_I[i], query_offset - i, node_selector);
                is_offset_sum += is_offset_byte[i];
            }

            constrain(query_value - value_sum, "query_value is wrong!");
            constrain(query_found - is_offset_sum, "query_found is wrong!"); // if zero the query offset is more than max length!
        }

        std::vector<zkevm_word_type> empty() {
            return {};
        }

    protected:
        node_header_string* h;

        void _initialize_body() {
            for (size_t j = 0; j < data.size(); j++) {
                data[j] = 0;
                index[j] = 0;
                data_finished[j] = 1;
            }
        }

        void _peek_and_set_data(std::vector<zkevm_word_type> &raw, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            this->_peek_data(raw, rlp_encoding_index, rlc_accumulator);
            this->_set_index_and_rlc(rlp_encoding_index, rlc_accumulator);
            this->_set_data_finished();
        }

        void _peek_data(std::vector<zkevm_word_type> &raw, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                auto raw_data_length = static_cast<std::uint64_t>(this->header->len.data.base());
                BOOST_ASSERT_MSG(raw.size() >= raw_data_length, "Error in RLP decoding3!");

                for (size_t j = 0; j < raw_data_length; j++) {
                    data[j] = raw[0];
                    data_finished[j] = 0;
                    raw.erase(raw.begin());
                }
                if (raw_data_length != 0) {
                    data_finished[raw_data_length - 1] = 1;
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

        void _set_data_finished() {
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                TYPE len = h->len;
                for (size_t j = 0; j < data.size(); j++) {
                    if ( index[j] - index[0] == len - 1) {
                        remainder_I[j] = 0;
                        is_last_byte[j] = 1;
                    } else {
                        remainder_I[j] = (len - 1 - (index[j] - index[0])).inversed();
                        is_last_byte[j] = 0;
                    }
                }
            }
        }

        void _set_index_and_rlc(std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                auto raw_data_length = static_cast<std::uint64_t>(h->len.data.base());
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

        void _main_constraints(TYPE initial_index) {
            TYPE first_data_index = initial_index + this->header->get_prefix_length();

            _constrain_is_zero(h->len_is_zero, h->len_I, h->len);
            _constrain_is_zero(h->len_is_one, h->len_minus_one_I, h->len - 1);

            constrain((1 - data_finished[0]) * data_finished[0]);
            constrain((h->len_is_zero + h->len_is_one) * (1 - this->data_finished[0]));
            constrain(h->len_is_zero * index[0] +
                (1 - h->len_is_zero) * (index[0] - first_data_index));
            constrain(h->len_is_zero * data[0]);
            constrain(h->len_is_zero * (rlc[0] - h->prefix_rlc[2]) +
                (1 - h->len_is_zero) * (rlc[0] - (h->prefix_rlc[2] * 53 + data[0])));

            for (size_t i = 1; i < data.size(); i++) {
                constrain((1 - data_finished[i]) * data_finished[i]);
                constrain((1 - data_finished[i]) * data_finished[i-1]);
                constrain(data_finished[i-1] * index[i] +
                    (1 - data_finished[i-1]) * (index[i] - index[i-1] - 1));

                TYPE remainder = h->len - (index[i] - index[0] + 1);
                _constrain_is_zero(is_last_byte[i], remainder_I[i], remainder);

                constrain(data_finished[i] - is_last_byte[i] - data_finished[i-1]);
                constrain(data[i] * data_finished[i-1]);
                constrain(rlc[i] - (data_finished[i-1] * rlc[i-1] + (1 - data_finished[i-1]) * (rlc[i-1] * 53 + data[i])));
            }
            constrain(data_finished[data.size() - 1] - 1);
            // if (this->have_query_constraint)
                // query_constraints();
        }
    };


    template<typename FieldType, GenerationStage stage>
    class node_inner_string_container: public node_inner<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;

    public:
        using typename generic_component<FieldType, stage>::TYPE;
        using node_inner = node_inner<FieldType, stage>;
        using node_inner_string = node_inner_string<FieldType, stage>;
        using node_header_string = node_header_string<FieldType, stage>;

        node_inner_string* inner;
        
        TYPE first_element_flag;
        TYPE first_element_image;
        TYPE query_value;
        // TYPE query_selector;
        // TYPE query_offset;
        node_header_string* h;

        node_inner_string_container(
            context_type &context_object,
            // inner_node_type _n_type,
            // mpt_type _trie_type,
            TYPE _rlc_challenge,
            std::size_t _max_data_len
            // node_inner_string_decoder* _inner
        ): node_inner(
            context_object,
            // _n_type,
            // _trie_type,
            _rlc_challenge
            ) {

            h = new node_header_string(context_object, _rlc_challenge);
            this->header = h;
            inner = new node_inner_string(
                context_object,
                // _trie_type,
                _rlc_challenge,
                get_max_rlp_length(_max_data_len),
                true
            );
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
            allocate(query_value, column_index++, row_index);
            this->inner->allocate_witness(column_index, row_index);
        }

        void rlp_lookup_constraints() {
            this->h->rlp_lookup_constraints(
                first_element_image,
                this->inner->header->prefix_exists[0] * this->inner->header->prefix[0] + (1 - this->inner->header->prefix_exists[0]) * this->inner->data[0],
                first_element_flag);
            this->inner->rlp_lookup_constraints();
        }

        void peek_and_encode_data(std::vector<zkevm_word_type> &raw, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            h->peek_and_encode_data(raw, rlp_encoding_index, rlc_accumulator, false);
            inner->peek_and_decode_data(raw, rlp_encoding_index, rlc_accumulator);
            if (inner->header->get_total_length() == 1) {
                first_element_flag = 1;
                first_element_image = inner->header->prefix_exists[0] * inner->header->prefix[0]
                                      + (1 - inner->header->prefix_exists[0]) * inner->data[0];
            } else {
                first_element_flag = 0;
                first_element_image = 0;
            }
        }

        TYPE set_query_data(std::size_t query_offset, std::size_t query_selector) {
            // TODO these are useful in array_container
            return inner->set_query_data(query_offset);
        }
        
        std::vector<zkevm_word_type> empty() {
            return {0x80};
        }

        void query_constraints(TYPE query_offset, TYPE query_value, TYPE query_selector) {
            // The two following must be changed for array container
            constrain(query_selector - 1, "Queries to storage trie must always have selector=1");
            constrain(query_selector * inner->query_found * inner->query_value - query_value, "Query value is incorrect!");
            constrain(inner->query_found - 1, "Query offset exceeded the max length!");
            this->inner->query_constraints(query_offset, query_selector);
        }

    protected:
        void _initialize_body() {
            this->inner->initialize();
        }

        void _main_constraints(TYPE initial_index) {
            TYPE first_data_index = initial_index + this->header->get_prefix_length();
            this->inner->main_constraints(this->header->prefix_rlc[2], first_data_index);
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

        std::vector<node_inner*> inners;

        node_inner_array(
            context_type &context_object,
            // mpt_type _trie_type,
            TYPE _rlc_challenge
        ):
            node_inner(
                context_object,
                // inner_node_type::array,
                // _trie_type,
                _rlc_challenge
            ) {
            h = new node_header_array(context_object, _rlc_challenge); 
            this->header = h;
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

        void allocate_witness(std::size_t &column_index, std::size_t &row_index) {
            h->allocate_witness(column_index, row_index);
            for (size_t i = 0; i < inners.size(); i++) {
                inners[i]->allocate_witness(column_index, row_index);
            }
        }
        
        std::vector<zkevm_word_type> empty() {
            return {0xC0};
        }

    protected:
        node_header_array* h;

        void _initialize_body() {
            for (auto &i : inners) {
                i->initialize();
            }
        }

        void _main_constraints(TYPE initial_index) {
            TYPE total_len;
            for (auto &i : inners)
                total_len += i->get_total_length_constraint();
            constrain(this->header->len - total_len);

            TYPE next_index, previous_rlc;
            for (size_t i = 0; i < this->inners.size(); i++) {
                if (i == 0) {
                    previous_rlc = this->header->prefix_rlc[2];
                    next_index = this->header->get_prefix_length() + initial_index;
                } else {
                    next_index = next_index + this->inners[i-1]->get_total_length_constraint();
                    previous_rlc = this->inners[i-1]->last_rlc();
                }
                this->inners[i]->main_constraints(previous_rlc, next_index);
                // this->inners[i]->query_constraints();
            }
        }

        void rlp_lookup_constraints() {
            h->rlp_lookup_constraints();
            for (size_t i = 0; i < this->inners.size(); i++){
                this->inners[i]->rlp_lookup_constraints();
            }
        }
    };
}  // namespace nil::blueprint::bbf
