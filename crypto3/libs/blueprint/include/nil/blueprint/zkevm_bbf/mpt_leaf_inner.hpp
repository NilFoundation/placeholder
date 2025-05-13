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
#include <nil/blueprint/zkevm_bbf/mpt_leaf_header.hpp>

namespace nil::blueprint::bbf {


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

        using node_header = node_header<FieldType, stage>;

        node_header* header;
        inner_node_type node_type;
        mpt_type trie_type;
        std::vector<zkevm_word_type> raw;

        TYPE rlc_challenge;

        node_inner( 
            context_type &context_object,
            inner_node_type _n_type, 
            mpt_type _trie_type,
            TYPE _rlc_challenge
        ):
            generic_component<FieldType, stage>(context_object, false), 
            node_type(_n_type), 
            trie_type(_trie_type),
            rlc_challenge(_rlc_challenge) {
            
        }

        void initialize() {
            _initialize_header();
            _initialize_body();
        }

        void set_data(std::vector<zkevm_word_type> _raw) {
            this->raw = _raw;
            _set_data();
            header->set_data_length(get_data_length());
        }

        void set_metadata(std::vector<std::uint8_t> &hash_input, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            this->_set_header_metadata(hash_input, rlp_encoding_index, rlc_accumulator);
            this->_set_metadata(hash_input, rlp_encoding_index, rlc_accumulator);
            this->_set_data_finished();
        }

        virtual void allocate_witness(std::size_t &column_index, std::size_t &row_index){
            throw "Method not implemented!";
        }

        void main_constraints(TYPE previous_rlc, TYPE initial_index, TYPE not_padding) {
            header->main_constraints(previous_rlc, initial_index, not_padding);
            this->_main_constraints(previous_rlc, initial_index, not_padding);
        }

        virtual std::size_t get_total_length() {
            throw "Method not implemented!";
        }

        virtual std::size_t get_data_length() {
            throw "Method not implemented!";
        }

        virtual void print() {
            throw "Method not implemented!";
        }

        virtual void rlp_lookup_constraints() {
            throw "Method not implemented!";
        }

        virtual TYPE last_rlc() {
            throw "Method not implemented!";
        }

        TYPE get_total_length_constraint() {
            return header->get_total_length_constraint();
        }

        protected:
        void _initialize_header() {
            header->initialize();
        }

        virtual void _initialize_body() {
            throw "Method not implemented!";
        }
        
        virtual void _set_data() {
            throw "Method not implemented!";
        }

        virtual void _set_metadata(std::vector<std::uint8_t> &hash_input, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            throw "Method not implemented!";
        }

        virtual void _set_header_metadata(std::vector<std::uint8_t> &hash_input, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            throw "Method not implemented!";
        }

        virtual void _set_data_finished() {
            throw "Method not implemented!";
        }

        // virtual void _allocate_witness(std::size_t &column_index, std::size_t &row_index){
        //     throw "Method not implemented! 16";
        // }

        virtual void _main_constraints(TYPE previous_rlc, TYPE initial_index, TYPE not_padding) {
            throw "Method not implemented!";
        }
    };
    
    

    template<typename FieldType, GenerationStage stage>
    class node_inner_string: public node_inner<FieldType, stage> {
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

        node_inner_string( 
            context_type &context_object,
            inner_node_type _n_type, 
            mpt_type _trie_type,
            TYPE _rlc_challenge
        ): node_inner(
            context_object, 
            _n_type, 
            _trie_type, 
            _rlc_challenge
        ) {

            node_header_string* h = new node_header_string(
                context_object,
                _n_type,
                _rlc_challenge
            );
            this->header = h;
            data.resize(110);
            index.resize(110);
            remainder_I.resize(110);
            is_last_byte.resize(110);
            data_finished.resize(110);
            rlc.resize(110);
        }

    
    std::size_t get_data_length() {
        return this->raw.size();
    }

    std::size_t get_total_length() {
        return _get_header()->get_total_length(this->raw[0]);
    }

    void print() {
        for (size_t i = 0; i < this->raw.size(); i++) {
            std::cout << "\t"
                << std::hex << this->data[i] << std::dec << "\t" 
                << std::hex << this->index[i] << std::dec << std::endl;
        }
    }

    void rlp_lookup_constraints() {
        _get_header()->rlp_lookup_constraints(first_element_image, data[0], first_element_flag);
    }

    TYPE last_rlc() {
        return rlc[rlc.size() - 1];
    }


    void allocate_witness(std::size_t &column_index, std::size_t &row_index){
        this->header->allocate_witness(column_index, row_index);
        allocate(first_element_image, column_index++, row_index);
        allocate(first_element_flag, column_index++, row_index);
        for (std::size_t k = 0; k < data.size(); k++) {
            allocate(data[k], column_index++, row_index);
            allocate(rlc[k], column_index++, row_index);
            allocate(data_finished[k], column_index++, row_index);
            allocate(index[k], column_index++, row_index);
            allocate(remainder_I[k], column_index++, row_index);
            allocate(is_last_byte[k], column_index++, row_index);
        }
    }

    protected:
        void _initialize_body() {
            for (size_t j = 0; j < data.size(); j++) {
                data[j] = 0;
                index[j] = 0;
                data_finished[j] = 1;
            }
        }

        void _set_data() {
            for (size_t j = 0; j < this->raw.size(); j++) {
                data[j] = this->raw[j];
                data_finished[j] = 0;
            }
            if (this->raw.size() > 0) {
                data_finished[this->raw.size() - 1] = 1;
            }
            if (this->raw.size() == 1 && this->raw[0] < 128) {
                first_element_flag = 1;
                first_element_image = this->raw[0];
            }
            else {
                first_element_flag = 0;
                first_element_image = 0;
            }
        }

        void _set_header_metadata(std::vector<std::uint8_t> &hash_input, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            _get_header()->set_metadata(hash_input, rlp_encoding_index, rlc_accumulator, this->raw[0]);
        }

        void _set_metadata(std::vector<std::uint8_t> &hash_input, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            for (size_t j = 0; j < this->header->raw_data_length; j++) {
                index[j] = rlp_encoding_index;
                hash_input[rlp_encoding_index++] = uint8_t(this->raw[j]);

                rlc[j] = rlc_accumulator * this->rlc_challenge + this->raw[j];
                rlc_accumulator = rlc[j];
            }
            for (size_t j = this->header->raw_data_length; j < rlc.size(); j++) {
                rlc[j] = rlc_accumulator;
            }
        }

        void _set_data_finished() {
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                TYPE len = this->header->raw_data_length;
                for (size_t j = 0; j < data.size(); j++) {
                    if ( index[j] - index[0] == len - 1) {
                        remainder_I[j] = 0;
                    } else {
                        remainder_I[j] = 
                            (len - 1 - (index[j] - index[0])).inversed();
                    }
                    this->is_last_byte[j] = 1 - 
                        (len - 1 - (index[j] - index[0])) 
                        * remainder_I[j];
                }
            }
        }


        void _is_zero_constraints(TYPE is_zero, TYPE inverse, TYPE X) {
            constrain(is_zero - (1 - X * inverse));
            constrain(X * is_zero);
        }

        void _main_constraints(TYPE previous_rlc, TYPE initial_index, TYPE not_padding) {
            TYPE first_data_index = initial_index + this->header->get_prefix_length();

            _is_zero_constraints(this->header->len_is_zero, this->header->len_I, this->header->len);
            _is_zero_constraints(this->header->len_is_one, this->header->len_minus_one_I, this->header->len - 1);

            constrain((1 - data_finished[0]) * data_finished[0]);
            constrain((this->header->len_is_zero + this->header->len_is_one) * (1 - this->data_finished[0]));
            constrain(this->header->len_is_zero * index[0] + 
                (1 - this->header->len_is_zero) * (index[0] - first_data_index));
            constrain(this->header->len_is_zero * data[0]);
            constrain(this->header->len_is_zero * (rlc[0] - this->header->prefix_rlc[2]) + 
                (1 - this->header->len_is_zero) * (rlc[0] - (this->header->prefix_rlc[2] * 53 + data[0])));
            
            for (size_t i = 1; i < data.size(); i++) {
                constrain((1 - data_finished[i]) * data_finished[i]);
                constrain((1 - data_finished[i]) * data_finished[i-1]);
                constrain(data_finished[i-1] * index[i] +
                    (1 - data_finished[i-1]) * (index[i] - index[i-1] - 1));

                TYPE remainder = this->header->len - (index[i] - index[0] + 1);
                _is_zero_constraints(is_last_byte[i], remainder_I[i], remainder);

                constrain(data_finished[i] - is_last_byte[i] - data_finished[i-1]);
                constrain(data[i] * data_finished[i-1]);
                constrain(rlc[i] - (data_finished[i-1] * rlc[i-1] + (1 - data_finished[i-1]) * (rlc[i-1] * 53 + data[i])));
            }
            constrain(data_finished[data.size() - 1] - 1);
        }

        node_header_string* _get_header() {
            return dynamic_cast<node_header_string*>(this->header);
        }
    };


    template<typename FieldType, GenerationStage stage>
    class node_inner_array: public node_inner<FieldType, stage> {
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

        using node_header_string = node_header_string<FieldType, stage>;
        using node_header_array = node_header_array<FieldType, stage>;
        using node_inner = node_inner<FieldType, stage>;
        using node_inner_string = node_inner_string<FieldType, stage>;

        node_inner_array( 
            context_type &context_object,
            mpt_type _trie_type,
            TYPE _rlc_challenge
        ):
            node_inner(
                context_object, 
                inner_node_type::array, 
                _trie_type, 
                _rlc_challenge
            ){


                node_header_array* h = new node_header_array(
                    context_object,
                    _rlc_challenge
                );
                this->header = h;

            // if (_trie_type == mpt_type::account_trie) {
            //     // TODO
            //     inners.push_back(node_inner(context_object, inner_node_type::nonce, _trie_type, this->rlc_challenge));
            //     inners.push_back(node_inner(context_object, inner_node_type::balance, _trie_type, this->rlc_challenge));
            //     inners.push_back(node_inner(context_object, inner_node_type::storage_root, _trie_type, this->rlc_challenge));
            //     inners.push_back(node_inner(context_object, inner_node_type::code_hash, _trie_type, this->rlc_challenge));
            // }
        }

        void add_inner(context_type &__c, inner_node_type __n) {
            node_inner_string* n = new node_inner_string(__c, __n, this->trie_type, this->rlc_challenge);
            inners.push_back(n);
        }

        TYPE last_rlc() {
            return inners[inners.size()-1]->last_rlc();
        }

        std::size_t get_total_length() {
            return _get_header()->get_total_length();
        }
    
        std::vector<node_inner*> inners;

        void allocate_witness(std::size_t &column_index, std::size_t &row_index) {
            this->header->allocate_witness(column_index, row_index);
            for (size_t i = 0; i < inners.size(); i++) {
                inners[i]->allocate_witness(column_index, row_index);
            }
        }
    protected:
        void _initialize_body() {
            for (auto &i : inners) {
                i->initialize();
            }
        }
    
        std::size_t get_data_length() {
            std::size_t internals_length = 0;
            for (size_t i = 0; i < this->inners.size(); i++)
                internals_length += inners[i]->get_total_length();
            return internals_length;
        }

        void rlp_lookup_constraints() {
            _get_header()->rlp_lookup_constraints();
            for (size_t i = 0; i < this->inners.size(); i++){
                this->inners[i]->rlp_lookup_constraints();
            }
        }

        void _main_constraints(TYPE previous_rlc, TYPE initial_index, TYPE not_padding) {
            // TODO is there any better way?
            if (inners.size() == 2) {
                constrain(this->header->len - 
                    (inners[0]->get_total_length_constraint() 
                    + inners[1]->get_total_length_constraint()));
            }
            this->header->main_constraints(previous_rlc, initial_index, not_padding);
            
            TYPE next_index;
            for (size_t i = 0; i < 2; i++) {
                if (i == 0) {
                    previous_rlc = this->header->prefix_rlc[2];
                    next_index = this->header->get_prefix_length() + initial_index;
                } else {
                    next_index = next_index + this->inners[i-1]->get_total_length_constraint();
                    previous_rlc = this->inners[i-1]->last_rlc();
                }
                this->inners[i]->main_constraints(previous_rlc, next_index, not_padding);
            }
        }

        void _set_metadata(std::vector<std::uint8_t> &hash_input, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            _get_header()->set_metadata(hash_input, rlp_encoding_index, rlc_accumulator);
            for (size_t i = 0; i < inners.size(); i++)
                inners[i]->set_metadata(hash_input, rlp_encoding_index, rlc_accumulator);
        }

        node_header_array* _get_header() {
            return dynamic_cast<node_header_array*>(this->header);
        }
    };
}  // namespace nil::blueprint::bbf
