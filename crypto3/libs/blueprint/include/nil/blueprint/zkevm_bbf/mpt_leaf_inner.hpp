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

        using node_header_string = node_header_string<FieldType, stage>;
        using node_header = node_header<FieldType, stage>;

        node_header_string header;
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
            data.resize(110);
            index.resize(110);
            is_last_I.resize(110);
            is_last_R.resize(110);
            is_last.resize(110);
            rlc.resize(110);
        }

        void initialize() {
            _initialize_header();
            _initialize_body();
        }

        void set_data(std::vector<zkevm_word_type> raw) {
            this->raw = raw;
            this->_set_data(raw);
            this->header.set_data_length(raw.size());
        }

        virtual std::size_t get_total_length() {
            throw "Method not implemented!";
        }

        void set_metadata(std::vector<std::uint8_t> &hash_input, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            this->_set_header_metadata(hash_input, rlp_encoding_index, rlc_accumulator);
            this->_set_metadata(hash_input, rlp_encoding_index, rlc_accumulator);
            this->_set_is_last();
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

        virtual void _initialize_body() {
            throw "Method not implemented!";
        }
        
        virtual void _set_data(std::vector<zkevm_word_type> _raw) {
            throw "Method not implemented!";
        }

        virtual void _set_metadata(std::vector<std::uint8_t> &hash_input, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            throw "Method not implemented!";
        }

        virtual void _set_header_metadata(std::vector<std::uint8_t> &hash_input, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            throw "Method not implemented!";
        }

        virtual void _set_is_last() {
            throw "Method not implemented!";
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
        using node_inner = node_inner<FieldType, stage>;

        std::vector<node_inner> inners;

        node_inner_array( 
            context_type &context_object,
            inner_node_type _n_type, 
            mpt_type _trie_type,
            TYPE _rlc_challenge):
            node_inner(context_object, _n_type, _trie_type, _rlc_challenge) {
            if (_trie_type == mpt_type::account_trie) {
                // TODO
                inners.push_back(node_inner(context_object, inner_node_type::nonce, _trie_type, this->rlc_challenge));
                inners.push_back(node_inner(context_object, inner_node_type::balance, _trie_type, this->rlc_challenge));
                inners.push_back(node_inner(context_object, inner_node_type::storage_root, _trie_type, this->rlc_challenge));
                inners.push_back(node_inner(context_object, inner_node_type::code_hash, _trie_type, this->rlc_challenge));
            }
        }
    
    protected:
        void _initialize_body() {
            for (auto &i : inners) {
                i.initialize();
            }
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

        node_inner_string( 
            context_type &context_object,
            inner_node_type _n_type, 
            mpt_type _trie_type,
            TYPE _rlc_challenge):
            node_inner(context_object, _n_type, _trie_type, _rlc_challenge) {
        }

    
    std::size_t get_total_length() {
        return this->header.get_total_length(this->raw[0]);
    }

    protected:
        void _initialize_body() {
            for (size_t j = 0; j < this->data.size(); j++) {
                this->data[j] = 0;
                this->index[j] = 0;
                this->is_last[j] = 1;
            }
        }

        void _set_data(std::vector<zkevm_word_type> _raw) {
            for (size_t j = 0; j < _raw.size(); j++) {
                this->data[j] = _raw[j];
                this->is_last[j] = 0;
            }
            if (_raw.size() > 0) {
                this->is_last[_raw.size() - 1] = 1;
            }
            if (_raw.size() == 1 && _raw[0] < 128) {
                this->first_element_flag = 1;
                this->first_element_image = _raw[0];
            }
            else {
                this->first_element_flag = 0;
                this->first_element_image = 0;
            }
        }

        void _set_header_metadata(std::vector<std::uint8_t> &hash_input, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            this->header.set_metadata(hash_input, rlp_encoding_index, rlc_accumulator, this->raw[0]);
        }

        void _set_metadata(std::vector<std::uint8_t> &hash_input, std::size_t &rlp_encoding_index, TYPE &rlc_accumulator) {
            for (size_t j = 0; j < this->header.raw_data_length; j++) {
                this->index[j] = rlp_encoding_index;
                hash_input[rlp_encoding_index++] = uint8_t(this->raw[j]);

                this->rlc[j] = rlc_accumulator * this->rlc_challenge + this->raw[j];
                rlc_accumulator = this->rlc[j];
            }
            for (size_t j = this->header.raw_data_length; j < this->rlc.size(); j++) {
                this->rlc[j] = rlc_accumulator;
            }
        }

        void _set_is_last() {
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                TYPE len = this->header.raw_data_length;
                for (size_t j = 0; j < this->data.size(); j++) {
                    if ( this->index[j] - this->index[0] == len - 1) {
                        this->is_last_I[j] = 0;
                    } else {
                        this->is_last_I[j] = 
                            (len - 1 - (this->index[j] - this->index[0])).inversed();
                    }
                    this->is_last_R[j] = 1 - 
                        (len - 1 - (this->index[j] - this->index[0])) 
                        * this->is_last_I[j];
                }
            }
        }
    };

}  // namespace nil::blueprint::bbf
