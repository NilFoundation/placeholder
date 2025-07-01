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
#include <nil/blueprint/zkevm_bbf/small_field/tables/keccak.hpp>
#include <nil/blueprint/zkevm_bbf/mpt_leaf/node_inner.hpp>
#include <nil/blueprint/zkevm_bbf/mpt_leaf/node_header.hpp>
#include <nil/blueprint/zkevm_bbf/mpt_leaf/leaf_node.hpp>


namespace nil::blueprint::bbf {

    struct leaf_node_data {
        std::vector<zkevm_word_type> original_key;
        std::array<std::vector<zkevm_word_type>, 2> data;
    };

    struct mpt_query {
        std::size_t offset;
        std::size_t selector;
        leaf_node_data node;
    };

    template<typename FieldType, GenerationStage stage>
    class mpt_leaf_node : public generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using RLPTable = typename bbf::rlp_table<FieldType, stage>;
        using KeccakTable = typename bbf::zkevm_small_field::keccak_table<FieldType, stage>;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

      public:
        using typename generic_component<FieldType, stage>::table_params;
        using typename generic_component<FieldType, stage>::TYPE;
        using node_inner_string = node_inner_string<FieldType, stage>;

        struct input_type {
            std::vector<mpt_query> queries;
            TYPE rlc_challenge;
        };

        // using input_type =
        //     typename std::conditional<stage == GenerationStage::ASSIGNMENT,
        //                                 _input_type, std::nullptr_t>::type;

        using value = typename FieldType::value_type;
        using integral_type = nil::crypto3::multiprecision::big_uint<257>;

        static table_params get_minimal_requirements(std::size_t max_mpt_query_size, mpt_type type) {
            std::size_t witnesses;
            if (type == mpt_type::account_trie)
                witnesses = 663; // must increase if single_byte_query
            else if (type == mpt_type::storage_trie)
                witnesses = 471; // must increase if single_byte_query
            else
                throw "Unsupported trie!";

            return {
                    .witnesses = witnesses, // change this to dynamic
                    .public_inputs = 0,
                    .constants = 0,
                    .rows = max_mpt_query_size * 3 // two for keccak and one for trie
                        + 1168 // rlp_table
                };
        }

        static void allocate_public_inputs(context_type &context, input_type &input,
                                           std::size_t max_mpt_query_size, mpt_type type) {}

        mpt_leaf_node(context_type &context_object, const input_type input,
            std::size_t max_mpt_query_size, mpt_type type)
            : generic_component<FieldType, stage>(context_object) {

            std::vector<std::size_t> keccak_lookup_area;
            std::vector<std::size_t> rlp_lookup_area;
            typename KeccakTable::private_input_type keccak_buffers;
            std::vector<leaf_node<FieldType, stage>*> nodes;
            std::size_t row_index = 0;

            for (size_t i = 0; i < max_mpt_query_size; i++) {
                query_type q = (type == mpt_type::account_trie || type == mpt_type::storage_trie) ? 
                                query_type::full_value_query : query_type::single_byte_query;
                leaf_node<FieldType, stage>* s = new leaf_node<FieldType, stage>(context_object, type, row_index, q);
                nodes.push_back(s);
                row_index += s->rows_count();
            }


            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                BOOST_ASSERT_MSG(input.queries.size() <= max_mpt_query_size, "number of queries exceeds!");
                for (size_t i = 0; i < max_mpt_query_size; i++) {
                    auto n = nodes[i];
                    n->initialize();
                    n->set_rlc_challenge(input.rlc_challenge);
                    if (i < input.queries.size()) {
                        leaf_node_data mn = input.queries[i].node;
                        std::size_t offset = input.queries[i].offset;
                        std::size_t selector = input.queries[i].selector;
                        std::vector<zkevm_word_type> key = mn.data[0];
                        std::vector<zkevm_word_type> value = mn.data[1];
                        n->set_data(key, value, mn.original_key, offset, selector);
                        BOOST_LOG_TRIVIAL(info) << n->print_table_entry();
                    } else {
                        n->set_empty_data();
                    }
                    for (auto &b : n->get_keccak_buffers())
                        keccak_buffers.new_buffer(b);
                    
                    BOOST_LOG_TRIVIAL(debug) << n->print();
                }
            }

            for( std::size_t i = 0; i < KeccakTable::get_witness_amount(); i++){
                keccak_lookup_area.push_back(i);
            }
            context_type keccak_ct = context_object.subcontext( keccak_lookup_area, max_mpt_query_size, max_mpt_query_size * 2);
            KeccakTable k_t = KeccakTable(keccak_ct, {input.rlc_challenge, keccak_buffers}, max_mpt_query_size * 2);

            for (std::size_t i = 0; i < RLPTable::get_witness_amount(); i++) {
                rlp_lookup_area.push_back(i);
            }
            context_type rlp_ct = context_object.subcontext(rlp_lookup_area, max_mpt_query_size * 3, 1168);
            RLPTable rlpt = RLPTable(rlp_ct);

            for (size_t i = 0; i < max_mpt_query_size; i++)
                nodes[i]->allocate_witness();

            std::vector<std::size_t> lookup_columns;
            size_t i = 0;
            for (; i < (type == mpt_type::storage_trie ? 32: 20); i++)
                lookup_columns.push_back(i); // original key
            lookup_columns.push_back(i++); // query_offset
            lookup_columns.push_back(i++); // query_value
            lookup_columns.push_back(i++); // query_selector
            lookup_columns.push_back(i++); // value total length
            lookup_columns.push_back(i++); // node exists
            lookup_table("mpt_leaf_table", lookup_columns, 0, max_mpt_query_size);

            for (size_t i = 0; i < max_mpt_query_size; i++)
                nodes[i]->constraints();
        }
    };
}  // namespace nil::blueprint::bbf
