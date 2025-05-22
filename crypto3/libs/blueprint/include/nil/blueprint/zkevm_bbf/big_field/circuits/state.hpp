//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/bench/scoped_profiler.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/subcomponents/state_table.hpp>

namespace nil::blueprint::bbf::zkevm_big_field{
    template<typename FieldType, GenerationStage stage>
    class state_transition : public generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

    public:
        using typename generic_component<FieldType, stage>::table_params;
        using typename generic_component<FieldType,stage>::TYPE;

        using state_table_type = state_table<FieldType, stage>;
        using value = typename FieldType::value_type;
        using integral_type = nil::crypto3::multiprecision::big_uint<257>;

        struct input_type{
            typename state_table_type::input_type state_trace;
            typename std::conditional<stage==GenerationStage::ASSIGNMENT, std::map<std::size_t, zkevm_call_state_data>, std::nullptr_t>::type call_state_data;
        };

        static constexpr std::size_t diff_index_selectors_amount = 32;
        static constexpr std::size_t chunks_amount = 30;
        static constexpr std::size_t helpers_amount = 23;
        static constexpr std::size_t op_selectors_amount = state_operation_types_amount - 1;

        static table_params get_minimal_requirements(
            std::size_t max_state
        ) {
            std::size_t witnesses = state_table_type::get_witness_amount()
                + helpers_amount
                + op_selectors_amount
                + chunks_amount
                + diff_index_selectors_amount;
            BOOST_LOG_TRIVIAL(info) << "State circuit witness amount = " << witnesses;
            return {
                .witnesses = witnesses,
                .public_inputs = 0,
                .constants = 0,
                .rows = max_state
            };
        }

        static void allocate_public_inputs(
            context_type &context,
            input_type &input,
            std::size_t max_state
        ) {}

        template<std::size_t n>
        TYPE bit_tag_selector(std::array<TYPE, n> bits, std::size_t k){
            TYPE result;
            integral_type mask = (1 << n);
            for( std::size_t bit_ind = 0; bit_ind < n; bit_ind++ ){
                mask >>= 1;
                TYPE bit_selector;
                if( (mask & k) == 0)
                    bit_selector = (1 - bits[bit_ind]);
                else
                    bit_selector = bits[bit_ind];
                if( bit_ind == 0)
                    result = bit_selector;
                else
                    result *= bit_selector;
            }
            return result;
        }

        state_transition(context_type &context_object,
            const input_type &input,
            std::size_t max_state
        ) :generic_component<FieldType,stage>(context_object) {
            BOOST_LOG_TRIVIAL(info) << "STATE  transition circuit";
            std::size_t START_OP = std::size_t(rw_operation_type::start);
            std::size_t ACCESS_LIST_OP = std::size_t(rw_operation_type::access_list);
            std::size_t STATE_OP = std::size_t(rw_operation_type::state);
            std::size_t TRANSIENT_STORAGE_OP = std::size_t(rw_operation_type::transient_storage);
            std::size_t CALL_CONTEXT_OP = std::size_t(rw_operation_type::state_call_context);
            std::size_t PADDING_OP = std::size_t(rw_operation_type::padding);

            std::vector<std::size_t> table_subcomponent_area;

            for( std::size_t i = 0; i < state_table_type::get_witness_amount(); i++ ) table_subcomponent_area.push_back(i);
            context_type state_table_ct = context_object.subcontext(table_subcomponent_area,0,max_state);
            state_table_type t(state_table_ct, input.state_trace, max_state);

            std::vector<std::size_t> state_table_area;
            state_table_area.push_back(table_subcomponent_area[0]); // is_original
            state_table_area.push_back(table_subcomponent_area[1]); // op
            state_table_area.push_back(table_subcomponent_area[2]); // id
            state_table_area.push_back(table_subcomponent_area[3]); // address
            state_table_area.push_back(table_subcomponent_area[4]); // field_type
            state_table_area.push_back(table_subcomponent_area[5]); // storage_key_hi
            state_table_area.push_back(table_subcomponent_area[6]); // storage_key_lo
            state_table_area.push_back(table_subcomponent_area[7]); // rw_id
            state_table_area.push_back(table_subcomponent_area[8]); // is_write
            state_table_area.push_back(table_subcomponent_area[9]); // value_hi
            state_table_area.push_back(table_subcomponent_area[10]); // value_lo
            state_table_area.push_back(table_subcomponent_area[11]); // previous_value_hi
            state_table_area.push_back(table_subcomponent_area[12]); // previous_value_lo
            state_table_area.push_back(state_table_type::get_witness_amount()); // call_id
            lookup_table("zkevm_state",state_table_area, 0, max_state);

            std::vector<std::size_t> parent_table_area;
            parent_table_area.push_back(table_subcomponent_area[1]); // op
            parent_table_area.push_back(table_subcomponent_area[2]); // id
            parent_table_area.push_back(table_subcomponent_area[3]); // address
            parent_table_area.push_back(table_subcomponent_area[4]); // field_type
            parent_table_area.push_back(table_subcomponent_area[5]); // storage_key_hi
            parent_table_area.push_back(table_subcomponent_area[6]); // storage_key_lo
            parent_table_area.push_back(table_subcomponent_area[7]); // rw_id
            parent_table_area.push_back(state_table_type::get_witness_amount()+1); // parent_id
            parent_table_area.push_back(state_table_type::get_witness_amount()+2); // update_parent_selector
            lookup_table("zkevm_state_parent",parent_table_area, 0, max_state);

            const std::vector<TYPE> &op = t.op;
            const std::vector<TYPE> &id = t.id;
            const std::vector<TYPE> &address = t.address;
            const std::vector<TYPE> &field_type = t.field_type;
            const std::vector<TYPE> &storage_key_hi = t.storage_key_hi;
            const std::vector<TYPE> &storage_key_lo = t.storage_key_lo;
            const std::vector<TYPE> &rw_id = t.rw_id;
            const std::vector<TYPE> &is_write = t.is_write;
            const std::vector<TYPE> &value_hi = t.value_hi;
            const std::vector<TYPE> &value_lo = t.value_lo;
            const std::vector<TYPE> &previous_value_hi = t.previous_value_hi;
            const std::vector<TYPE> &previous_value_lo = t.previous_value_lo;
            const std::vector<TYPE> &initial_value_hi = t.initial_value_hi;
            const std::vector<TYPE> &initial_value_lo = t.initial_value_lo;
            const std::vector<TYPE> &is_original = t.is_original;
            const std::vector<TYPE> &internal_counter = t.internal_counter;

            std::vector<std::array<TYPE, op_selectors_amount>> op_selectors(max_state);
            std::vector<std::array<TYPE, diff_index_selectors_amount>> diff_index_selectors(max_state);
            std::vector<std::array<TYPE, chunks_amount>> chunks(max_state);

            std::vector<TYPE> call_id(max_state);
            std::vector<TYPE> parent_id(max_state);             // 0 for block
            std::vector<TYPE> update_parent_selector(max_state);
            std::vector<TYPE> reverted_is_last_selector(max_state);

            std::vector<TYPE> diff(max_state);
            std::vector<TYPE> diff_inv(max_state);
            std::vector<TYPE> is_diff_non_zero(max_state);
            std::vector<TYPE> is_last(max_state);
            std::vector<TYPE> is_first(max_state);
            std::vector<TYPE> not_is_first_and_read(max_state);
            std::vector<TYPE> is_first_and_read(max_state);
            std::vector<TYPE> parent_id_inv(max_state);
            std::vector<TYPE> is_not_block(max_state);
            std::vector<TYPE> grandparent_id(max_state);        // 0 for block and for transaction
            std::vector<TYPE> grandparent_id_inv(max_state);
            std::vector<TYPE> is_not_block_and_not_transaction(max_state);
            std::vector<TYPE> last_in_call_selector(max_state);
            std::vector<TYPE> call_initial_value_hi(max_state);
            std::vector<TYPE> call_initial_value_lo(max_state);
            std::vector<TYPE> counter(max_state);
            std::vector<TYPE> modified_items(max_state);
            std::vector<TYPE> is_reverted(max_state);
            std::vector<TYPE> last_in_reverted_call_selector(max_state);

            std::map<rw_operation_type, std::size_t> op_selector_indices;
            std::size_t index = 0;
            op_selector_indices[rw_operation_type::state_call_context] = index++;
            op_selector_indices[rw_operation_type::access_list] = index++;
            op_selector_indices[rw_operation_type::state] = index++;
            op_selector_indices[rw_operation_type::transient_storage] = index++;
            op_selector_indices[rw_operation_type::padding] = index++;

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                auto &state_trace = input.state_trace;
                auto &call_state_data = input.call_state_data;

                BOOST_LOG_TRIVIAL(trace) << "State trace.size = " << state_trace.size() << std::endl;
                std::vector<TYPE> sorted;
                std::vector<TYPE> sorted_prev;
                for( std::size_t i = 0; i < state_trace.size(); i++ ){
                    BOOST_LOG_TRIVIAL(debug) << i << ". " << state_trace[i];
                    if( i != 0 ) op_selectors[i][op_selector_indices[state_trace[i].op]] = 1;

                    std::size_t cur_chunk = 0;
                    // id
                    zkevm_word_type mask = 0xffff0000;
                    chunks[i][cur_chunk++] = (mask & integral_type(state_trace[i].id)) >> 16;
                    mask = 0xffff;
                    chunks[i][cur_chunk++] = (mask & integral_type(state_trace[i].id));

                    // address
                    mask = 0xffff;
                    mask <<= (16 * 9);
                    for( std::size_t j = 0; j < 10; j++){
                        chunks[i][cur_chunk++] = (((mask & integral_type(state_trace[i].address)) >> (16 * (9-j))));
                        mask >>= 16;
                    }

                    // storage_key
                    mask = 0xffff;
                    mask <<= (16 * 15);
                    for( std::size_t j = 0; j < 16; j++){
                        chunks[i][cur_chunk++] = (((mask & integral_type(state_trace[i].storage_key)) >> (16 * (15-j))));
                        mask >>= 16;
                    }

                    // rw_id
                    mask = 0xffff;
                    mask <<= 16;
                    chunks[i][cur_chunk++] = (mask & state_trace[i].rw_counter) >> 16;
                    mask >>= 16;
                    chunks[i][cur_chunk++] = (mask & state_trace[i].rw_counter);

                    sorted_prev = sorted;
                    sorted.clear();
                    for( std::size_t j = 0; j < chunks_amount; j++ ){
                        sorted.push_back(chunks[i][j]);
                        if( j == 1 ) sorted.push_back(op[i]);
                        if( j == 12 ) sorted.push_back(field_type[i]);
                    }

                    if( i == 0) continue;

                    std::size_t diff_ind;
                    for( diff_ind= 0; diff_ind < sorted.size(); diff_ind++ ){
                        if(sorted[diff_ind] != sorted_prev[diff_ind]) break;
                    }
                    diff_index_selectors[i][diff_ind] = 1;
                    diff[i] = sorted[diff_ind] - sorted_prev[diff_ind];
                    diff_inv[i] = diff[i] == 0? 0: diff[i].inversed();
                    is_diff_non_zero[i] = diff[i] == 0? 0: 1;
                    is_first[i] = (diff_ind < 30);
                    is_last[i-1] = i-1 == 0? 0: is_first[i];
                    is_first_and_read[i] = is_first[i] * (1 - is_write[i]);
                    not_is_first_and_read[i] = (1 - is_first[i]) * (1 - is_write[i]);
                    call_id[i] = state_trace[i].call_id;
                    parent_id[i] = state_trace[i].parent_id;
                    parent_id_inv[i] = parent_id[i] == 0? 0: parent_id[i].inversed();
                    call_initial_value_hi[i] = w_hi<FieldType>(state_trace[i].call_initial_value);
                    call_initial_value_lo[i] = w_lo<FieldType>(state_trace[i].call_initial_value);
                    is_not_block[i] = parent_id[i] == 0? 0: 1;
                    grandparent_id[i] = state_trace[i].grandparent_id;
                    grandparent_id_inv[i] = grandparent_id[i] == 0? 0: grandparent_id[i].inversed();
                    modified_items[i] = call_state_data.at(state_trace[i].id).modified_items;
                    is_reverted[i] = call_state_data.at(state_trace[i].id).is_reverted;

                    if( state_trace[i-1].op == rw_operation_type::state
                        || state_trace[i-1].op == rw_operation_type::transient_storage
                        || state_trace[i-1].op == rw_operation_type::access_list
                    ) reverted_is_last_selector[i-1] = is_last[i-1] * is_reverted[i-1];

                    is_not_block_and_not_transaction[i] = grandparent_id[i] == 0? 0: 1;
                    if( is_last[i-1] != 0 && is_not_block[i-1] != 0 && state_trace[i-1].op == rw_operation_type::state){
                        update_parent_selector[i - 1] = 1;
                    }
                    if( is_last[i-1] != 0 && is_not_block_and_not_transaction[i-1] != 0 &&
                        (state_trace[i-1].op == rw_operation_type::access_list || state_trace[i-1].op == rw_operation_type::transient_storage)
                    ){
                        update_parent_selector[i - 1] = 1;
                    }
                    if( is_last[i-1] != 0 && id[i] != id[i-1] ) last_in_call_selector[i - 1] = 1;
                    last_in_reverted_call_selector[i-1] = last_in_call_selector[i-1] * is_reverted[i-1];

                    if( state_trace[i].op == rw_operation_type::state_call_context ){
                        counter[i] = 0;
                    } else if( op[i] == op[i-1] &&
                        address[i] == address[i-1] &&
                        field_type[i] == field_type[i-1] &&
                        storage_key_hi[i] == storage_key_hi[i-1] &&
                        storage_key_lo[i] == storage_key_lo[i-1]
                    ){
                        counter[i] = counter[i-1];
                    } else {
                        counter[i] = counter[i-1] + 1;
                    }

                    BOOST_LOG_TRIVIAL(trace)
                        << "   modified_items = " << modified_items[i]
                        << " counter = " << counter[i]
                        << (is_reverted[i] == 1? " reverted" : "");
                }
                // TODO: Process empty trace correctly
                is_last[state_trace.size() - 1] = 1;
                if( state_trace.back().op == rw_operation_type::state
                    || state_trace.back().op == rw_operation_type::transient_storage
                    || state_trace.back().op == rw_operation_type::access_list
                ) reverted_is_last_selector[state_trace.size() - 1] = is_reverted[state_trace.size() - 1];

                if( is_not_block[state_trace.size()-1] != 0 && state_trace[state_trace.size()-1].op == rw_operation_type::state){
                    update_parent_selector[state_trace.size()-1] = 1;
                }
                if( is_last[state_trace.size()-1] != 0 && is_not_block_and_not_transaction[state_trace.size()-1] != 0 &&
                    (state_trace[state_trace.size()-1].op == rw_operation_type::access_list || state_trace[state_trace.size()-1].op == rw_operation_type::transient_storage)
                ){
                    update_parent_selector[state_trace.size()-1] = 1;
                }
                last_in_call_selector[state_trace.size() - 1] = 1;
                last_in_reverted_call_selector[state_trace.size() - 1] = is_reverted[state_trace.size() - 1] * last_in_call_selector[state_trace.size() - 1];

                for( std::size_t i = state_trace.size(); i < max_state; i++ ){
                    op_selectors[i][op_selector_indices[rw_operation_type::padding]] = 1;
                }
            }

            for( std::size_t i = 0; i < max_state; i++ ){
                std::size_t cur_column = state_table_type::get_witness_amount();
                allocate(call_id[i], cur_column++, i);
                allocate(parent_id[i], cur_column++, i);
                allocate(update_parent_selector[i], cur_column++, i);

                for( std::size_t j = 0; j < op_selectors_amount; j++){
                    allocate(op_selectors[i][j], cur_column++, i);
                };
                for( std::size_t k = 0; k < chunks_amount; k++){
                    allocate(chunks[i][k], cur_column++, i);
                }
                for( std::size_t j = 0; j < diff_index_selectors_amount; j++){
                    allocate(diff_index_selectors[i][j], cur_column++, i);
                }
                allocate(diff[i], cur_column++, i);
                allocate(diff_inv[i], cur_column++, i);
                allocate(is_diff_non_zero[i], cur_column++, i);
                allocate(is_first[i], cur_column++, i);
                allocate(is_last[i], cur_column++, i);
                allocate(is_first_and_read[i], cur_column++, i);
                allocate(not_is_first_and_read[i], cur_column++, i);
                allocate(parent_id_inv[i], cur_column++, i);
                allocate(is_not_block[i], cur_column++, i);
                allocate(grandparent_id[i], cur_column++, i);
                allocate(grandparent_id_inv[i], cur_column++, i);
                allocate(is_not_block_and_not_transaction[i], cur_column++, i);
                allocate(last_in_call_selector[i], cur_column++, i);
                allocate(call_initial_value_hi[i], cur_column++, i);
                allocate(call_initial_value_lo[i], cur_column++, i);
                allocate(counter[i], cur_column++, i);
                allocate(modified_items[i], cur_column++, i);
                allocate(is_reverted[i], cur_column++, i);
                allocate(reverted_is_last_selector[i], cur_column++, i);
                allocate(last_in_reverted_call_selector[i], cur_column++, i);
            }

            constrain(op[0] - START_OP);
            constrain(internal_counter[0]);

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                std::vector<TYPE> every_row_constraints;
                std::vector<TYPE> non_first_row_constraints;
                std::vector<TYPE> chunked_16_lookups;

                // Op selectors are selectors and they decompose op correctly
                TYPE op_constraint;
                TYPE op_selectors_sum;
                BOOST_ASSERT(op_selector_indices.size() == op_selectors_amount);

                for( auto &[k,v]:op_selector_indices){
                    op_constraint += op_selectors[1][v] * TYPE(std::size_t(k));
                }
                for( std::size_t i = 0; i < op_selectors_amount; i++ ){
                    op_selectors_sum += op_selectors[1][i];
                    every_row_constraints.push_back(op_selectors[1][i] * (op_selectors[1][i] - 1));
                }
                non_first_row_constraints.push_back(op_selectors_sum - 1);
                every_row_constraints.push_back(op[1] - op_constraint);

                TYPE access_list_selector = op_selectors[1][op_selector_indices[rw_operation_type::access_list]];
                TYPE state_selector = op_selectors[1][op_selector_indices[rw_operation_type::state]];
                TYPE transient_storage_selector = op_selectors[1][op_selector_indices[rw_operation_type::transient_storage]];
                TYPE call_context_selector = op_selectors[1][op_selector_indices[rw_operation_type::state_call_context]];
                TYPE padding_selector = op_selectors[1][op_selector_indices[rw_operation_type::padding]];

                TYPE access_list_selector_prev = op_selectors[0][op_selector_indices[rw_operation_type::access_list]];
                TYPE state_selector_prev = op_selectors[0][op_selector_indices[rw_operation_type::state]];
                TYPE transient_storage_selector_prev = op_selectors[0][op_selector_indices[rw_operation_type::transient_storage]];
                TYPE padding_selector_prev = op_selectors[0][op_selector_indices[rw_operation_type::padding]];

                // Chunks decomposition
                std::size_t cur_chunk = 0;
                TYPE id_composition;
                id_composition = chunks[1][cur_chunk++]; id_composition *= (1<<16);
                id_composition += chunks[1][cur_chunk++];
                every_row_constraints.push_back(context_object.relativize(id[1] - id_composition, -1));

                TYPE addr_composition;
                addr_composition = chunks[1][cur_chunk++]; addr_composition *= (1<<16); //1
                addr_composition += chunks[1][cur_chunk++]; addr_composition *= (1<<16); //2
                addr_composition += chunks[1][cur_chunk++]; addr_composition *= (1<<16); //3
                addr_composition += chunks[1][cur_chunk++]; addr_composition *= (1<<16); //4
                addr_composition += chunks[1][cur_chunk++]; addr_composition *= (1<<16); //5
                addr_composition += chunks[1][cur_chunk++]; addr_composition *= (1<<16); //6
                addr_composition += chunks[1][cur_chunk++]; addr_composition *= (1<<16); //7
                addr_composition += chunks[1][cur_chunk++]; addr_composition *= (1<<16); //8
                addr_composition += chunks[1][cur_chunk++]; addr_composition *= (1<<16); //9
                addr_composition += chunks[1][cur_chunk++];
                every_row_constraints.push_back(context_object.relativize(address[1] - addr_composition, -1));

                TYPE storage_key_hi_comp;
                storage_key_hi_comp = chunks[1][cur_chunk++]; storage_key_hi_comp *= (1<<16); //1
                storage_key_hi_comp += chunks[1][cur_chunk++]; storage_key_hi_comp *= (1<<16); //2
                storage_key_hi_comp += chunks[1][cur_chunk++]; storage_key_hi_comp *= (1<<16); //3
                storage_key_hi_comp += chunks[1][cur_chunk++]; storage_key_hi_comp *= (1<<16); //4
                storage_key_hi_comp += chunks[1][cur_chunk++]; storage_key_hi_comp *= (1<<16); //5
                storage_key_hi_comp += chunks[1][cur_chunk++]; storage_key_hi_comp *= (1<<16); //6
                storage_key_hi_comp += chunks[1][cur_chunk++]; storage_key_hi_comp *= (1<<16); //7
                storage_key_hi_comp += chunks[1][cur_chunk++];
                every_row_constraints.push_back(context_object.relativize(storage_key_hi[1] - storage_key_hi_comp, -1));

                TYPE storage_key_lo_comp;
                storage_key_lo_comp = chunks[1][cur_chunk++]; storage_key_lo_comp *= (1<<16); //1
                storage_key_lo_comp += chunks[1][cur_chunk++]; storage_key_lo_comp *= (1<<16); //2
                storage_key_lo_comp += chunks[1][cur_chunk++]; storage_key_lo_comp *= (1<<16); //3
                storage_key_lo_comp += chunks[1][cur_chunk++]; storage_key_lo_comp *= (1<<16); //4
                storage_key_lo_comp += chunks[1][cur_chunk++]; storage_key_lo_comp *= (1<<16); //5
                storage_key_lo_comp += chunks[1][cur_chunk++]; storage_key_lo_comp *= (1<<16); //6
                storage_key_lo_comp += chunks[1][cur_chunk++]; storage_key_lo_comp *= (1<<16); //7
                storage_key_lo_comp += chunks[1][cur_chunk++];
                every_row_constraints.push_back(context_object.relativize(storage_key_lo[1] - storage_key_lo_comp, -1));

                TYPE rw_id_composition;
                rw_id_composition = chunks[1][cur_chunk++]; rw_id_composition *= (1<<16);
                rw_id_composition += chunks[1][cur_chunk++];
                every_row_constraints.push_back(context_object.relativize(rw_id[1] - rw_id_composition, -1));

                TYPE diff_index_selectors_sum;
                TYPE is_first_constraint;
                for( std::size_t i = 0; i < diff_index_selectors_amount; i++){
                    diff_index_selectors_sum += diff_index_selectors[1][i];
                    if( i < 30 ) is_first_constraint += diff_index_selectors[1][i];
                    every_row_constraints.push_back(diff_index_selectors[1][i] * (diff_index_selectors[1][i] - 1));
                }
                every_row_constraints.push_back(diff_index_selectors_sum * (diff_index_selectors_sum - 1));
                non_first_row_constraints.push_back(is_first_constraint - is_first[1]);

                std::vector<TYPE> sorted;
                std::vector<TYPE> sorted_prev;
                std::size_t chunk_ind = 0;
                std::size_t sorted_ind = 0;
                sorted_prev.push_back(chunks[0][chunk_ind]); sorted.push_back(chunks[1][chunk_ind++]);
                sorted_prev.push_back(chunks[0][chunk_ind]); sorted.push_back(chunks[1][chunk_ind++]);
                sorted_prev.push_back(op[0]); sorted.push_back(op[1]);
                for( std::size_t i = 0; i < 10; i++ ) {
                    sorted_prev.push_back(chunks[0][chunk_ind]);
                    sorted.push_back(chunks[1][chunk_ind++]);
                }
                sorted_prev.push_back(field_type[0]); sorted.push_back(field_type[1]);
                for( std::size_t i = 0; i < 18; i++ ) {
                    sorted_prev.push_back(chunks[0][chunk_ind]);
                    sorted.push_back(chunks[1][chunk_ind++]);
                }

                TYPE filled_selector = access_list_selector + state_selector + transient_storage_selector + call_context_selector;
                non_first_row_constraints.push_back(filled_selector * padding_selector_prev);
                for( std::size_t s_ind = 0; s_ind < sorted.size() - 1; s_ind++ ){
                    TYPE eq_selector;
                    for( std::size_t d_ind = s_ind+1; d_ind < diff_index_selectors_amount; d_ind++){
                        eq_selector += diff_index_selectors[1][d_ind];
                    }
                    non_first_row_constraints.push_back(filled_selector * eq_selector * (sorted[s_ind] - sorted_prev[s_ind]));
                    non_first_row_constraints.push_back(filled_selector * diff_index_selectors[1][s_ind] * (sorted[s_ind] - sorted_prev[s_ind] - diff[1]));
                }

                every_row_constraints.push_back(diff[1] * diff_inv[1] - is_diff_non_zero[1]);
                every_row_constraints.push_back(is_diff_non_zero[1] * (1 - is_diff_non_zero[1]));
                non_first_row_constraints.push_back(filled_selector * (1 - is_diff_non_zero[1]));
                every_row_constraints.push_back(is_write[1] * (1 - is_write[1]));
                every_row_constraints.push_back(is_first_and_read[1] - is_first[1] * (1 - is_write[1]));
                every_row_constraints.push_back(not_is_first_and_read[1] - filled_selector * (1 - is_first[1]) * (1 - is_write[1]));
                non_first_row_constraints.push_back(not_is_first_and_read[1] * (value_hi[1] - value_hi[0]));
                non_first_row_constraints.push_back(not_is_first_and_read[1] * (value_lo[1] - value_lo[0]));
                non_first_row_constraints.push_back(filled_selector * (1 - is_first[1]) * (previous_value_hi[1] - value_hi[0]));
                non_first_row_constraints.push_back(filled_selector * (1 - is_first[1]) * (previous_value_lo[1] - value_lo[0]));
                non_first_row_constraints.push_back(filled_selector * (1 - is_first[1]) * (call_initial_value_hi[1] - call_initial_value_hi[0]));
                non_first_row_constraints.push_back(filled_selector * (1 - is_first[1]) * (call_initial_value_lo[1] - call_initial_value_lo[0]));
                non_first_row_constraints.push_back(filled_selector * (1 - is_first[1]) * (initial_value_hi[1] - initial_value_hi[0]));
                non_first_row_constraints.push_back(filled_selector * (1 - is_first[1]) * (initial_value_lo[1] - initial_value_lo[0]));
                // every_row_constraints.push_back(is_first_and_read[1] * (access_list_selector + transient_storage_selector) * value_hi[1]);
                // every_row_constraints.push_back(is_first_and_read[1] * (access_list_selector + transient_storage_selector) * value_lo[1]);
                every_row_constraints.push_back(access_list_selector * value_hi[1]);
                every_row_constraints.push_back(access_list_selector * value_lo[1] * (1 - value_lo[1]) );
                non_first_row_constraints.push_back(call_context_selector * counter[1]);
                non_first_row_constraints.push_back((state_selector + access_list_selector + transient_storage_selector) * (diff_index_selectors[1][0] + diff_index_selectors[1][1]) * (counter[1] - 1));
                non_first_row_constraints.push_back((state_selector + access_list_selector + transient_storage_selector) * (1 - is_first[1]) * (counter[1] - counter[0]));
                non_first_row_constraints.push_back(is_last[0] * (1 - is_first[1] - padding_selector));
                every_row_constraints.push_back(is_not_block[1] - parent_id[1] * parent_id_inv[1]);
                every_row_constraints.push_back(is_not_block[1] * (is_not_block[1] - 1));
                every_row_constraints.push_back(is_not_block_and_not_transaction[1] - grandparent_id[1] * grandparent_id_inv[1]);
                every_row_constraints.push_back(is_not_block_and_not_transaction[1] * (is_not_block_and_not_transaction[1] - 1));
                every_row_constraints.push_back(update_parent_selector[1] - is_last[1] * (
                    state_selector * is_not_block[1] +
                    (access_list_selector + transient_storage_selector) * is_not_block_and_not_transaction[1]
                ));
                non_first_row_constraints.push_back(
                    last_in_call_selector[0] - is_last[0] * ( diff_index_selectors[1][0] + diff_index_selectors[1][1] + padding_selector)
                );
                every_row_constraints.push_back(is_original[1] * (id[1] - call_id[1]));
                every_row_constraints.push_back(is_original[1] * (1 - is_original[1]));
                every_row_constraints.push_back(is_original[1] * (1 - filled_selector));

                non_first_row_constraints.push_back((filled_selector - is_first[1]) * (modified_items[1] - modified_items[0]));
                non_first_row_constraints.push_back((filled_selector - is_first[1]) * (is_reverted[1] - is_reverted[0]));
                every_row_constraints.push_back(is_last[1] * is_reverted[1] * (value_hi[1] - call_initial_value_hi[1]));
                every_row_constraints.push_back(is_last[1] * is_reverted[1] * (value_lo[1] - call_initial_value_lo[1]));
                every_row_constraints.push_back(is_last[1] * is_reverted[1] * (1 - is_original[1]));
                every_row_constraints.push_back(
                    reverted_is_last_selector[1] - (state_selector + transient_storage_selector + access_list_selector) * is_last[1] * is_reverted[1]
                );
                every_row_constraints.push_back(
                    last_in_reverted_call_selector[1] - is_reverted[1] * last_in_call_selector[1]
                );

                non_first_row_constraints.push_back(
                    filled_selector * (internal_counter[1] - internal_counter[0] - is_first[1])
                );

                // Parent lookup
                std::vector<TYPE> parent_lookup = {
                    filled_selector,
                    filled_selector * TYPE(std::size_t(rw_operation_type::state_call_context)),
                    filled_selector * id[1],
                    filled_selector * TYPE(std::size_t(state_call_context_fields::parent_id)),
                    TYPE(0),
                    TYPE(0),
                    TYPE(0),
                    filled_selector * ( id[1] +  std::size_t(state_call_context_fields::parent_id) ),
                    TYPE(0),
                    TYPE(0),
                    filled_selector * parent_id[1],
                    TYPE(0),
                    filled_selector * parent_id[1],
                    filled_selector * id[1]
                };
                std::vector<TYPE> reverted_lookup = {
                    filled_selector,
                    filled_selector * TYPE(std::size_t(rw_operation_type::state_call_context)),
                    filled_selector * id[1],
                    filled_selector * TYPE(std::size_t(state_call_context_fields::is_reverted)),
                    TYPE(0),
                    TYPE(0),
                    TYPE(0),
                    filled_selector * ( id[1] +  std::size_t(state_call_context_fields::is_reverted) ),
                    TYPE(0),
                    TYPE(0),
                    filled_selector * is_reverted[1],
                    TYPE(0),
                    filled_selector * is_reverted[1],
                    filled_selector * id[1]
                };
                std::vector<TYPE> modified_items_column_lookup = {
                    filled_selector,
                    filled_selector * TYPE(std::size_t(rw_operation_type::state_call_context)),
                    filled_selector * id[1],
                    filled_selector * TYPE(std::size_t(state_call_context_fields::modified_items)),
                    TYPE(0),
                    TYPE(0),
                    TYPE(0),
                    filled_selector * ( id[1] +  std::size_t(state_call_context_fields::modified_items) ),
                    TYPE(0),
                    TYPE(0),
                    filled_selector * modified_items[1],
                    TYPE(0),
                    filled_selector * modified_items[1],
                    filled_selector * id[1]
                };
                std::vector<TYPE> grandparent_lookup = {
                    is_not_block[1],
                    is_not_block[1] * TYPE(std::size_t(rw_operation_type::state_call_context)),
                    is_not_block[1] * parent_id[1],
                    is_not_block[1] * TYPE(std::size_t(state_call_context_fields::parent_id)),
                    TYPE(0),
                    TYPE(0),
                    TYPE(0),
                    is_not_block[1] * ( parent_id[1] + std::size_t(state_call_context_fields::parent_id)) ,
                    TYPE(0),
                    TYPE(0),
                    is_not_block[1] * grandparent_id[1],
                    TYPE(0),
                    is_not_block[1] * grandparent_id[1],
                    is_not_block[1] * parent_id[1]
                };
                std::vector<TYPE> update_parent_lookup = {
                    TYPE(0),
                    op[1],
                    parent_id[1],
                    address[1],
                    field_type[1],
                    storage_key_hi[1],
                    storage_key_lo[1],
                    rw_id[1],
                    TYPE(1),
                    value_hi[1],
                    value_lo[1],
                    call_initial_value_hi[1],
                    call_initial_value_lo[1],
                    id[1]
                };
                std::vector<TYPE> modified_items_lookup = {
                    TYPE(1),
                    TYPE(std::size_t(rw_operation_type::state_call_context)),
                    id[1],
                    TYPE(std::size_t(state_call_context_fields::modified_items)),
                    TYPE(0),
                    TYPE(0),
                    TYPE(0),
                    id[1] + std::size_t(state_call_context_fields::modified_items),
                    TYPE(0),
                    TYPE(0),
                    counter[1],
                    TYPE(0),
                    counter[1],
                    id[1]
                };
                std::vector<TYPE> end_call_lookup = {
                    TYPE(1),
                    TYPE(std::size_t(rw_operation_type::state_call_context)),
                    id[1],
                    TYPE(std::size_t(state_call_context_fields::end_call_rw_id)),
                    TYPE(0),
                    TYPE(0),
                    TYPE(0),
                    id[1] + std::size_t(state_call_context_fields::end_call_rw_id),
                    TYPE(0),
                    TYPE(0),
                    rw_id[1],
                    TYPE(0),
                    rw_id[1],
                    id[1]
                };
                std::vector<TYPE> revert_end_call_lookup = {
                    TYPE(1),
                    TYPE(std::size_t(rw_operation_type::state_call_context)),
                    id[1],
                    TYPE(std::size_t(state_call_context_fields::end_call_rw_id)),
                    TYPE(0),
                    TYPE(0),
                    TYPE(0),
                    id[1] + std::size_t(state_call_context_fields::end_call_rw_id),
                    TYPE(0),
                    TYPE(0),
                    rw_id[1] - counter[1] + modified_items[1],
                    TYPE(0),
                    rw_id[1] - counter[1] + modified_items[1],
                    id[1]
                };
                std::vector<TYPE> child_lookup = {
                    op[1],
                    call_id[1],
                    address[1],
                    field_type[1],
                    storage_key_hi[1],
                    storage_key_lo[1],
                    rw_id[1],
                    id[1],
                    TYPE(1)
                };
                for( std::size_t i = 0; i < parent_lookup.size(); i++){
                    parent_lookup[i] = context_object.relativize(parent_lookup[i], -1);
                    grandparent_lookup[i] = context_object.relativize(grandparent_lookup[i], -1);
                    update_parent_lookup[i] = context_object.relativize(update_parent_lookup[i] * update_parent_selector[1], -1);
                    modified_items_lookup[i] = context_object.relativize(modified_items_lookup[i] * last_in_call_selector[1], -1);
                    end_call_lookup[i] = context_object.relativize(end_call_lookup[i] * last_in_reverted_call_selector[1], -1);
                    reverted_lookup[i] = context_object.relativize(reverted_lookup[i], -1);
                    revert_end_call_lookup[i] = context_object.relativize(revert_end_call_lookup[i] * reverted_is_last_selector[1], -1);
                    modified_items_column_lookup[i] = context_object.relativize(modified_items_column_lookup[i], -1);
                }
                for( std::size_t i = 0; i < child_lookup.size(); i++){
                    child_lookup[i] = context_object.relativize((filled_selector - is_original[1]) * child_lookup[i], -1);
                }

                context_object.relative_lookup(parent_lookup, "zkevm_state", 0, max_state-1);
                context_object.relative_lookup(grandparent_lookup, "zkevm_state", 0, max_state-1);
                context_object.relative_lookup(update_parent_lookup, "zkevm_state", 0, max_state-1);
                context_object.relative_lookup(modified_items_lookup, "zkevm_state", 0, max_state-1);
                context_object.relative_lookup(end_call_lookup, "zkevm_state", 0, max_state-1);
                context_object.relative_lookup(reverted_lookup, "zkevm_state", 0, max_state-1);
                context_object.relative_lookup(revert_end_call_lookup, "zkevm_state", 0, max_state-1);
                context_object.relative_lookup(modified_items_column_lookup, "zkevm_state", 0, max_state-1);
                context_object.relative_lookup(child_lookup, "zkevm_state_parent", 0, max_state-1);

                for( std::size_t i = 0; i < chunks_amount; i++){
                    chunked_16_lookups.push_back(chunks[1][i]);
                }
                chunked_16_lookups.push_back(diff[1]);
                chunked_16_lookups.push_back(padding_selector * (op[1] - op[0]));

                for( auto& constraint: every_row_constraints){
                    context_object.relative_constrain(context_object.relativize(constraint, -1), 0, max_state-1);
                }
                for( auto &constraint:chunked_16_lookups ){
                    std::vector<TYPE> tmp = {context_object.relativize(constraint, -1)};
                    context_object.relative_lookup(tmp, "chunk_16_bits/full", 0, max_state-1);
                }
                for( auto &constraint: non_first_row_constraints ){
                    context_object.relative_constrain(context_object.relativize(constraint, -1), 1, max_state-1);
                }
            }
        }
    };
}
