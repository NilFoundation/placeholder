//---------------------------------------------------------------------------//
// Copyright (c) 2025 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/tables/state.hpp>

namespace nil::blueprint::bbf::zkevm_small_field{
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
        static constexpr std::size_t chunks_amount = 4;     // 2 for rw_id,2 for id
        static constexpr std::size_t helpers_amount = 38;
        static constexpr std::size_t op_selectors_amount = state_operation_types_amount - 1;

        static table_params get_minimal_requirements(
            std::size_t max_state
        ) {
            std::size_t witnesses = state_table_type::get_witness_amount(state_table_mode::full)
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

        state_transition(context_type &context_object,
            const input_type &input,
            std::size_t max_state
        ) :generic_component<FieldType,stage>(context_object) {
            BOOST_LOG_TRIVIAL(info) << "State circuit started" << std::endl;
            std::vector<std::size_t> table_subcomponent_area;
            for( std::size_t i = 0; i < state_table_type::get_witness_amount(state_table_mode::full); i++ )
                table_subcomponent_area.push_back(i);
            context_type state_table_ct = context_object.subcontext(table_subcomponent_area,0,max_state);
            state_table_type t(state_table_ct, input.state_trace, max_state, state_table_mode::full);

            const std::vector<TYPE> &is_original = t.is_original;
            const std::vector<TYPE> &op = t.op = t.op;
            const std::vector<TYPE> &id = t.id;                                // 2          -- 2 chunks fitted in field element less than 2^25
            const std::vector<std::array<TYPE, 10>> &address = t.address;           // 3-12       -- 10 chunks
            const std::vector<TYPE> &field_type = t.field_type;                        // 13
            const std::vector<std::array<TYPE, 16>> &storage_key = t.storage_key;       // 14 -- 45   -- 16 full chunks
            const std::vector<TYPE> &rw_id = t.rw_id;                             // 46   -- 2 chunks fitted in field element less than 2^25
            const std::vector<TYPE> &is_write = t.is_write;                          // 47
            const std::vector<std::array<TYPE, 16>> &value = t.value;            // 48 -- 79
            const std::vector<std::array<TYPE, 16>> &previous_value = t.previous_value;   // 80 -- 111
            const std::vector<std::array<TYPE, 16>> &initial_value = t.initial_value;    // 112 -- 143
            const std::vector<TYPE> &internal_counter = t.internal_counter;                  // 144 -- 2 chunks fitted in field element less than 2^25
            const std::vector<TYPE> &call_id = t.call_id;
            const std::vector<TYPE> &parent_id = t.parent_id;
            const std::vector<TYPE> &update_parent_selector = t.update_parent_selector;

            std::vector<std::array<TYPE, op_selectors_amount>> op_selectors(max_state);
            std::vector<std::array<TYPE, diff_index_selectors_amount>> diff_index_selectors(max_state);
            std::vector<std::array<TYPE, chunks_amount>> chunks(max_state);

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
            std::vector<std::array<TYPE,16>> call_initial_value(max_state);
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

                    // rw_id
                    mask = 0xffff;
                    mask <<= 16;
                    chunks[i][cur_chunk++] = (mask & state_trace[i].rw_counter) >> 16;
                    mask >>= 16;
                    chunks[i][cur_chunk++] = (mask & state_trace[i].rw_counter);

                    sorted_prev = sorted;
                    sorted.clear();
                    sorted.push_back(chunks[i][0]);
                    sorted.push_back(chunks[i][1]);
                    sorted.push_back(op[i]);
                    sorted.insert(sorted.end(), address[i].begin(), address[i].end());
                    sorted.push_back(field_type[i]);
                    sorted.insert(sorted.end(), storage_key[i].begin(), storage_key[i].end());
                    sorted.push_back(chunks[i][2]);
                    sorted.push_back(chunks[i][3]);

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
                    parent_id_inv[i] = parent_id[i] == 0? 0: parent_id[i].inversed();
                    auto call_initial_value_chunks = w_to_16(state_trace[i].call_initial_value);
                    for( std::size_t j = 0; j < 16; j++){
                        call_initial_value[i][j] = call_initial_value_chunks[j];
                    }
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
                    if( is_last[i-1] != 0 && id[i] != id[i-1] ) last_in_call_selector[i - 1] = 1;
                    last_in_reverted_call_selector[i-1] = last_in_call_selector[i-1] * is_reverted[i-1];

                    if( state_trace[i].op == rw_operation_type::state_call_context ){
                        counter[i] = 0;
                    } else if( diff_ind >= 30 ){
                        counter[i] = counter[i-1];
                    } else {
                        counter[i] = counter[i-1] + 1;
                    }
                    if( update_parent_selector[i-1] != t.update_parent_selector[i-1] ) {
                        BOOST_LOG_TRIVIAL(error) << "update_parent_selector[" << i-1 << "] in circuit = " << update_parent_selector[i-1]
                            << " != " << t.update_parent_selector[i-1] << std::endl;
                        BOOST_CHECK(update_parent_selector[i-1] == t.update_parent_selector[i-1]);
                    }
                }
                // TODO: Process empty trace correctly
                is_last[state_trace.size() - 1] = 1;
                if( state_trace.back().op == rw_operation_type::state
                    || state_trace.back().op == rw_operation_type::transient_storage
                    || state_trace.back().op == rw_operation_type::access_list
                ) reverted_is_last_selector[state_trace.size() - 1] = is_reverted[state_trace.size() - 1];

                last_in_call_selector[state_trace.size() - 1] = 1;
                last_in_reverted_call_selector[state_trace.size() - 1] = is_reverted[state_trace.size() - 1] * last_in_call_selector[state_trace.size() - 1];

                for( std::size_t i = state_trace.size(); i < max_state; i++ ){
                    op_selectors[i][op_selector_indices[rw_operation_type::padding]] = 1;
                }
            }

            for( std::size_t i = 0; i < max_state; i++ ){
                std::size_t cur_column = state_table_type::get_witness_amount(state_table_mode::full);

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
                for( std::size_t j = 0; j < 16; j++ ){
                    allocate(call_initial_value[i][j], cur_column++, i);
                }
                allocate(counter[i], cur_column++, i);
                allocate(modified_items[i], cur_column++, i);
                allocate(is_reverted[i], cur_column++, i);
                allocate(reverted_is_last_selector[i], cur_column++, i);
                allocate(last_in_reverted_call_selector[i], cur_column++, i);
            }

            constrain(op[0], "First operation must be START_OP");
            constrain(internal_counter[0], "First operation must have internal_counter = 0");

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                std::vector<std::pair<TYPE, std::string>> every_row_constraints;
                std::vector<std::pair<TYPE, std::string>> non_first_row_constraints;
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
                    every_row_constraints.push_back({op_selectors[1][i] * (op_selectors[1][i] - 1), "op_selector[" + std::to_string(i) + "] may be only 0 or 1"});
                }
                non_first_row_constraints.push_back({op_selectors_sum - 1, "one and only one op_selector must be set"});
                every_row_constraints.push_back({op[1] - op_constraint, "op is encoded correctly by op_selectors"});

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
                every_row_constraints.push_back({id[1] - id_composition, "id decomposition"});

                TYPE rw_id_composition;
                rw_id_composition = chunks[1][cur_chunk++]; rw_id_composition *= (1<<16);
                rw_id_composition += chunks[1][cur_chunk++];
                every_row_constraints.push_back({rw_id[1] - rw_id_composition, "rw_id decomposition"});

                TYPE diff_index_selectors_sum;
                TYPE is_first_constraint;
                for( std::size_t i = 0; i < diff_index_selectors_amount; i++){
                    diff_index_selectors_sum += diff_index_selectors[1][i];
                    if( i < 30 ) is_first_constraint += diff_index_selectors[1][i];
                    every_row_constraints.push_back({diff_index_selectors[1][i] * (diff_index_selectors[1][i] - 1), "diff_index_selectors[" + std::to_string(i) + "] may be only 0 or 1"});
                }
                every_row_constraints.push_back({diff_index_selectors_sum * (diff_index_selectors_sum - 1), "Only one of diff_index_selectors must be set"});
                non_first_row_constraints.push_back({is_first_constraint - is_first[1], "is_first is correctly connected with diff_index"});

                std::vector<TYPE> sorted;
                std::vector<TYPE> sorted_prev;
                sorted_prev.push_back(chunks[0][0]); sorted.push_back(chunks[1][0]);
                sorted_prev.push_back(chunks[0][1]); sorted.push_back(chunks[1][1]);
                sorted_prev.push_back(op[0]); sorted.push_back(op[1]);
                for( std::size_t i = 0; i < 10; i++ ) {
                    sorted_prev.push_back(address[0][i]);
                    sorted.push_back(address[1][i]);
                }
                sorted_prev.push_back(field_type[0]); sorted.push_back(field_type[1]);
                for( std::size_t i = 0; i < 16; i++ ) {
                    sorted_prev.push_back(storage_key[0][i]);
                    sorted.push_back(storage_key[1][i]);
                }
                sorted_prev.push_back(chunks[0][2]); sorted.push_back(chunks[1][2]);
                sorted_prev.push_back(chunks[0][3]); sorted.push_back(chunks[1][3]);

                TYPE filled_selector = access_list_selector + state_selector + transient_storage_selector + call_context_selector;
                for( std::size_t s_ind = 0; s_ind < sorted.size() - 1; s_ind++ ){
                    TYPE eq_selector;
                    for( std::size_t d_ind = s_ind+1; d_ind < diff_index_selectors_amount; d_ind++){
                        eq_selector += diff_index_selectors[1][d_ind];
                    }
                    non_first_row_constraints.push_back({
                        filled_selector * eq_selector * (sorted[s_ind] - sorted_prev[s_ind]),
                        "If diff_index = " + std::to_string(s_ind) + " then for all i < " + std::to_string(s_ind) + " sorted[i] == sorted_prev[i]"
                    });
                    non_first_row_constraints.push_back({
                        filled_selector * diff_index_selectors[1][s_ind] * (sorted[s_ind] - sorted_prev[s_ind] - diff[1]),
                        "If diff_index = " + std::to_string(s_ind) + " diff is defined as sorted[" + std::to_string(s_ind) + "] - sorted_prev[" + std::to_string(s_ind) + "]"
                    });
                }

                every_row_constraints.push_back({is_diff_non_zero[1] * (1 - is_diff_non_zero[1]), "is_diff_non_zero may be only 0 or 1"});
                every_row_constraints.push_back({diff[1] * diff_inv[1] - is_diff_non_zero[1],"is_diff_non_zero definition"});
                every_row_constraints.push_back({(1 - is_diff_non_zero[1]) * diff[1], "if diff is not zero then is_diff_non_zero is 1"});
                every_row_constraints.push_back({(1 - is_diff_non_zero[1]) * diff_inv[1], "if diff_inv is not zero then is_diff_non_zero is 1"});

                non_first_row_constraints.push_back({filled_selector * (1 - is_diff_non_zero[1]), "For non-padding rows diff is not zero"});
                every_row_constraints.push_back({is_write[1] * (1 - is_write[1]), "is_write may be only 0 or 1"});
                every_row_constraints.push_back({is_first_and_read[1] - is_first[1] * (1 - is_write[1]), "is_first_and_read is correctly defined"});
                every_row_constraints.push_back({not_is_first_and_read[1] - filled_selector * (1 - is_first[1]) * (1 - is_write[1]), "not_is_first_and_read is correctly defined"});
                for( std::size_t i = 0; i < 16; i++){
                    non_first_row_constraints.push_back({
                        not_is_first_and_read[1] * (value[1][i] - value[0][i]),
                        "read-after-write constraint for " + std::to_string(i) + " chunk"
                    });
                    non_first_row_constraints.push_back({
                        filled_selector * (1 - is_first[1]) * (previous_value[1][i] - value[0][i]),
                        "previous value for " + std::to_string(i) + " chunk is correctly defined"
                    });
                    non_first_row_constraints.push_back({
                        filled_selector * (1 - is_first[1]) * (initial_value[1][i] - initial_value[0][i]),
                        "initial value " + std::to_string(i) + " chunk doesn't change during a call"
                    });
                    non_first_row_constraints.push_back({
                        filled_selector * (1 - is_first[1]) * (call_initial_value[1][i] - call_initial_value[0][i]),
                        "call initial value " + std::to_string(i) + " chunk doesn't change during a call"
                    });
                }
                for( std::size_t i = 0; i < 15; i++ ){
                    every_row_constraints.push_back({
                        access_list_selector * value[1][i],
                        "access_list " + std::to_string(i) + " chunk is zero"
                    });
                }
                every_row_constraints.push_back({
                    access_list_selector * value[1][15] * (1 - value[1][15]),
                    "access_list value may be only 1 or 0"
                });
                for( std::size_t i = 0; i < 16; i++){
                    every_row_constraints.push_back({
                        (access_list_selector + transient_storage_selector) * initial_value[1][i],
                        "access and transient storage are initialized by zeroes chunk " + std::to_string(i)
                    });
                    every_row_constraints.push_back({
                        (access_list_selector + transient_storage_selector) *
                        (is_not_block[1] - is_not_block_and_not_transaction[1]) * call_initial_value[1][i],
                        "transient_storage and access_list are initalized by zeroes in transaction chunk " + std::to_string(i)
                    });
                }
                non_first_row_constraints.push_back({call_context_selector * counter[1], "counter for call_context is zero"});
                non_first_row_constraints.push_back({
                    (state_selector + access_list_selector + transient_storage_selector) *
                    (diff_index_selectors[1][0] + diff_index_selectors[1][1]) *
                    (counter[1] - 1),
                    "Counter for the first state, access_list or transient_storage row is 1"
                });
                non_first_row_constraints.push_back({
                    (state_selector + access_list_selector + transient_storage_selector) *
                    (counter[1] - counter[0] - is_first[1]),
                    "Counter doesn't change for non-first operation for an item and increased for a first operation"
                });
                non_first_row_constraints.push_back({is_last[0] * (1 - is_first[1] - padding_selector), "is_last is correctly defined"});
                every_row_constraints.push_back({is_not_block[1] - parent_id[1] * parent_id_inv[1],"is_not_block = parent_id != 0"});
                every_row_constraints.push_back({is_not_block[1] * (is_not_block[1] - 1),"is_not_block may be only 0 or 1"});
                every_row_constraints.push_back({parent_id[1] * (1 - is_not_block[1]), "if parent_id id not zero then is_not_block is 1" });
                every_row_constraints.push_back({parent_id_inv[1] * (1 - is_not_block[1]), "if parent_id_inv id not zero then is_not_block is 1" });

                every_row_constraints.push_back({
                    is_not_block_and_not_transaction[1] - grandparent_id[1] * grandparent_id_inv[1],
                    "is_not_block_and_not_transaction is correctly defined"
                });
                every_row_constraints.push_back({
                    is_not_block_and_not_transaction[1] * (is_not_block_and_not_transaction[1] - 1),
                    "is_not_block_and_not_transaction may be only 0 or 1"
                });
                every_row_constraints.push_back({
                    grandparent_id[1] * (1 - is_not_block_and_not_transaction[1]),
                    "if grandparent_id id not zero then is_not_block_and_not_transaction is 1"
                });
                every_row_constraints.push_back({
                    grandparent_id_inv[1] * (1 - is_not_block_and_not_transaction[1]),
                    "if grandparent_id id not zero then is_not_block_and_not_transaction is 1"
                });

                every_row_constraints.push_back({update_parent_selector[1] - is_last[1] * (
                    state_selector * is_not_block[1] +
                    (access_list_selector + transient_storage_selector) * is_not_block_and_not_transaction[1]
                ), "update_parent is correctly defined"});
                non_first_row_constraints.push_back({
                    last_in_call_selector[0] - is_last[0] * ( diff_index_selectors[1][0] + diff_index_selectors[1][1] + padding_selector),
                    "last_in_call_selector is correctly defined"
                });
                every_row_constraints.push_back({
                    is_original[1] * (id[1] - call_id[1]),
                    "for original operations id == call_id"
                });
                every_row_constraints.push_back({
                    is_original[1] * (1 - is_original[1]),
                    "is_original may be only 0 or 1"
                });
                every_row_constraints.push_back({
                    is_original[1] * (1 - filled_selector),
                    "is_original may be 1 always for not padding rows"
                });

                non_first_row_constraints.push_back({
                    (filled_selector - is_first[1]) * (modified_items[1] - modified_items[0]),
                    "modified_items for non-first operations is not changed"
                });
                non_first_row_constraints.push_back({
                    (filled_selector - is_first[1]) * (is_reverted[1] - is_reverted[0]),
                    "is_reverted for non-first operations is not changed"
                });
                for( std::size_t i = 0; i < 16; i++ ){
                    non_first_row_constraints.push_back({
                        (filled_selector - is_first[1]) * (call_initial_value[1][i] - call_initial_value[0][i]),
                        "last operation in reverted call returns to call_initial value for " + std::to_string(i) + " chunk"
                    });
                }
                every_row_constraints.push_back({
                    is_last[1] * is_reverted[1] * (1 - is_original[1]),
                    "last operation in reverted call is original"
                });
                every_row_constraints.push_back({
                    reverted_is_last_selector[1] - (state_selector + transient_storage_selector + access_list_selector) * is_last[1] * is_reverted[1],
                    "reverted_is_last_selector is correctly defined"
                });
                every_row_constraints.push_back({
                    last_in_reverted_call_selector[1] - is_reverted[1] * last_in_call_selector[1],
                    "last_in_reverted_call_selector is correctly defined"
                });
                non_first_row_constraints.push_back({
                    filled_selector * (internal_counter[1] - internal_counter[0] - is_first[1]),
                    "internal_counter increased for first operation"
                });

                // Parent lookup
                std::vector<TYPE> parent_lookup;
                parent_lookup.push_back(filled_selector); // is_original
                parent_lookup.push_back(filled_selector * TYPE(std::size_t(rw_operation_type::state_call_context))); // op
                parent_lookup.push_back(filled_selector * id[1]); // id
                // address
                for( std::size_t i = 0; i < 9; i++) parent_lookup.push_back(TYPE(0));
                parent_lookup.push_back(filled_selector * TYPE(std::size_t(state_call_context_fields::parent_id)));
                parent_lookup.push_back(TYPE(0)); // field_type
                for( std::size_t i = 0; i < 16; i++) parent_lookup.push_back(TYPE(0)); // storage_key
                parent_lookup.push_back(filled_selector * ( id[1] +  std::size_t(state_call_context_fields::parent_id) )); // rw_id
                parent_lookup.push_back(TYPE(0));   // is_write
                // value
                for( std::size_t i = 0; i < 15; i++) parent_lookup.push_back(TYPE(0));
                parent_lookup.push_back(filled_selector * parent_id[1]);
                // previous_value
                for( std::size_t i = 0; i < 15; i++) parent_lookup.push_back(TYPE(0));
                parent_lookup.push_back(filled_selector * parent_id[1]);
                parent_lookup.push_back(filled_selector * id[1]); // call_id

                // reverted_lookup
                std::vector<TYPE> reverted_lookup;
                reverted_lookup.push_back(filled_selector); // is_original
                reverted_lookup.push_back(filled_selector * TYPE(std::size_t(rw_operation_type::state_call_context))); // op
                reverted_lookup.push_back(filled_selector * id[1]); // id
                // address
                for( std::size_t i = 0; i < 9; i++) reverted_lookup.push_back(TYPE(0));
                reverted_lookup.push_back(filled_selector * TYPE(std::size_t(state_call_context_fields::is_reverted)));
                reverted_lookup.push_back(TYPE(0)); // field_type
                for( std::size_t i = 0; i < 16; i++) reverted_lookup.push_back(TYPE(0)); // storage_key
                reverted_lookup.push_back(filled_selector * ( id[1] +  std::size_t(state_call_context_fields::is_reverted) )); // rw_id
                reverted_lookup.push_back(TYPE(0));   // is_write
                // value
                for( std::size_t i = 0; i < 15; i++) reverted_lookup.push_back(TYPE(0));
                reverted_lookup.push_back(filled_selector * is_reverted[1]);
                // previous_value
                for( std::size_t i = 0; i < 15; i++) reverted_lookup.push_back(TYPE(0));
                reverted_lookup.push_back(filled_selector * is_reverted[1]);
                reverted_lookup.push_back(filled_selector * id[1]); // call_id

                std::vector<TYPE> modified_items_column_lookup;
                modified_items_column_lookup.push_back(filled_selector); // is_original
                modified_items_column_lookup.push_back(filled_selector * TYPE(std::size_t(rw_operation_type::state_call_context))); // op
                modified_items_column_lookup.push_back(filled_selector * id[1]); // id
                // address
                for( std::size_t i = 0; i < 9; i++) modified_items_column_lookup.push_back(TYPE(0));
                modified_items_column_lookup.push_back(filled_selector * TYPE(std::size_t(state_call_context_fields::modified_items)));
                modified_items_column_lookup.push_back(TYPE(0)); // field_type
                for( std::size_t i = 0; i < 16; i++) modified_items_column_lookup.push_back(TYPE(0)); // storage_key
                modified_items_column_lookup.push_back(filled_selector * ( id[1] +  std::size_t(state_call_context_fields::modified_items) )); // rw_id
                modified_items_column_lookup.push_back(TYPE(0));   // is_write
                // value
                for( std::size_t i = 0; i < 15; i++) modified_items_column_lookup.push_back(TYPE(0));
                modified_items_column_lookup.push_back(filled_selector * modified_items[1]);
                // previous_value
                for( std::size_t i = 0; i < 15; i++) modified_items_column_lookup.push_back(TYPE(0));
                modified_items_column_lookup.push_back(filled_selector * modified_items[1]);
                modified_items_column_lookup.push_back(filled_selector * id[1]); // call_id

                std::vector<TYPE> grandparent_lookup;
                grandparent_lookup.push_back(is_not_block[1]); // is_original
                grandparent_lookup.push_back(is_not_block[1] * TYPE(std::size_t(rw_operation_type::state_call_context))); // op
                grandparent_lookup.push_back(is_not_block[1] * parent_id[1]); // id
                // address
                for( std::size_t i = 0; i < 9; i++) grandparent_lookup.push_back(TYPE(0));
                grandparent_lookup.push_back(is_not_block[1] * TYPE(std::size_t(state_call_context_fields::parent_id))); // field_type
                grandparent_lookup.push_back(TYPE(0)); // field_type
                for( std::size_t i = 0; i < 16; i++) grandparent_lookup.push_back(TYPE(0)); // storage_key
                grandparent_lookup.push_back(is_not_block[1] * ( parent_id[1] + std::size_t(state_call_context_fields::parent_id) )); // rw_id
                grandparent_lookup.push_back(TYPE(0));   // is_write
                // value
                for( std::size_t i = 0; i < 15; i++) grandparent_lookup.push_back(TYPE(0));
                grandparent_lookup.push_back(is_not_block[1] * grandparent_id[1]);
                // previous_value
                for( std::size_t i = 0; i < 15; i++) grandparent_lookup.push_back(TYPE(0));
                grandparent_lookup.push_back(is_not_block[1] * grandparent_id[1]);
                grandparent_lookup.push_back(is_not_block[1] * parent_id[1]); // call_id

                std::vector<TYPE> modified_items_lookup;
                modified_items_lookup.push_back(TYPE(1)); // is_original
                modified_items_lookup.push_back(TYPE(std::size_t(rw_operation_type::state_call_context))); // op
                modified_items_lookup.push_back(id[1]); // id
                // address
                for( std::size_t i = 0; i < 9; i++) modified_items_lookup.push_back(TYPE(0));
                modified_items_lookup.push_back(TYPE(std::size_t(state_call_context_fields::modified_items))); // field_type
                modified_items_lookup.push_back(TYPE(0)); // field_type
                for( std::size_t i = 0; i < 16; i++) modified_items_lookup.push_back(TYPE(0)); // storage_key
                modified_items_lookup.push_back(id[1] + std::size_t(state_call_context_fields::modified_items)); // rw_id
                modified_items_lookup.push_back(TYPE(0));   // is_write
                // value
                for( std::size_t i = 0; i < 15; i++)
                    modified_items_lookup.push_back(TYPE(0));
                modified_items_lookup.push_back(counter[1]);
                // previous_value
                for( std::size_t i = 0; i < 15; i++)
                    modified_items_lookup.push_back(TYPE(0));
                modified_items_lookup.push_back(counter[1]);
                modified_items_lookup.push_back(id[1]); // call_id

                std::vector<TYPE> end_call_lookup;
                end_call_lookup.push_back(TYPE(1)); // is_original
                end_call_lookup.push_back(TYPE(std::size_t(rw_operation_type::state_call_context))); // op
                end_call_lookup.push_back(id[1]); // id
                // address
                for( std::size_t i = 0; i < 9; i++) end_call_lookup.push_back(TYPE(0));
                end_call_lookup.push_back(TYPE(std::size_t(state_call_context_fields::end_call_rw_id))); // field_type
                end_call_lookup.push_back(TYPE(0));   // field_type
                for( std::size_t i = 0; i < 16; i++) end_call_lookup.push_back(TYPE(0)); // storage_key
                end_call_lookup.push_back(id[1] + std::size_t(state_call_context_fields::end_call_rw_id)); // rw_id
                end_call_lookup.push_back(TYPE(0));   // is_write
                // value
                for( std::size_t i = 0; i < 15; i++)
                    end_call_lookup.push_back(TYPE(0));
                end_call_lookup.push_back(rw_id[1]);
                // previous_value
                for( std::size_t i = 0; i < 15; i++)
                    end_call_lookup.push_back(TYPE(0));
                end_call_lookup.push_back(rw_id[1]);
                end_call_lookup.push_back(id[1]); // call_id

                std::vector<TYPE> revert_end_call_lookup;
                revert_end_call_lookup.push_back(TYPE(1)); // is_original
                revert_end_call_lookup.push_back(TYPE(std::size_t(rw_operation_type::state_call_context))); // op
                revert_end_call_lookup.push_back(id[1]); // id
                // address
                for( std::size_t i = 0; i < 9; i++) revert_end_call_lookup.push_back(TYPE(0));
                revert_end_call_lookup.push_back(TYPE(std::size_t(state_call_context_fields::end_call_rw_id))); // field_type
                revert_end_call_lookup.push_back(TYPE(0));   // field_type
                for( std::size_t i = 0; i < 16; i++) revert_end_call_lookup.push_back(TYPE(0)); // storage_key
                revert_end_call_lookup.push_back(id[1] + std::size_t(state_call_context_fields::end_call_rw_id)); // rw_id
                revert_end_call_lookup.push_back(TYPE(0));   // is_write
                // value
                for( std::size_t i = 0; i < 15; i++)
                    revert_end_call_lookup.push_back(TYPE(0));
                revert_end_call_lookup.push_back(rw_id[1] - counter[1] + modified_items[1]);
                // previous_value
                for( std::size_t i = 0; i < 15; i++)
                    revert_end_call_lookup.push_back(TYPE(0));
                revert_end_call_lookup.push_back(rw_id[1] - counter[1] + modified_items[1]);
                revert_end_call_lookup.push_back(id[1]); // call_id

                std::vector<TYPE> update_parent_lookup;
                update_parent_lookup.push_back(TYPE(0)); // is_original
                update_parent_lookup.push_back(op[1]); // op
                update_parent_lookup.push_back(parent_id[1]); // id
                // address
                for( std::size_t i = 0; i < 10; i++ ) update_parent_lookup.push_back(address[1][i]);
                update_parent_lookup.push_back(TYPE(0));   // field_type
                // storage_key
                for( std::size_t i = 0; i < 16; i++) update_parent_lookup.push_back(storage_key[1][i]);
                update_parent_lookup.push_back(rw_id[1]); // rw_id
                update_parent_lookup.push_back(TYPE(1));   // is_write
                // value
                for( std::size_t i = 0; i < 16; i++)
                    update_parent_lookup.push_back(value[1][i]);
                // previous_value
                for( std::size_t i = 0; i < 16; i++)
                    update_parent_lookup.push_back(call_initial_value[1][i]);
                update_parent_lookup.push_back(id[1]); // call_id

                std::vector<TYPE> child_lookup;
                child_lookup.push_back(op[1]); // op
                child_lookup.push_back(call_id[1]); // call_id
                for( std::size_t i = 0; i < 10; i++ ) child_lookup.push_back(address[1][i]); // address
                child_lookup.push_back(field_type[1]); // field_type
                for( std::size_t i = 0; i < 16; i++) child_lookup.push_back(storage_key[1][i]); // storage_key
                child_lookup.push_back(rw_id[1]); // rw_id
                child_lookup.push_back(id[1]); // rw_id
                child_lookup.push_back(TYPE(1)); // is_write

                for( std::size_t i = 0; i < parent_lookup.size(); i++){
                    parent_lookup[i] = context_object.relativize(parent_lookup[i], -1);
                    grandparent_lookup[i] = context_object.relativize(grandparent_lookup[i], -1);
                    modified_items_lookup[i] = context_object.relativize(modified_items_lookup[i] * last_in_call_selector[1], -1);
                    end_call_lookup[i] = context_object.relativize(end_call_lookup[i] * last_in_reverted_call_selector[1], -1);
                    reverted_lookup[i] = context_object.relativize(reverted_lookup[i], -1);
                    revert_end_call_lookup[i] = context_object.relativize(revert_end_call_lookup[i] * reverted_is_last_selector[1], -1);
                    modified_items_column_lookup[i] = context_object.relativize(modified_items_column_lookup[i], -1);
                    update_parent_lookup[i] = context_object.relativize(update_parent_lookup[i] * update_parent_selector[1], -1);
                }
                for( std::size_t i = 0; i < child_lookup.size(); i++){
                    child_lookup[i] = context_object.relativize((filled_selector - is_original[1]) * child_lookup[i], -1);
                }

                context_object.relative_lookup(parent_lookup, "zkevm_state", 0, max_state-1);
                context_object.relative_lookup(grandparent_lookup, "zkevm_state", 0, max_state-1);
                context_object.relative_lookup(modified_items_lookup, "zkevm_state", 0, max_state-1);
                context_object.relative_lookup(end_call_lookup, "zkevm_state", 0, max_state-1);
                context_object.relative_lookup(reverted_lookup, "zkevm_state", 0, max_state-1);
                context_object.relative_lookup(revert_end_call_lookup, "zkevm_state", 0, max_state-1);
                context_object.relative_lookup(modified_items_column_lookup, "zkevm_state", 0, max_state-1);
                context_object.relative_lookup(update_parent_lookup, "zkevm_state", 0, max_state-1);
                context_object.relative_lookup(child_lookup, "zkevm_state_parent", 0, max_state-1);

                for( std::size_t i = 0; i < chunks_amount; i++){
                    chunked_16_lookups.push_back(chunks[1][i]);
                }
                chunked_16_lookups.push_back(diff[1]);
                chunked_16_lookups.push_back(padding_selector * (op[1] - op[0]));

                for( auto& constraint: every_row_constraints){
                    context_object.relative_constrain(context_object.relativize(constraint.first, -1), 0, max_state-1, constraint.second);
                }
                for( auto &constraint: non_first_row_constraints ){
                    context_object.relative_constrain(context_object.relativize(constraint.first, -1), 1, max_state-1, constraint.second);
                }
                for( auto &constraint:chunked_16_lookups ){
                    std::vector<TYPE> tmp = {context_object.relativize(constraint, -1)};
                    context_object.relative_lookup(tmp, "chunk_16_bits/full", 0, max_state-1);
                }
            }
        }
    };
}
