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
#include <nil/blueprint/zkevm_bbf/big_field/subcomponents/rw_table.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/subcomponents/state_table.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/subcomponents/timeline_table.hpp>

namespace nil::blueprint::bbf::zkevm_big_field{
    template<typename FieldType, GenerationStage stage>
    class rw : public generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

    public:
        using typename generic_component<FieldType, stage>::table_params;
        using typename generic_component<FieldType,stage>::TYPE;

        using rw_table_type = rw_table<FieldType, stage>;
        using state_table_type = state_table<FieldType, stage>;
        using timeline_table_type = timeline_table<FieldType, stage>;

        struct input_type{
            typename rw_table_type::input_type rw_trace;
            typename timeline_table_type::input_type timeline;
            typename state_table_type::input_type state_trace;
        };

        using value = typename FieldType::value_type;
        using integral_type = nil::crypto3::multiprecision::big_uint<257>;

        // Chunks 7: op -- 1, id -- 2, address -- 2, rw_id -- 2;
        // Diff for each chunk has its own selector
        // Each op also has its ownn selector

        static constexpr std::size_t id_chunks_amount = 2;
        static constexpr std::size_t address_chunks_amount = 2;
        static constexpr std::size_t rw_id_chunks_amount = 2;
        static constexpr std::size_t chunks_amount = 6;
        static constexpr std::size_t op_selectors_amount = (short_rw_operation_types_amount - 1);
        static constexpr std::size_t diff_index_selectors_amount = 7;

        static table_params get_minimal_requirements(
            std::size_t max_rw_size,
            std::size_t max_state_size
        ) {
            std::size_t witness_amount = rw_table_type::get_witness_amount()
                + state_table_type::get_witness_amount()
                + timeline_table_type::get_witness_amount()
                + chunks_amount                                 // Additional chunks
                + diff_index_selectors_amount                   // Diff selector
                + op_selectors_amount                           // Selectors for op
                + 6;
            BOOST_LOG_TRIVIAL(info) << "RW circuit witness amount = " << witness_amount;
            return {
                .witnesses = witness_amount,
                .public_inputs = 0,
                .constants = 0,
                .rows = max_rw_size + max_state_size
            };
        }

        static void allocate_public_inputs(
            context_type &context, input_type &input, std::size_t max_rw_size, std::size_t max_state
        ) {}

        rw(context_type &context_object, const input_type &input,
            std::size_t max_rw_size,
            std::size_t max_state
        ) :generic_component<FieldType,stage>(context_object) {
            std::size_t START_OP = std::size_t(rw_operation_type::start);
            std::size_t STACK_OP = std::size_t(rw_operation_type::stack);
            std::size_t MEMORY_OP = std::size_t(rw_operation_type::memory);
            std::size_t CALL_CONTEXT_OP = std::size_t(rw_operation_type::call_context);
            std::size_t CALLDATA_OP = std::size_t(rw_operation_type::calldata);
            std::size_t RETURNDATA_OP = std::size_t(rw_operation_type::returndata);
            std::size_t BLOBHASH_OP = std::size_t(rw_operation_type::blobhash);
            std::size_t PADDING_OP = std::size_t(rw_operation_type::padding);

            std::size_t current_column = 0;

            std::vector<std::size_t> rw_table_area;
            for( std::size_t i = 0; i < rw_table_type::get_witness_amount(); i++ ) rw_table_area.push_back(current_column++);
            context_type rw_table_ct = context_object.subcontext(rw_table_area,0,max_rw_size);
            rw_table_type t(rw_table_ct, input.rw_trace, max_rw_size, true);

            std::vector<std::size_t> timeline_table_area;
            for( std::size_t i = 0; i < timeline_table_type::get_witness_amount(); i++ ) timeline_table_area.push_back(current_column++);
            context_type timeline_table_ct = context_object.subcontext(timeline_table_area,0,max_rw_size + max_state);
            timeline_table_type tt(timeline_table_ct, input.timeline, max_rw_size + max_state);

            std::vector<std::size_t> state_table_area;
            for( std::size_t i = 0; i < state_table_type::get_witness_amount(); i++ ) state_table_area.push_back(current_column++);
            context_type state_table_ct = context_object.subcontext(state_table_area,0,max_state);
            state_table_type st(state_table_ct, input.state_trace, max_state);

            const std::vector<TYPE> &op = t.op;
            const std::vector<TYPE> &id = t.id;
            const std::vector<TYPE> &address = t.address;
            const std::vector<TYPE> &rw_id = t.rw_id;
            const std::vector<TYPE> &is_write = t.is_write;
            const std::vector<TYPE> &value_hi = t.value_hi;
            const std::vector<TYPE> &value_lo = t.value_lo;
            const std::vector<TYPE> &internal_counter = t.internal_counter;
            const std::vector<TYPE> &is_filled = t.is_filled;

            // Allocated cells
            std::vector<std::array<TYPE,op_selectors_amount>> op_selectors(max_rw_size);
            std::vector<std::array<TYPE,diff_index_selectors_amount>> diff_index_selectors(max_rw_size);
            std::vector<std::array<TYPE,chunks_amount>> chunks(max_rw_size);

            std::vector<TYPE> is_first(max_rw_size);
            std::vector<TYPE> is_last(max_rw_size);
            std::vector<TYPE> diff(max_rw_size);
            std::vector<TYPE> inv_diff(max_rw_size);
            std::vector<TYPE> is_diff_non_zero(max_rw_size);

            // std::vector<TYPE> not_first_or_padding(max_rw_size);
            // std::vector<TYPE> firsts_diff_index_bits(max_rw_size);
            // std::vector<TYPE> last_and_not_start_or_padding(max_rw_size);
            // std::vector<TYPE> address_near(max_rw_size);
            // std::vector<TYPE> not_first_or_write(max_rw_size);
            // std::vector<TYPE> first_and_not_write(max_rw_size);

            // Temporary variables
            std::vector<TYPE> sorted;
            std::vector<TYPE> sorted_prev;

            std::map<rw_operation_type, std::size_t> op_selector_indices;
            std::size_t index = 0;
            op_selector_indices[rw_operation_type::call_context] = index++;
            op_selector_indices[rw_operation_type::stack] = index++;
            op_selector_indices[rw_operation_type::memory] = index++;
            op_selector_indices[rw_operation_type::calldata] = index++;
            op_selector_indices[rw_operation_type::returndata] = index++;
            op_selector_indices[rw_operation_type::blobhash] = index++;
            op_selector_indices[rw_operation_type::padding] = index++;

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                for(std::size_t i = 0; i < input.timeline.size(); i++){
                    BOOST_LOG_TRIVIAL(trace)
                            << "\ttime " << i
                            << " rw_id = " << input.timeline[i].rw_id << " "
                            << rw_operation_type_to_string(input.timeline[i].op)
                            << " internal_counter = " << input.timeline[i].internal_counter;
                }
                for(std::size_t i = 0; i < input.state_trace.size(); i++){
                    BOOST_LOG_TRIVIAL(trace) << "STATE " << i << " " << input.state_trace[i];
                }

                auto rw_trace = input.rw_trace;
                BOOST_LOG_TRIVIAL(trace) << "RW trace.size = " << rw_trace.size();

                for( std::size_t i = 0; i < rw_trace.size(); i++ ){
                    // First operations is always start i.e. 0
                    if( i != 0 ) op_selectors[i][op_selector_indices[rw_trace[i].op]] = 1;
                    std::size_t cur_chunk = 0;
                    // id
                    std::size_t mask = 0xffff0000;
                    chunks[i][cur_chunk++] = (mask & integral_type(rw_trace[i].id)) >> 16;
                    mask = 0xffff;
                    chunks[i][cur_chunk++] = (mask & integral_type(rw_trace[i].id));

                    // address
                    mask = 0xffff0000;
                    chunks[i][cur_chunk++] = (mask & integral_type(rw_trace[i].address)) >> 16;
                    mask = 0xffff;
                    chunks[i][cur_chunk++] = (mask & integral_type(rw_trace[i].address));

                    // rw_id
                    mask = 0xffff;
                    mask <<= 16;
                    chunks[i][cur_chunk++] = (mask & rw_trace[i].rw_counter) >> 16;
                    mask >>= 16;
                    chunks[i][cur_chunk++] = (mask & rw_trace[i].rw_counter);

                    sorted_prev = sorted;
                    sorted = {op[i]};
                    for( std::size_t j = 0; j < chunks_amount; j++ ){
                        sorted.push_back(chunks[i][j]);
                    }

                    if( i == 0) continue;
                    std::size_t diff_ind;
                    for( diff_ind= 0; diff_ind < chunks_amount; diff_ind++ ){
                        if(sorted[diff_ind] != sorted_prev[diff_ind]) break;
                    }
                    diff_index_selectors[i][diff_ind] = 1;

                    if( op[i] != START_OP && diff_ind < sorted.size() - 2){
                        is_first[i] = 1;
                        if(i != 0) is_last[i-1] = 1;
                    }
                    BOOST_LOG_TRIVIAL(debug) << i << ". " << rw_trace[i] << " is_first = " << is_first[i] << " is_last = " << is_last[i];

                    diff[i] = sorted[diff_ind] - sorted_prev[diff_ind];
                    inv_diff[i] = diff[i] == 0? 0: diff[i].inversed();
                    is_diff_non_zero[i] = diff[i] * inv_diff[i];
                }

                is_first[rw_trace.size()] = 1;
                diff_index_selectors[rw_trace.size()][0] = 1;
                diff[rw_trace.size()] = op[rw_trace.size()] - op[rw_trace.size() - 1];
                inv_diff[rw_trace.size()] = diff[rw_trace.size()] == 0? 0: diff[rw_trace.size()].inversed();
                is_diff_non_zero[rw_trace.size()] = diff[rw_trace.size()] == 0? 0 : 1;
                for( std::size_t i = rw_trace.size(); i < max_rw_size; i++ ){
                    op_selectors[i][op_selector_indices[rw_operation_type::padding]] = 1;
                }
            }

            for( std::size_t i = 0; i < max_rw_size; i++){
                std::size_t cur_column = rw_table_type::get_witness_amount() + state_table_type::get_witness_amount() + timeline_table_type::get_witness_amount();
                for( std::size_t j = 0; j < op_selectors_amount; j++){
                    allocate(op_selectors[i][j], ++cur_column, i);
                };
                for( std::size_t k = 0; k < chunks_amount; k++){
                    allocate(chunks[i][k], ++cur_column, i);
                }
                for( std::size_t j = 0; j < diff_index_selectors_amount; j++){
                    allocate(diff_index_selectors[i][j], ++cur_column, i);
                }
                allocate(diff[i], ++cur_column, i);
                allocate(inv_diff[i], ++cur_column, i);
                allocate(is_diff_non_zero[i], ++cur_column, i);
                allocate(is_first[i], ++cur_column, i);
                allocate(is_last[i], ++cur_column, i);
            }

            constrain(op[0] - START_OP);
            constrain(internal_counter[0]);
            constrain(tt.internal_counter[0]);

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                std::vector<TYPE> every_row_constraints;
                std::vector<TYPE> non_first_row_constraints;
                std::vector<TYPE> chunked_16_lookups;

                // Fill sorted and sorted_prev arrays
                sorted.push_back(op[1]);
                sorted_prev.push_back(op[0]);
                chunked_16_lookups.push_back(diff[1]);
                for( std::size_t j = 0; j < chunks_amount; j++ ){
                    chunked_16_lookups.push_back(chunks[1][j]);
                    sorted.push_back(chunks[1][j]);
                    sorted_prev.push_back(chunks[0][j]);
                }

                TYPE op_constraint;
                TYPE op_selectors_sum;
                BOOST_ASSERT(op_selector_indices.size() == op_selectors_amount);

                for( auto &[k,v]:op_selector_indices){
                    op_constraint += op_selectors[1][v] * TYPE(std::size_t(k));
                }
                for( std::size_t j = 0; j < op_selectors_amount; j++ ){
                    op_selectors_sum += op_selectors[1][j];
                    every_row_constraints.push_back(op_selectors[1][j] * (op_selectors[1][j] - 1));
                }
                non_first_row_constraints.push_back(op_selectors_sum - 1); // Start selector is busy
                every_row_constraints.push_back(op_constraint - op[1]);

                TYPE diff_ind_selectors_sum;
                for( std::size_t j = 0; j < diff_index_selectors_amount; j++){
                    diff_ind_selectors_sum += diff_index_selectors[1][j];
                    non_first_row_constraints.push_back(diff_index_selectors[1][j] * (diff_index_selectors[1][j] - 1));
                }
                non_first_row_constraints.push_back(diff_ind_selectors_sum * (diff_ind_selectors_sum - 1));

                TYPE non_rw_counter_diff_ind_selectors_sum;
                for(std::size_t j = 0; j < diff_index_selectors_amount-2; j++){
                    non_rw_counter_diff_ind_selectors_sum += diff_index_selectors[1][j];
                }

                for( std::size_t s_ind = 0; s_ind < sorted.size() - 1; s_ind++ ){
                    TYPE eq_selector;
                    for( std::size_t d_ind = s_ind+1; d_ind < diff_index_selectors_amount; d_ind++){
                        eq_selector += diff_index_selectors[1][d_ind];
                    }
                    non_first_row_constraints.push_back(eq_selector * (sorted[s_ind] - sorted_prev[s_ind]));
                    non_first_row_constraints.push_back(diff_index_selectors[1][s_ind] * (sorted[s_ind] - sorted_prev[s_ind] - diff[1]));
                }

                TYPE is_first_constraint;
                for( std::size_t j = 0; j < sorted.size() - 2; j++){
                    is_first_constraint += diff_index_selectors[1][j];
                }
                non_first_row_constraints.push_back(is_last[1] * (1 - is_first[2]));
                non_first_row_constraints.push_back(is_first[1] - is_first_constraint);
                non_first_row_constraints.push_back(diff[1] * inv_diff[1] - is_diff_non_zero[1]);
                non_first_row_constraints.push_back(diff[1] * (is_diff_non_zero[1] - 1));
                non_first_row_constraints.push_back(inv_diff[1] * (is_diff_non_zero[1] - 1));

                TYPE id_composition;
                std::size_t cur_chunk = 0;
                id_composition = chunks[1][cur_chunk++]; id_composition *= (1<<16);
                id_composition += chunks[1][cur_chunk++];
                every_row_constraints.push_back(id[1] - id_composition);

                TYPE addr_composition;
                addr_composition = chunks[1][cur_chunk++]; addr_composition *= (1<<16);
                addr_composition += chunks[1][cur_chunk++];
                every_row_constraints.push_back(address[1] - addr_composition);

                TYPE rw_id_composition;
                rw_id_composition = chunks[1][cur_chunk++]; rw_id_composition *= (1<<16);
                rw_id_composition += chunks[1][cur_chunk++];
                every_row_constraints.push_back(rw_id[1] - rw_id_composition);

                every_row_constraints.push_back(is_write[1] * (is_write[1]-1));
                every_row_constraints.push_back(is_first[1] * (is_first[1]-1));
                every_row_constraints.push_back(is_last[1] * (is_last[1] - 1));

                // Degree 3 may be lowered by one additional column
                non_first_row_constraints.push_back((1 - is_first[1] ) * (1 - is_write[1]) * (value_hi[1] - value_hi[0]));
                non_first_row_constraints.push_back((1 - is_first[1] ) * (1 - is_write[1]) * (value_lo[1] - value_lo[0]));

                // TYPE start_selector; // Not used
                TYPE call_context_selector = op_selectors[1][op_selector_indices[rw_operation_type::call_context]];
                TYPE stack_selector = op_selectors[1][op_selector_indices[rw_operation_type::stack]];
                TYPE memory_selector = op_selectors[1][op_selector_indices[rw_operation_type::memory]];
                TYPE calldata_selector = op_selectors[1][op_selector_indices[rw_operation_type::calldata]];
                TYPE returndata_selector = op_selectors[1][op_selector_indices[rw_operation_type::returndata]];
                TYPE blobhash_selector = op_selectors[1][op_selector_indices[rw_operation_type::blobhash]];
                TYPE padding_selector = op_selectors[1][op_selector_indices[rw_operation_type::padding]];

                every_row_constraints.push_back(is_filled[1] - (calldata_selector + returndata_selector + memory_selector + stack_selector + call_context_selector + blobhash_selector));
                every_row_constraints.push_back((calldata_selector + returndata_selector) *  is_write[1] * (1 - is_first[1]) );
                every_row_constraints.push_back(is_write[1] *(blobhash_selector + padding_selector));
                non_first_row_constraints.push_back((1 - padding_selector) * (1 - is_diff_non_zero[1]));
                every_row_constraints.push_back(value_hi[1] *(calldata_selector + returndata_selector + memory_selector + padding_selector));

                chunked_16_lookups.push_back(value_lo[1] * (calldata_selector + returndata_selector + memory_selector));
                chunked_16_lookups.push_back((255 - value_lo[1]) * (calldata_selector + returndata_selector + memory_selector));
                chunked_16_lookups.push_back(stack_selector * address[1]);
                chunked_16_lookups.push_back(stack_selector * (1024 - address[1]));

                non_first_row_constraints.push_back(stack_selector * (1 - is_first[1]) * (address[1] - address[0]) * (address[1] - address[0] - 1));
                non_first_row_constraints.push_back((memory_selector + calldata_selector + returndata_selector) * is_first[1] * (1 - is_write[1]) * value_lo[1]);
                non_first_row_constraints.push_back(is_filled[1] * (internal_counter[1] - internal_counter[0] - non_rw_counter_diff_ind_selectors_sum));

                non_first_row_constraints.push_back(tt.rw_table_selector[1] * (tt.rw_table_selector[1] - 1));
                non_first_row_constraints.push_back(tt.state_table_selector[1] * (tt.state_table_selector[1] - 1));
                non_first_row_constraints.push_back((tt.state_table_selector[1] + tt.rw_table_selector[1] - 1) * (tt.state_table_selector[1] + tt.rw_table_selector[1]));
                non_first_row_constraints.push_back(
                    (1 - tt.state_table_selector[1] - tt.rw_table_selector[1]) *
                    (tt.state_table_selector[2] + tt.rw_table_selector[2])
                );
                non_first_row_constraints.push_back((tt.state_table_selector[1] + tt.rw_table_selector[1]) * (tt.rw_id[1] - tt.rw_id[0] - 1));

                context_object.relative_lookup({
                    context_object.relativize(tt.rw_table_selector[1], -1),
                    context_object.relativize(tt.rw_table_selector[1] * tt.rw_id[1], -1),
                    context_object.relativize(tt.rw_table_selector[1] * tt.internal_counter[1], -1)
                }, "zkevm_rw_timeline", 0, max_rw_size + max_state - 1);

                context_object.relative_lookup({
                    context_object.relativize(tt.state_table_selector[1], -1),
                    context_object.relativize(tt.state_table_selector[1] * tt.rw_id[1], -1),
                    context_object.relativize(tt.state_table_selector[1] * tt.internal_counter[1], -1)
                }, "zkevm_state_timeline", 0, max_rw_size + max_state - 1);

                context_object.relative_lookup({
                    context_object.relativize(is_filled[1] * rw_id[1], -1),
                    context_object.relativize(is_filled[1], -1),
                    context_object.relativize(TYPE(0), -1),
                    context_object.relativize(is_filled[1] * internal_counter[1], -1)
                }, "zkevm_timeline", 0, max_rw_size-1);

                context_object.relative_lookup({
                    context_object.relativize(st.is_original[1] * st.rw_id[1], -1),
                    context_object.relativize(TYPE(0), -1),
                    context_object.relativize(st.is_original[1], -1),
                    context_object.relativize(st.is_original[1] * st.internal_counter[1], -1)
                }, "zkevm_timeline", 0, max_state-1);

                for( auto& constraint: every_row_constraints){
                    context_object.relative_constrain(context_object.relativize(constraint, -1), 0, max_rw_size-1);
                }
                for( auto &constraint:chunked_16_lookups ){
                    std::vector<TYPE> tmp = {context_object.relativize(constraint, -1)};
                    context_object.relative_lookup(tmp, "chunk_16_bits/full", 0, max_rw_size-1);
                }
                for( auto &constraint: non_first_row_constraints ){
                    context_object.relative_constrain(context_object.relativize(constraint, -1), 1, max_rw_size - 1);
                }
            }
        }
    };
}