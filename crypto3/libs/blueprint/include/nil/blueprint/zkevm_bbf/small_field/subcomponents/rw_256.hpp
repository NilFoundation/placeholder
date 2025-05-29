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
#include <nil/blueprint/zkevm_bbf/small_field/tables/rw_256.hpp>

namespace nil::blueprint::bbf::zkevm_small_field{
    template<typename FieldType, GenerationStage stage>
    class rw_256 : public generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

    public:
        using typename generic_component<FieldType, stage>::table_params;
        using typename generic_component<FieldType,stage>::TYPE;

        using rw_256_table_type = rw_256_table<FieldType, stage>;

        using input_type = typename rw_256_table_type::input_type;

        // using value = typename FieldType::value_type;
        // using integral_type = nil::crypto3::multiprecision::big_uint<257>;

        // Chunks 7: op -- 1, id -- 2, address -- 2, rw_id -- 2;
        // Diff for each chunk has its own selector
        // Each op also has its ownn selector

        static constexpr std::size_t id_chunks_amount = 2;
        static constexpr std::size_t rw_id_chunks_amount = 2;
        static constexpr std::size_t chunks_amount = 6;
        static constexpr std::size_t op_selectors_amount = 2;

        static std::size_t get_witness_amount(){
            return  rw_256_table_type::get_witness_amount()
                + id_chunks_amount + rw_id_chunks_amount     // Additional chunks
                + chunks_amount                              // Diff selector
                + op_selectors_amount                        // Selectors for op
                + 6;
        }

        static table_params get_minimal_requirements(
            std::size_t max_rw_size,
            std::size_t instances_rw_256
        ) {
            std::size_t witness_amount = rw_256<FieldType, stage>::get_witness_amount();
            BOOST_LOG_TRIVIAL(info) << "RW circuit witness amount = " << witness_amount;
            return {
                .witnesses = witness_amount,
                .public_inputs = 0,
                .constants = 0,
                .rows = max_rw_size
            };
        }

        static void allocate_public_inputs(
            context_type &context, input_type &input, std::size_t max_rw_size, std::size_t instances_rw_256
        ) {}

        rw_256(context_type &context_object, const input_type &input,
            std::size_t max_rw_size, std::size_t instances_rw_256
        ) :generic_component<FieldType,stage>(context_object) {
            std::size_t current_column = 0;

            std::vector<std::size_t> rw_256_table_area;
            for( std::size_t i = 0; i < rw_256_table_type::get_witness_amount(); i++ ) rw_256_table_area.push_back(current_column++);
            context_type rw_256_table_ct = context_object.subcontext(rw_256_table_area,0,max_rw_size);
            rw_256_table_type t(rw_256_table_ct, input, max_rw_size);

            const std::vector<TYPE> &op = t.op;                                   // stack, call_context
            const std::vector<TYPE> &id = t.id;                                   // 2 chunks fitted in field element less than 2^25
            const std::vector<TYPE> &address = t.address;                         // < 1024
            const std::vector<TYPE> &rw_id = t.rw_id;                             // 2 chunks fitted in field element less than 2^25
            const std::vector<TYPE> &is_write = t.is_write;                       // bool
            const std::vector<std::array<TYPE, 16>> &value = t.value;             // 16 chunks
            const std::vector<TYPE> &internal_counter = t.internal_counter;       // 2  chunks fitted in field element less than 2^25
            const std::vector<TYPE> &is_filled = t.is_filled;                     // bool

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                _timeline_lookup = {
                    is_filled[1] * rw_id[1],
                    TYPE(0),
                    is_filled[1],
                    TYPE(0),
                    is_filled[1] * internal_counter[1]
                };
            }

            std::vector<TYPE> call_context_selector(max_rw_size);
            std::vector<TYPE> stack_selector(max_rw_size);

            std::vector<std::array<TYPE,chunks_amount>> diff_index_selectors(max_rw_size);
            std::vector<std::pair<TYPE, TYPE>> id_chunks(max_rw_size);
            std::vector<std::pair<TYPE, TYPE>> rw_id_chunks(max_rw_size);

            std::vector<TYPE> is_first(max_rw_size);
            std::vector<TYPE> diff(max_rw_size);
            std::vector<TYPE> inv_diff(max_rw_size);
            std::vector<TYPE> is_diff_non_zero(max_rw_size); // For lower constraints degree

            if constexpr  (stage == GenerationStage::ASSIGNMENT) {
                auto rw_trace = input;
                BOOST_ASSERT(rw_trace[0].op == rw_operation_type::start);

                std::size_t current_row = 0;

                std::array<TYPE, chunks_amount> sorted;
                std::array<TYPE, chunks_amount> sorted_prev;
                for( std::size_t i = 0; i < rw_trace.size(); i++ ){
                    if( current_row >= max_rw_size ) BOOST_LOG_TRIVIAL(fatal) << "Not enougn rows in rw_8 table";
                    BOOST_ASSERT(current_row < max_rw_size);
                    if(
                        rw_trace[i].op != rw_operation_type::start
                        && rw_trace[i].op != rw_operation_type::call_context
                        && rw_trace[i].op != rw_operation_type::stack
                    ) continue;

                    call_context_selector[current_row] = rw_trace[i].op == rw_operation_type::call_context? 1: 0;
                    stack_selector[current_row] = rw_trace[i].op == rw_operation_type::stack? 1: 0;

                    id_chunks[current_row].first = ((rw_trace[i].id & 0xFFFF0000) >> 16);
                    id_chunks[current_row].second = rw_trace[i].id & 0xFFFF;

                    rw_id_chunks[current_row].first = ((rw_trace[i].rw_counter & 0xFFFF0000) >> 16);
                    rw_id_chunks[current_row].second = rw_trace[i].rw_counter & 0xFFFF;

                    sorted_prev = sorted;
                    sorted[0] = op[current_row];
                    sorted[1] = id_chunks[current_row].first;
                    sorted[2] = id_chunks[current_row].second;
                    sorted[3] = address[current_row];
                    sorted[4] = rw_id_chunks[current_row].first;
                    sorted[5] = rw_id_chunks[current_row].second;

                    if( i != 0) {
                        std::size_t diff_ind;
                        for( diff_ind= 0; diff_ind < chunks_amount; diff_ind++ ){
                            if(sorted[diff_ind] != sorted_prev[diff_ind]) break;
                        }
                        BOOST_ASSERT(diff_ind < chunks_amount);
                        diff_index_selectors[current_row][diff_ind] = 1;

                        if( diff_ind < sorted.size() - 2){
                            is_first[current_row] = 1;
                        }

                        diff[current_row] = sorted[diff_ind] - sorted_prev[diff_ind];
                        inv_diff[current_row] = diff[current_row] == 0? 0: diff[current_row].inversed();
                        is_diff_non_zero[current_row] = diff[current_row] * inv_diff[current_row];
                    }
                    BOOST_LOG_TRIVIAL(debug)
                        << "rw_256 " << current_row
                        << ". " << rw_trace[i]
                        << " is_first = " << is_first[current_row]
                        << " internal_counter = " << internal_counter[current_row];
                    current_row ++;
                }
                is_first[current_row] = 1;
                diff_index_selectors[current_row][0] = 1;
                diff[current_row] = op[current_row] - op[current_row-1];
                inv_diff[current_row] =  diff[current_row].inversed();
                is_diff_non_zero[current_row] = 1;
            }
            for( std::size_t i = 0; i < max_rw_size; i++ ){
                std::size_t current_columm = rw_256_table_type::get_witness_amount();
                allocate(call_context_selector[i], current_columm++, i);
                allocate(stack_selector[i], current_columm++, i);
                allocate(id_chunks[i].first, current_columm++, i);
                allocate(id_chunks[i].second, current_columm++, i);
                allocate(rw_id_chunks[i].first, current_columm++, i);
                allocate(rw_id_chunks[i].second, current_columm++, i);
                allocate(is_first[i], current_columm++, i);
                allocate(diff[i], current_columm++, i);
                allocate(inv_diff[i], current_columm++, i);
                allocate(is_diff_non_zero[i], current_columm++, i);
                for( std::size_t j = 0; j < chunks_amount; j++ ){
                    allocate(diff_index_selectors[i][j], current_columm++, i);
                }
            }
            constrain(op[0] - std::size_t(rw_operation_type::start));
            constrain(internal_counter[0]);
            if constexpr  (stage == GenerationStage::CONSTRAINTS) {
                std::vector<TYPE> every_row_constraints;
                std::vector<TYPE> non_first_row_constraints;
                std::vector<TYPE> chunked_16_lookups;

                // Rw_operation_type selectors may be only 0 or 1
                every_row_constraints.push_back(call_context_selector[1] * (call_context_selector[1] - 1));
                every_row_constraints.push_back(stack_selector[1] * (stack_selector[1] - 1));

                // is_filled is sum of rw_operation_type selectors
                every_row_constraints.push_back(is_filled[1] - (
                    call_context_selector[1] + stack_selector[1]
                ));

                // is_filled is always 0 and 1, so two rw_operation_type selectors cannot be 1 simultaneously
                every_row_constraints.push_back( is_filled[1] * (is_filled[1] - 1));

                // Rw_operation_type selectors encodes op correctly.
                // First is start rw_operation_type::start and was constrained earlier
                non_first_row_constraints.push_back(op[1] - (
                    call_context_selector[1] * std::size_t(rw_operation_type::call_context) +
                    stack_selector[1] * std::size_t(rw_operation_type::stack) +
                    (1 - is_filled[1]) * std::size_t(rw_operation_type::padding)
                ));

                // id is encoded correctly
                every_row_constraints.push_back(id[1] - (id_chunks[1].first * (0x10000) + id_chunks[1].second));

                // rw_id is encoded correctly
                every_row_constraints.push_back(rw_id[1] - (rw_id_chunks[1].first * (0x10000) + rw_id_chunks[1].second));

                std::vector<TYPE> sorted_prev = {
                    op[0],
                    id_chunks[0].first,
                    id_chunks[0].second,
                    address[0],
                    rw_id_chunks[0].first,
                    rw_id_chunks[0].second
                };

                std::vector<TYPE> sorted = {
                    op[1],
                    id_chunks[1].first,
                    id_chunks[1].second,
                    address[1],
                    rw_id_chunks[1].first,
                    rw_id_chunks[1].second
                };

                TYPE diff_ind_selectors_sum;
                for( std::size_t i = 0; i < chunks_amount; i++ ){
                    // diff_ind_selector may be 0 or 1
                    every_row_constraints.push_back(diff_index_selectors[1][i] * (diff_index_selectors[1][i] - 1));
                    diff_ind_selectors_sum += diff_index_selectors[1][i];
                }
                // only one of diff_index_selectors may be 1
                every_row_constraints.push_back(diff_ind_selectors_sum * (diff_ind_selectors_sum - 1));

                // diff_index (encoded by diff_index_selector) correctness
                for( std::size_t s_ind = 0; s_ind < sorted.size() - 1; s_ind++ ){
                    TYPE eq_selector;
                    for( std::size_t d_ind = s_ind+1; d_ind < chunks_amount; d_ind++){
                        eq_selector += diff_index_selectors[1][d_ind];
                    }
                    non_first_row_constraints.push_back(eq_selector * (sorted[s_ind] - sorted_prev[s_ind]));
                    non_first_row_constraints.push_back(diff_index_selectors[1][s_ind] * (sorted[s_ind] - sorted_prev[s_ind] - diff[1]));
                }

                 // is_first is correct
                TYPE is_first_constraint;
                for( std::size_t i = 0; i < chunks_amount - 2; i++ ){
                    is_first_constraint +=  diff_index_selectors[1][i];
                }
                every_row_constraints.push_back(is_first[1] - is_first_constraint);

                // inv_diff and is_diff_non_zero are correct
                non_first_row_constraints.push_back(diff[1] * inv_diff[1] - is_diff_non_zero[1]);
                non_first_row_constraints.push_back(diff[1] * (is_diff_non_zero[1] - 1));
                non_first_row_constraints.push_back(inv_diff[1] * (is_diff_non_zero[1] - 1));

                // is_write is always 0 or 1
                every_row_constraints.push_back(is_write[1] * (is_write[1] - 1));

                // internal counter is incremented only for new item
                non_first_row_constraints.push_back(
                    is_filled[1] * (internal_counter[1] - internal_counter[0] - is_first[1])
                );

                // read-after-write constraint
                for( std::size_t i = 0; i < 16; i++ ){
                    non_first_row_constraints.push_back(
                        (1 - is_first[1]) * (1 - is_write[1]) * (value[1][i] - value[0][i])
                    );
                }

                // Situation when stack[1] and stack[3] were used, but stack[2] not is impossible
                // For call_context this mean that the whole call_context was read
                non_first_row_constraints.push_back((1-is_first[1]) * (address[1] - address[0]));

                // First operation for each stack item is W
                non_first_row_constraints.push_back(stack_selector[1] * is_first[1] * (1 - is_write[1]));

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
        std::vector<TYPE> timeline_lookup(){
            return _timeline_lookup;
        }
    protected:
        std::vector<TYPE> _timeline_lookup;
    };
}