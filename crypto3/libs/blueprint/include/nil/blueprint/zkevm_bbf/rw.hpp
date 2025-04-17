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
#include <nil/blueprint/zkevm_bbf/subcomponents/rw_table.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/call_commit_table.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
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
                using call_commit_table_type = call_commit_table<FieldType, stage>;

                struct input_type{
                    template<typename T>
                    using enable_for_assignment_t = typename std::conditional_t<stage == GenerationStage::ASSIGNMENT, T, std::nullptr_t>;

                    enable_for_assignment_t<rw_operations_vector> rw_operations;
                    // call_id => {first write operations for given CALL including subcalls including reverted subcalls}
                    enable_for_assignment_t<std::map<std::size_t, zkevm_call_commit>> call_commits;
                };

                using value = typename FieldType::value_type;
                using integral_type = nil::crypto3::multiprecision::big_uint<257>;

                static constexpr std::size_t op_bits_amount = 4;
                static constexpr std::size_t diff_index_bits_amount = 5;

                static constexpr std::size_t id_chunks_amount = 2;
                static constexpr std::size_t address_chunks_amount = 10;
                static constexpr std::size_t storage_key_chunks_amount = 16;
                static constexpr std::size_t rw_id_chunks_amount = 2;
                static constexpr std::size_t chunks_amount = 30;

                static table_params get_minimal_requirements(
                    std::size_t max_rw_size,
                    std::size_t max_mpt_size,
                    std::size_t max_call_commits
                ) {
                    return {
                        .witnesses = rw_table_type::get_witness_amount() + call_commit_table_type::get_witness_amount() + 50,
                        .public_inputs = 0,
                        .constants = 2,
                        .rows = std::max(max_rw_size, max_call_commits) + max_mpt_size
                    };
                }

                static void allocate_public_inputs(
                    context_type &context, input_type &input,
                    std::size_t max_rw_size, std::size_t max_mpt_size, std::size_t max_call_commits
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

                rw(context_type &context_object, const input_type &input,
                    std::size_t max_rw_size,
                    std::size_t max_mpt_size,
                    std::size_t max_call_commits
                ) :generic_component<FieldType,stage>(context_object) {
                    std::size_t START_OP = rw_op_to_num(rw_operation_type::start);
                    std::size_t STACK_OP = rw_op_to_num(rw_operation_type::stack);
                    std::size_t MEMORY_OP = rw_op_to_num(rw_operation_type::memory);
                    std::size_t STATE_OP = rw_op_to_num(rw_operation_type::state);
                    std::size_t TRANSIENT_STORAGE_OP = rw_op_to_num(rw_operation_type::transient_storage);
                    std::size_t CALL_CONTEXT_OP = rw_op_to_num(rw_operation_type::call_context);
                    std::size_t ACCESS_LIST_OP = rw_op_to_num(rw_operation_type::access_list);
                    // std::size_t TX_REFUND_OP = rw_op_to_num(rw_operation_type::tx_refund);
                    // std::size_t TX_LOG_OP = rw_op_to_num(rw_operation_type::tx_log);
                    // std::size_t TX_RECEIPT_OP = rw_op_to_num(rw_operation_type::tx_receipt);
                    std::size_t PADDING_OP = rw_op_to_num(rw_operation_type::padding);

                    PROFILE_SCOPE("Rw circuit constructor, total time");
                    std::vector<std::size_t> rw_table_area;
                    for( std::size_t i = 0; i < rw_table_type::get_witness_amount(); i++ ) rw_table_area.push_back(i);

                    std::vector<std::size_t> call_commit_table_area;
                    for( std::size_t i = rw_table_type::get_witness_amount(); i < rw_table_type::get_witness_amount() + call_commit_table_type::get_witness_amount(); i++ ) call_commit_table_area.push_back(i);

                    context_type rw_table_ct = context_object.subcontext(rw_table_area,0,max_rw_size);
                    rw_table_type t(rw_table_ct, input.rw_operations, max_rw_size, true);

                    context_type call_commit_table_ct = context_object.subcontext(call_commit_table_area,0,max_call_commits);
                    call_commit_table_type ct(call_commit_table_ct, input.call_commits, max_call_commits);

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
                    const std::vector<TYPE> &value_before_hi = t.value_before_hi;
                    const std::vector<TYPE> &value_before_lo = t.value_before_lo;
                    const std::vector<TYPE> &call_id = t.call_id;
                    const std::vector<TYPE> &w_id_before = t.w_id_before;

                    // Allocated cells
                    std::vector<std::array<TYPE,op_bits_amount>> op_bits(max_rw_size);
                    std::vector<std::array<TYPE,diff_index_bits_amount>> diff_index_bits(max_rw_size);
                    std::vector<TYPE> is_first(max_rw_size);
                    std::vector<std::array<TYPE,chunks_amount>> chunks(max_rw_size);
                    std::vector<TYPE> diff(max_rw_size);
                    std::vector<TYPE> inv_diff(max_rw_size);
                    std::vector<TYPE> initial_value_hi(max_rw_size);
                    std::vector<TYPE> initial_value_lo(max_rw_size);
                    std::vector<TYPE> state_root_hi(max_rw_size);
                    std::vector<TYPE> state_root_lo(max_rw_size);
                    std::vector<TYPE> state_root_before_hi(max_rw_size);
                    std::vector<TYPE> state_root_before_lo(max_rw_size);
                    std::vector<TYPE> is_last(max_rw_size);
                    // Temporary variables
                    std::vector<TYPE> sorted;
                    std::vector<TYPE> sorted_prev;

                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        auto rw_trace = input.rw_operations;
                        std::cout << "RW trace.size = " << rw_trace.size() << std::endl;
                        for( std::size_t i = 0; i < rw_trace.size(); i++ ){
                            // if( rw_trace[i].op != rw_operation_type::padding )
                            //    std::cout << "\t" << i << "." << rw_trace[i];

                            integral_type mask = (1 << op_bits_amount);
                            for( std::size_t j = 0; j < op_bits_amount; j++){
                                mask >>= 1;
                                op_bits[i][j] = (((static_cast<unsigned>(rw_trace[i].op) & mask) == 0) ? 0 : 1);
                            }
                            std::size_t cur_chunk = 0;
                            // id
                            mask = 0xffff0000;
                            chunks[i][cur_chunk++] = (mask & integral_type(rw_trace[i].id)) >> 16;
                            mask = 0xffff;
                            chunks[i][cur_chunk++] = (mask & integral_type(rw_trace[i].id));

                            // address
                            mask = 0xffff;
                            mask <<= (16 * 9);
                            for( std::size_t j = 0; j < address_chunks_amount; j++){
                                chunks[i][cur_chunk++] = (((mask & integral_type(rw_trace[i].address)) >> (16 * (9-j))));
                                mask >>= 16;
                            }

                            // storage_key
                            mask = 0xffff;
                            mask <<= (16 * 15);
                            for( std::size_t j = 0; j < storage_key_chunks_amount; j++){
                                chunks[i][cur_chunk++] = (((mask & integral_type(rw_trace[i].storage_key)) >> (16 * (15-j))));
                                mask >>= 16;
                            }

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
                                if( j == 12 ) sorted.push_back(field_type[i]);
                            }

                            if( i == 0) continue;
                            std::size_t diff_ind;
                            for( diff_ind= 0; diff_ind < chunks_amount; diff_ind++ ){
                                if(sorted[diff_ind] != sorted_prev[diff_ind]) break;
                            }
                            if( op[i] != START_OP && op[i] != PADDING_OP && diff_ind < 30){
                                is_first[i] = 1;
                                if(i != 0) is_last[i-1] = 1;
                            }
                            // std::cout << " is_first = " << is_first[i];
                            // std::cout << " w_id_before = " << w_id_before[i];

                            initial_value_hi[i] = w_hi<FieldType>(rw_trace[i].initial_value);
                            initial_value_lo[i] = w_lo<FieldType>(rw_trace[i].initial_value);
                            mask = (1 << diff_index_bits_amount);
                            for( std::size_t j = 0; j < diff_index_bits_amount; j++){
                                mask >>= 1;
                                diff_index_bits[i][j] = (((diff_ind & mask) == 0) ? 0 : 1);
                            }
                            diff[i] = sorted[diff_ind] - sorted_prev[diff_ind];
                            inv_diff[i] = diff[i] == 0? 0: diff[i].inversed();
                            // std::cout << std::endl;
                        }
                        for( std::size_t i = rw_trace.size(); i < max_rw_size; i++ ){
                            integral_type mask = (1 << op_bits_amount);
                            for( std::size_t j = 0; j < op_bits_amount; j++){
                                mask >>= 1;
                                op_bits[i][j] = (((PADDING_OP & mask) == 0) ? 0 : 1);
                            }
                        }
                    }
                    for( std::size_t i = 0; i < max_rw_size; i++){
                        if( i % 20 == 0)  std::cout << "."; std::cout.flush();
                        std::size_t cur_column = rw_table_type::get_witness_amount() + call_commit_table_type::get_witness_amount();
                        for( std::size_t j = 0; j < op_bits_amount; j++){
                            allocate(op_bits[i][j], ++cur_column, i);
                        };

                        for( std::size_t k = 0; k < chunks_amount; k++){
                            allocate(chunks[i][k], ++cur_column, i);
                        }
                        for( std::size_t j = 0; j < diff_index_bits_amount; j++){
                            allocate(diff_index_bits[i][j], ++cur_column, i);
                        }
                        allocate(initial_value_hi[i], ++cur_column, i);
                        allocate(initial_value_lo[i], ++cur_column, i);
                        allocate(diff[i], ++cur_column, i); lookup(diff[i], "chunk_16_bits/full");
                        allocate(inv_diff[i], ++cur_column, i);
                        allocate(is_first[i], ++cur_column, i);
                        allocate(is_last[i], ++cur_column, i);
                        allocate(state_root_hi[i], ++cur_column, i);
                        allocate(state_root_lo[i], ++cur_column, i);
                        allocate(state_root_before_hi[i], ++cur_column, i);
                        allocate(state_root_before_lo[i], ++cur_column, i);
                    }
                    std::cout << std::endl;
                    if constexpr (stage == GenerationStage::CONSTRAINTS) {
                        std::vector<TYPE> every_row_constraints;
                        std::vector<TYPE> non_first_row_constraints;
                        std::vector<TYPE> chunked_16_lookups;
                        for( std::size_t j = 0; j < diff_index_bits_amount; j++){
                            every_row_constraints.push_back(context_object.relativize(diff_index_bits[1][j] * (diff_index_bits[1][j] - 1), -1));
                        }
                        for( std::size_t k = 0; k < chunks_amount; k++){
                            chunked_16_lookups.push_back(context_object.relativize(chunks[1][k], -1));
                        }
                        TYPE op_bit_composition;
                        for( std::size_t j = 0; j < op_bits_amount; j++){
                            every_row_constraints.push_back(context_object.relativize(op_bits[1][j] * (op_bits[1][j] - 1), -1));
                            if(j == 0) {
                                op_bit_composition = op_bits[1][j];
                            } else {
                                op_bit_composition *= 2;
                                op_bit_composition += op_bits[1][j];
                            }
                        }
                        every_row_constraints.push_back(context_object.relativize(op_bit_composition - op[1], -1));

                        TYPE id_composition;
                        std::size_t cur_chunk = 0;
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

                        sorted_prev = {op[0]};
                        sorted = {op[1]};
                        for( std::size_t j = 0; j < chunks_amount; j++ ){
                            sorted_prev.push_back(chunks[0][j]);
                            sorted.push_back(chunks[1][j]);
                            if( j == 12 ) {
                                sorted_prev.push_back(field_type[0]);
                                sorted.push_back(field_type[1]);
                            }
                        }

                        TYPE start_selector = bit_tag_selector(op_bits[1], START_OP);
                        TYPE stack_selector = bit_tag_selector(op_bits[1], STACK_OP);
                        TYPE memory_selector = bit_tag_selector(op_bits[1], MEMORY_OP);
                        TYPE state_selector = bit_tag_selector(op_bits[1], STATE_OP);
                        TYPE transient_storage_selector = bit_tag_selector(op_bits[1], TRANSIENT_STORAGE_OP);
                        TYPE call_context_selector = bit_tag_selector(op_bits[1], CALL_CONTEXT_OP);
                        TYPE access_list_selector = bit_tag_selector(op_bits[1], ACCESS_LIST_OP);
                        TYPE padding_selector = bit_tag_selector(op_bits[1], PADDING_OP);

                        for( std::size_t diff_ind = 0; diff_ind < sorted.size(); diff_ind++ ){
                            TYPE diff_ind_selector = bit_tag_selector<diff_index_bits_amount>(diff_index_bits[1], diff_ind);
                            for(std::size_t less_diff_ind = 0; less_diff_ind < diff_ind; less_diff_ind++){
                                non_first_row_constraints.push_back(context_object.relativize((op[1] - PADDING_OP) * diff_ind_selector * (sorted[less_diff_ind]-sorted_prev[less_diff_ind]),-1));
                            }
                            non_first_row_constraints.push_back( context_object.relativize((op[1] - PADDING_OP) * diff_ind_selector * (sorted[diff_ind] - sorted_prev[diff_ind] - diff[1]), -1));
                        }

                        every_row_constraints.push_back(context_object.relativize(is_write[1] * (is_write[1]-1), -1));
                        every_row_constraints.push_back(context_object.relativize(is_first[1] * (is_first[1]-1), -1));
                        every_row_constraints.push_back(context_object.relativize(is_last[1] * (is_last[1] - 1), -1));
                        // every_row_constraints.push_back(context_object.relativize(is_first_for_id[1] * (is_first_for_id[1] - 1), -1));
                        // every_row_constraints.push_back(context_object.relativize(is_last_for_id[1] * (is_last_for_id[1] - 1), -1));

                        every_row_constraints.push_back(context_object.relativize((diff[1] * inv_diff[1] - 1) * diff[1], -1));
                        every_row_constraints.push_back(context_object.relativize((diff[1] * inv_diff[1] - 1) * inv_diff[1], -1));

                        every_row_constraints.push_back(context_object.relativize((op[1] - START_OP) * (op[1] - PADDING_OP) * (is_first[1] - 1) * (diff_index_bits[1][0] - 1), -1));
                        every_row_constraints.push_back(context_object.relativize((op[1] - START_OP) * (op[1] - PADDING_OP) * (is_first[1] - 1) * (diff_index_bits[1][1] - 1), -1));
                        every_row_constraints.push_back(context_object.relativize((op[1] - START_OP) * (op[1] - PADDING_OP) * (is_first[1] - 1) * (diff_index_bits[1][2] - 1), -1));
                        every_row_constraints.push_back(context_object.relativize((op[1] - START_OP) * (op[1] - PADDING_OP) * (is_first[1] - 1) * (diff_index_bits[1][3] - 1), -1));
                        every_row_constraints.push_back(context_object.relativize(diff_index_bits[1][0] * diff_index_bits[1][1] * diff_index_bits[1][2] * diff_index_bits[1][3] * is_first[1], -1));
                        non_first_row_constraints.push_back(context_object.relativize(is_last[0] * (1 - is_first[1]) * (op[1] - PADDING_OP), -1));
                        // non_first_row_constraints.push_back(context_object.relativize(is_last_for_id[0] * (1 - is_first_for_id[1]) * (op[1] - PADDING_OP), -1));
                        non_first_row_constraints.push_back(context_object.relativize((1 - is_last[0]) * is_first[1] * (op[0] - START_OP), -1));
                        // non_first_row_constraints.push_back(context_object.relativize((1 - is_last_for_id[0]) * is_first_for_id[1] * (op[0] - START_OP), -1));

                        // every_row_constraints.push_back(context_object.relativize((op[1] - START_OP) * (op[1] - PADDING_OP) * is_first_for_id[1] * diff_index_bits[1][0], -1));
                        // every_row_constraints.push_back(context_object.relativize((op[1] - START_OP) * (op[1] - PADDING_OP) * is_first_for_id[1] * diff_index_bits[1][1], -1));
                        // every_row_constraints.push_back(context_object.relativize((op[1] - START_OP) * (op[1] - PADDING_OP) * is_first_for_id[1] * diff_index_bits[1][2], -1));
                        // every_row_constraints.push_back(context_object.relativize((op[1] - START_OP) * (op[1] - PADDING_OP) * is_first_for_id[1] * diff_index_bits[1][3] *  diff_index_bits[1][4], -1));
                        // every_row_constraints.push_back(context_object.relativize(
                        //     (op[1] - START_OP) * (op[1] - PADDING_OP) *
                        //     (1 - is_first_for_id[1]) *
                        //     (1 - diff_index_bits[1][0]) *
                        //     (1 - diff_index_bits[1][1]) *
                        //     (1 - diff_index_bits[1][2]) *
                        //     (2 - diff_index_bits[1][3] - diff_index_bits[1][4])
                        // , -1));
                        // every_row_constraints.push_back(context_object.relativize(
                        //     (op[1] - START_OP) * (op[1] - PADDING_OP) * (1 - is_first_for_id[1]) *
                        //     (4 - diff_index_bits[1][0]  - diff_index_bits[1][1] - diff_index_bits[1][2] - diff_index_bits[1][3]*diff_index_bits[1][4]))
                        // ));

                        non_first_row_constraints.push_back(context_object.relativize((op[0] - START_OP) * (op[0] - PADDING_OP)
                            * is_last[0] * diff_index_bits[1][0]
                            * diff_index_bits[1][1] * diff_index_bits[1][2]
                            * diff_index_bits[1][3], -1));
                        non_first_row_constraints.push_back(context_object.relativize(
                            (1 - padding_selector) * (is_first[1] - 1) * (1 - is_write[1]) * (value_hi[1] - value_hi[0]), -1)
                        );
                        non_first_row_constraints.push_back(context_object.relativize(
                            (1 - padding_selector) * (is_first[1] - 1) * (1 - is_write[1]) * (value_lo[1] - value_lo[0]), -1)
                        );
                        every_row_constraints.push_back(context_object.relativize((op[1] - START_OP) * (op[1] - PADDING_OP) * (is_first[1] - 1) * (initial_value_hi[1] - initial_value_hi[0]), -1));
                        every_row_constraints.push_back(context_object.relativize((op[1] - START_OP) * (op[1] - PADDING_OP) * (is_first[1] - 1) * (initial_value_lo[1] - initial_value_lo[0]), -1));
    //                     // Specific constraints for START
                        std::map<std::size_t, std::vector<TYPE>> special_constraints;
                        special_constraints[START_OP].push_back(context_object.relativize(start_selector * storage_key_hi[1], -1));
                        special_constraints[START_OP].push_back(context_object.relativize(start_selector * storage_key_lo[1], -1));
                        special_constraints[START_OP].push_back(context_object.relativize(start_selector * id[1], -1));
                        special_constraints[START_OP].push_back(context_object.relativize(start_selector * address[1], -1));
                        special_constraints[START_OP].push_back(context_object.relativize(start_selector * field_type[1], -1));
                        special_constraints[START_OP].push_back(context_object.relativize(start_selector * rw_id[1], -1));
                        special_constraints[START_OP].push_back(context_object.relativize(start_selector * initial_value_hi[1], -1));
                        special_constraints[START_OP].push_back(context_object.relativize(start_selector * initial_value_lo[1], -1));
                        special_constraints[START_OP].push_back(context_object.relativize(start_selector * state_root_hi[1], -1));
                        special_constraints[START_OP].push_back(context_object.relativize(start_selector * state_root_lo[1], -1));
                        special_constraints[START_OP].push_back(context_object.relativize(start_selector * state_root_before_hi[1], -1));
                        special_constraints[START_OP].push_back(context_object.relativize(start_selector * state_root_before_lo[1], -1));

                        // Specific constraints for STACK
                        special_constraints[STACK_OP].push_back(context_object.relativize(stack_selector * field_type[1], -1));
                        special_constraints[STACK_OP].push_back(context_object.relativize(stack_selector * is_first[1] * (1 - is_write[1]), -1));  // 4. First stack operation is obviously write
                        //if(i!=0) {
                            non_first_row_constraints.push_back(context_object.relativize(stack_selector * (address[1] - address[0]) * (is_write[1] - 1), -1));                  // 5. First operation is always write
                            non_first_row_constraints.push_back(context_object.relativize(stack_selector * (1 - is_first[1]) * (address[1] - address[0]) * (address[1] - address[0] - 1), -1));      // 6. Stack pointer always grows and only by one
                            non_first_row_constraints.push_back(context_object.relativize(stack_selector * (1 - is_first[1]) * (state_root_hi[1] - state_root_before_hi[0]), -1));
                            non_first_row_constraints.push_back(context_object.relativize(stack_selector * (1 - is_first[1]) * (state_root_lo[1] - state_root_before_lo[0]), -1));
                        //}
                        special_constraints[STACK_OP].push_back(context_object.relativize(stack_selector * storage_key_hi[1], -1));
                        special_constraints[STACK_OP].push_back(context_object.relativize(stack_selector * storage_key_lo[1], -1));
                        special_constraints[STACK_OP].push_back(context_object.relativize(stack_selector * initial_value_hi[1], -1));
                        special_constraints[STACK_OP].push_back(context_object.relativize(stack_selector * initial_value_lo[1], -1));
                        chunked_16_lookups.push_back(context_object.relativize(stack_selector * address[1], -1));
                        chunked_16_lookups.push_back(context_object.relativize(1023 - stack_selector * address[1], -1));

                        // Specific constraints for MEMORY
                        // address is 32 bit
                        //if( i != 0 )
                            non_first_row_constraints.push_back(context_object.relativize(memory_selector * (is_first[1] - 1) * (is_write[1] - 1) * (value_lo[1] - value_lo[0]), -1));       // 4. for read operations value is equal to previous value
                        special_constraints[MEMORY_OP].push_back(context_object.relativize(memory_selector * value_hi[1], -1));
                        special_constraints[MEMORY_OP].push_back(context_object.relativize(memory_selector * is_first[1] * (is_write[1] - 1) * value_lo[1], -1));
                        special_constraints[MEMORY_OP].push_back(context_object.relativize(memory_selector * field_type[1], -1));
                        special_constraints[MEMORY_OP].push_back(context_object.relativize(memory_selector * storage_key_hi[1], -1));
                        special_constraints[MEMORY_OP].push_back(context_object.relativize(memory_selector * storage_key_lo[1], -1));
                        special_constraints[MEMORY_OP].push_back(context_object.relativize(memory_selector * initial_value_hi[1], -1));
                        special_constraints[MEMORY_OP].push_back(context_object.relativize(memory_selector * initial_value_lo[1], -1));
                        special_constraints[MEMORY_OP].push_back(context_object.relativize(memory_selector * (1 - is_first[1]) * (state_root_hi[1] - state_root_before_hi[1]), -1));
                        special_constraints[MEMORY_OP].push_back(context_object.relativize(memory_selector * (1 - is_first[1]) * (state_root_lo[1] - state_root_before_lo[1]), -1));
                        chunked_16_lookups.push_back(context_object.relativize(memory_selector * value_lo[1], -1));
                        chunked_16_lookups.push_back(context_object.relativize(255 - memory_selector * value_lo[1], -1));

                        // Specific constraints for STATE
                        // lookup to MPT circuit
                        // if field is not 0 then is account state change storage key is 0
                        special_constraints[STATE_OP].push_back(context_object.relativize(state_selector * storage_key_hi[1] * field_type[1], -1));
                        special_constraints[STATE_OP].push_back(context_object.relativize(state_selector * storage_key_lo[1] * field_type[1], -1));
                        non_first_row_constraints.push_back(context_object.relativize(
                            (state_selector + access_list_selector) * (1 - is_first[1]) * (value_hi[0] - value_before_hi[1]), -1
                        ));
                        non_first_row_constraints.push_back(context_object.relativize(
                            (state_selector + access_list_selector) * (1 - is_first[1]) * (value_lo[0] - value_before_lo[1]), -1
                        ));
                        non_first_row_constraints.push_back(context_object.relativize(
                            (state_selector + access_list_selector) * is_first[1] * (value_before_hi[1] - initial_value_hi[1]), -1
                        ));
                        non_first_row_constraints.push_back(context_object.relativize(
                            (state_selector + access_list_selector) * is_first[1] * (value_before_lo[1] - initial_value_lo[1]), -1
                        ));
                        non_first_row_constraints.push_back(context_object.relativize(
                            (state_selector + access_list_selector) * (1 - is_first[1]) * is_write[0] * (w_id_before[1] - rw_id[0]), -1)
                        );
                        non_first_row_constraints.push_back(context_object.relativize(
                            (state_selector + access_list_selector) * (1 - is_first[1]) * (1 - is_write[0]) * (w_id_before[1] - w_id_before[0]), -1)
                        );
                        // Each modified state item for a given call is presented in call_commit table for this call
                        std::vector<TYPE> write_items_lookup = {
                            call_id[1], op[1], id[1], address[1], field_type[1], storage_key_hi[1], storage_key_lo[1]
                        };
                        for( std::size_t j = 0; j < write_items_lookup.size(); j++){
                            write_items_lookup[j] = context_object.relativize(
                                (state_selector + access_list_selector) * is_write[1] * write_items_lookup[j], -1
                            );
                        }
                        context_object.relative_lookup( write_items_lookup, "zkevm_call_commit_items", 1, max_rw_size-1 );
                        //lookup_constrain({"MPT table", {
                        //    state_selector * addr,
                        //    state_selector * field,
                        //    state_selector * storage_key_hi,
                        //    state_selector * storage_key_lo,
                        //    state_selector * initial_value_hi,
                        //    state_selector * initial_value_lo,
                        //    state_selector * value_hi,
                        //    state_selector * value_lo,
                        //    state_selector * state_root_hi,
                        //    state_selector * state_root_lo
                        //}});

                        // Specific constraints for TRANSIENT_STORAGE
                        // field is 0
                        special_constraints[TRANSIENT_STORAGE_OP].push_back(context_object.relativize(transient_storage_selector * field_type[1], -1));

                        // Specific constraints for CALL_CONTEXT
                        // address, storage_key, initial_value, value_prev are 0
                        // state_root = state_root_prev
                        // range_check for field_flag
                        special_constraints[CALL_CONTEXT_OP].push_back(context_object.relativize(call_context_selector * address[1], -1));
                        special_constraints[CALL_CONTEXT_OP].push_back(context_object.relativize(call_context_selector * storage_key_hi[1], -1));
                        special_constraints[CALL_CONTEXT_OP].push_back(context_object.relativize(call_context_selector * storage_key_lo[1], -1));
                        special_constraints[CALL_CONTEXT_OP].push_back(context_object.relativize(call_context_selector * (1 - is_first[1]) * (state_root_hi[1] - state_root_before_hi[1]), -1));
                        special_constraints[CALL_CONTEXT_OP].push_back(context_object.relativize(call_context_selector * (1 - is_first[1]) * (state_root_lo[1] - state_root_before_lo[1]), -1));
                        special_constraints[CALL_CONTEXT_OP].push_back(context_object.relativize(call_context_selector * initial_value_hi[1], -1));
                        special_constraints[CALL_CONTEXT_OP].push_back(context_object.relativize(call_context_selector * initial_value_lo[1], -1));

                        // Specific constraints for TX_REFUND_OP
                        // address, field_tag and storage_key are 0
                        // state_root eqauls state_root_prev
                        // initial_value is 0
                        // if first access is Read then value = 0
                        // special_constraints[TX_REFUND_OP].push_back(context_object.relativize(tx_refund_selector * address[1], -1));
                        // special_constraints[TX_REFUND_OP].push_back(context_object.relativize(tx_refund_selector * field_type[1], -1));
                        // special_constraints[TX_REFUND_OP].push_back(context_object.relativize(tx_refund_selector * storage_key_hi[1], -1));
                        // special_constraints[TX_REFUND_OP].push_back(context_object.relativize(tx_refund_selector * storage_key_lo[1], -1));
                        // special_constraints[TX_REFUND_OP].push_back(context_object.relativize(tx_refund_selector * is_first[1] * (1-is_write[1]) * value_hi[1], -1));
                        // special_constraints[TX_REFUND_OP].push_back(context_object.relativize(tx_refund_selector * is_first[1] * (1-is_write[1]) * value_lo[1], -1));
                        // special_constraints[TX_REFUND_OP].push_back(context_object.relativize(tx_refund_selector * (state_root_hi[1] - state_root_before_hi[1]), -1));
                        // special_constraints[TX_REFUND_OP].push_back(context_object.relativize(tx_refund_selector * (state_root_lo[1] - state_root_before_lo[1]), -1));

                        // Specific constraints for TX_LOG_OP
                        //  is_write is true
                        //  initial_value is 0
                        //  state_root eqauls state_root_prev
                        //  value_prev equals initial_value
                        //  address 64 bits
                        // Grouped by transactionints[TX_LOG_OP].push_back(context_object.relativize(tx_log_selector * (1 - is_write[1]), -1));
                        // special_constraints[TX_LOG_OP].push_back(context_object.relativize(tx_log_selector * (state_root_hi[1] - state_root_before_hi[1]), -1));
                        // special_constraints[TX_LOG_OP].push_back(context_object.relativize(tx_log_selector * (state_root_lo[1] - state_root_before_lo[1]), -1));
                        // special_constraints[TX_LOG_OP].push_back(context_object.relativize(tx_log_selector * initial_value_hi[1], -1));
                        // special_constraints[TX_LOG_OP].push_back(context_object.relativize(tx_log_selector * initial_value_lo[1], -1));

                        // Specific constraints for TX_RECEIPT_OP
                        // address and storage_key are 0
                        //  field_tag is boolean (according to EIP-658)
                        //  tx_id increases by 1 and value increases as well if tx_id changes
                        //  tx_id is 1 if it's the first row and tx_id is in 11 bits range
                        //  state root is the same
                        //  value_prev is 0 and initial_value is 0
                        // special_constraints[TX_RECEIPT_OP].push_back(context_object.relativize(tx_receipt_selector * address[1], -1));
                        // special_constraints[TX_RECEIPT_OP].push_back(context_object.relativize(tx_receipt_selector * storage_key_hi[1], -1));
                        // special_constraints[TX_RECEIPT_OP].push_back(context_object.relativize(tx_receipt_selector * storage_key_lo[1], -1));

                        // Specific constraints for MODIFIED_ITEMS_OP
                        // is_write is always 1
                        // is_first is always 1 i.e. each item may be here only once
                        // parent_id field is  id of parent of call_call_id field
                        // each item that was changed in current context was also changed in parent context
                        // any item presented in any context exists in STATE section
                        // special_constraints[MODIFIED_ITEMS_OP].push_back(context_object.relativize(modified_items_selector * (1 - is_write[1]), -1));
                        // special_constraints[MODIFIED_ITEMS_OP].push_back(context_object.relativize(modified_items_selector * (1 - is_first[1]), -1));
                        // special_constraints[MODIFIED_ITEMS_OP].push_back(context_object.relativize(
                        //     modified_items_selector * (rw_call_id[1] - id[1] - diff_0[1] - diff_1[1] * 0x10000), -1
                        // ));
                        // special_constraints[MODIFIED_ITEMS_OP].push_back(context_object.relativize(
                        //     modified_items_selector * (id[1] - w_id_before[1] - diff_2[1] - diff_3[1] * 0x10000), -1
                        // ));
                        // special_constraints[MODIFIED_ITEMS_OP].push_back(context_object.relativize(
                        //     modified_items_selector * (is_first_for_id[1] * (rw_id[1] - 1)), -1
                        // ));
                        // non_first_row_constraints.push_back(context_object.relativize(
                        //     modified_items_selector * ((1 - is_first_for_id[1]) * (rw_id[1] - rw_id[0] - 1)), -1
                        // ));
                        // std::vector<TYPE> parent_call_lookup = rw_table<FieldType, stage>::call_context_lookup(
                        //     id[1],
                        //     std::size_t(call_context_field::parent_id),
                        //     TYPE(0),
                        //     parent_id[1]
                        // );
                        // for( std::size_t j = 0; j < parent_call_lookup.size(); j++){
                        //     parent_call_lookup[j] = context_object.relativize(modified_items_selector * parent_call_lookup[j], -1);
                        // }
                        // context_object.relative_lookup( parent_call_lookup, "zkevm_rw", 1, max_rw_size-1 );
                        // std::vector<TYPE> parent_modified_items_lookup = rw_table<FieldType, stage>::rw_item_lookup(
                        //     MODIFIED_ITEMS_OP,
                        //     op_helper[1],
                        //     parent_id[1],
                        //     address[1],
                        //     field_type[1],
                        //     storage_key_hi[1],
                        //     storage_key_lo[1]
                        // );
                        // for( std::size_t j = 0; j < parent_modified_items_lookup.size(); j++){
                        //     parent_modified_items_lookup[j] = context_object.relativize(
                        //         modified_items_selector * parent_id[1] * parent_id_inv[1] * parent_modified_items_lookup[j], -1
                        //     );
                        // }
                        // context_object.relative_lookup( parent_modified_items_lookup, "zkevm_rw_items", 1, max_rw_size-1 );
                        // std::vector<TYPE> access_is_real_lookup = {
                        //     op_helper[1],
                        //     op_helper[1],
                        //     call_id[1], // block_id
                        //     address[1],
                        //     field_type[1],
                        //     storage_key_hi[1],
                        //     storage_key_lo[1],
                        //     rw_call_id[1],
                        //     TYPE(1),            // is_write
                        //     value_before_hi[1],
                        //     value_before_lo[1],
                        //     value_hi[1],
                        //     value_lo[1],
                        //     call_call_id[1],
                        //     TYPE(0),
                        //     w_id_before[1]
                        // };
                        // for( std::size_t j = 0; j < access_is_real_lookup.size(); j++){
                        //     access_is_real_lookup[j] = context_object.relativize(
                        //         modified_items_selector * parent_id[1] * parent_id_inv[1] * access_is_real_lookup[j], -1
                        //     );
                        // }
                        // context_object.relative_lookup( access_is_real_lookup, "zkevm_rw_ext", 1, max_rw_size-1 );
                        // std::vector<TYPE> modified_items_amount_lookup = rw_table<FieldType, stage>::call_context_lookup(
                        //     id[1],
                        //     std::size_t(call_context_field::modified_items),
                        //     TYPE(0),
                        //     rw_id[1]
                        // );
                        // for( std::size_t j = 0; j < modified_items_amount_lookup.size(); j++){
                        //     modified_items_amount_lookup[j] = context_object.relativize(
                        //         modified_items_selector * is_last_for_id[1] * modified_items_amount_lookup[j]
                        //     , -1);
                        // }
                        // context_object.relative_lookup( modified_items_amount_lookup, "zkevm_rw", 1, max_rw_size-1 );

                        // Specific constraints for PADDING
                        special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * address[1], -1));
                        special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * storage_key_hi[1], -1));
                        special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * storage_key_lo[1], -1));
                        special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * id[1], -1));
                        special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * address[1], -1));
                        special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * field_type[1], -1));
                        special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * rw_id[1], -1));
                        special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * state_root_hi[1], -1));
                        special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * state_root_lo[1], -1));
                        special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * state_root_before_hi[1], -1));
                        special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * state_root_before_lo[1], -1));
                        special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * value_hi[1], -1));
                        special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * value_lo[1], -1));
                        special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * initial_value_hi[1], -1));
                        special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * initial_value_lo[1], -1));

                        std::size_t max_constraints = 0;
                        for(const auto&[k,constr] : special_constraints){
                            if( constr.size() > max_constraints) max_constraints = constr.size();
                        }
                        for( std::size_t i = 0; i < max_constraints; i++ ){
                            TYPE constraint;
                            for(const auto&[k,constr] : special_constraints){
                                if( constr.size() > i ) constraint += constr[i];
                            }
                            every_row_constraints.push_back(constraint);
                        }

                        {
                            PROFILE_SCOPE("RW circuit constraints row definition");
                            std::vector<std::size_t> every_row;
                            std::vector<std::size_t> non_first_row;
                            for( std::size_t i = 0; i < max_rw_size; i++){
                                every_row.push_back(i);
                                if( i!= 0 ) non_first_row.push_back(i);
                            }
                            for( auto& constraint: every_row_constraints){
                                context_object.relative_constrain(constraint, 0, max_rw_size-1);
                            }
                            for( auto &constraint:chunked_16_lookups ){
                                std::vector<TYPE> tmp = {constraint};
                                context_object.relative_lookup(tmp, "chunk_16_bits/full", 0, max_rw_size-1);
                            }
                            for( auto &constraint: non_first_row_constraints ){
                                context_object.relative_constrain(constraint, 1, max_rw_size - 1);
                            }
                        }
                    }
                    std::cout << std::endl;
                }
            };
        }
    }
}
