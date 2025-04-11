//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining acall_commit
// of this software and associated documentation files (the oftware"), to deal
// in the Software without restriction, including without limitation the rights
// to use,call_commit, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The abovecall_commitright notice and this permission notice shall be included in all
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

#include <nil/blueprint/zkevm_bbf/subcomponents/keccak_table.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/bytecode_table.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/rw_table.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/copy_table.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/call_commit_table.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            template<typename FieldType, GenerationStage stage>
            class call_commit : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;

            public:
                using RWTable = rw_table<FieldType, stage>;
                using CallCommitTable = call_commit_table<FieldType, stage>;

                using typename generic_component<FieldType, stage>::table_params;
                using typename generic_component<FieldType,stage>::TYPE;
                using integral_type =  nil::crypto3::multiprecision::big_uint<257>;

                struct input_type {
                    RWTable::input_type rw_operations;
                    CallCommitTable::input_type call_commits;
                };

                static constexpr std::size_t call_commit_advice_amount = 25;

                static table_params get_minimal_requirements(
                    std::size_t max_rw,
                    std::size_t max_call_commits
                ) {
                    return {
                        .witnesses =call_commit_advice_amount
                            + RWTable::get_witness_amount()
                            + CallCommitTable::get_witness_amount(),
                        .public_inputs = 1,
                        .constants = 3,
                        .rows = std::max(
                            max_call_commits,
                            max_rw
                        )
                    };
                }

                static void allocate_public_inputs(
                    context_type &context,
                    input_type &input,
                    std::size_t max_rw,
                    std::size_t max_call_commits
                ) {
                }

                call_commit(
                    context_type &context_object,
                    const input_type &input,
                    std::size_t max_rw,
                    std::size_t max_call_commits
                ) :generic_component<FieldType,stage>(context_object) {
                    // Allocate places for dynamic lookups
                    std::size_t current_column = 0;
                    std::vector<std::size_t> rw_lookup_area;
                    for( std::size_t i = 0; i < RWTable::get_witness_amount(); i++){
                        rw_lookup_area.push_back(current_column++);
                    }
                    std::vector<std::size_t> call_commit_lookup_area;
                    for( std::size_t i = 0; i < CallCommitTable::get_witness_amount(); i++){
                        call_commit_lookup_area.push_back(current_column++);
                    }

                    context_type rw_ct = context_object.subcontext(rw_lookup_area, 0, max_rw);
                    context_type call_commit_ct = context_object.subcontext( call_commit_lookup_area, 0, max_call_commits);

                    RWTable rw_t = RWTable(rw_ct, input.rw_operations, max_rw, true);
                    CallCommitTable t = CallCommitTable(call_commit_ct, input.call_commits, max_call_commits);
                    
                    const std::vector<TYPE> &call_id = t.call_id;
                    const std::vector<TYPE> &op = t.op;
                    const std::vector<TYPE> &id = t.id;
                    const std::vector<TYPE> &address = t.address;
                    const std::vector<TYPE> &field_type = t.field_type;
                    const std::vector<TYPE> &storage_key_hi = t.storage_key_hi;
                    const std::vector<TYPE> &storage_key_lo = t.storage_key_lo;
                    const std::vector<TYPE> &counter = t.counter;               // counter for modified items for each id
                    const std::vector<TYPE> &value_hi = t.value_hi;             // value_before in rw_table
                    const std::vector<TYPE> &value_lo = t.value_lo;

                    std::vector<TYPE> new_value_hi(max_call_commits);           // value in rw_table
                    std::vector<TYPE> new_value_lo(max_call_commits);
                    std::vector<TYPE> w_id_before(max_call_commits);
                    std::vector<TYPE> parent_id(max_call_commits);              // parent call_id
                    std::vector<TYPE> call_id_chunk0(max_call_commits);
                    std::vector<TYPE> call_id_chunk1(max_call_commits);
                    // 0 if call_id is the same as previous or padding, 1 if first chunk is different, 2 if second chunk is different
                    std::vector<TYPE> diff_ind(max_call_commits);
                    // difference in first non-equal chunk of call_id
                    std::vector<TYPE> diff(max_call_commits);
                    std::vector<TYPE> call_id_inv(max_call_commits);
                    // dynamic selector for last row for call_id
                    std::vector<TYPE> is_last(max_call_commits);
                    std::vector<TYPE> real_call_id(max_call_commits);           // original call_id in rw_table
                    std::vector<TYPE> depth(max_call_commits);                  // call depth - 1 (blocks are not reverted, so we don't store lists for them)
                    std::vector<TYPE> depth_inv(max_call_commits);
                    std::vector<TYPE> rw_counter_chunk0(max_call_commits);      // rw_counter
                    std::vector<TYPE> rw_counter_chunk1(max_call_commits);
                    // rw_counter before ending call opcode -- STOP, REVERT, RETURN. All reverted operations were before this counter
                    std::vector<TYPE> call_end_chunk0(max_call_commits);
                    std::vector<TYPE> call_end_chunk1(max_call_commits);
                    // rw_counter - call_id
                    std::vector<TYPE> diff0_chunk0(max_call_commits);
                    std::vector<TYPE> diff0_chunk1(max_call_commits);
                    // call_end - rw_counter
                    std::vector<TYPE> diff1_chunk0(max_call_commits);
                    std::vector<TYPE> diff1_chunk1(max_call_commits);
                    // call_id - w_id_before
                    std::vector<TYPE> diff2_chunk0(max_call_commits);
                    std::vector<TYPE> diff2_chunk1(max_call_commits);

                    if constexpr ( stage == GenerationStage::ASSIGNMENT) {
                        auto call_commits = input.call_commits;
                        std::size_t row = 0;
                        for( auto &[ind,call_commit]: call_commits){
                            std::cout << "CALL COMMIT " << ind << " depth = " << call_commit.depth << std::endl;
                            for( std::size_t i = 0; i < call_commit.items.size(); i++, row++ ){
                                std::cout << "\t" << i+1 << " " << call_commit.items[i] << std::endl;
                                BOOST_ASSERT(row < max_call_commits);
                                BOOST_ASSERT(ind == call_commit.call_id);
                                new_value_hi[row] = w_hi<FieldType>(call_commit.items[i].value);
                                new_value_lo[row] = w_lo<FieldType>(call_commit.items[i].value);
                                w_id_before[row] = call_commit.items[i].w_id_before;
                                call_id_chunk0[row] = (( call_commit.call_id & 0xFFFF0000) >> 16);
                                call_id_chunk1[row] = ( call_commit.call_id & 0xFFFF );
                                call_end_chunk0[row] = (( call_commit.call_end & 0xFFFF0000) >> 16);
                                call_end_chunk1[row] = ( call_commit.call_end & 0xFFFF );
                                parent_id[row] = call_commit.parent_id;
                                call_id_inv[row] = call_id[row] == 0? 0: call_id[row].inversed();
                                rw_counter_chunk0[row] = (( call_commit.items[i].rw_counter & 0xFFFF0000) >> 16);
                                rw_counter_chunk1[row] = ( call_commit.items[i].rw_counter & 0xFFFF );
                                real_call_id[row] = call_commit.items[i].call_id;
                                depth[row] = call_commit.depth - 1; // We won't revert blocks, so, how we'll store only transactions
                                depth_inv[row] = depth[row] == 0? 0: depth[row].inversed();

                                auto diff0 = call_commit.items[i].rw_counter - call_commit.call_id;
                                diff0_chunk0[row] = (( diff0 & 0xFFFF0000) >> 16);
                                diff0_chunk1[row] = ( diff0 & 0xFFFF );
                                auto diff1 = call_commit.call_end - call_commit.items[i].rw_counter;
                                diff1_chunk0[row] = (( diff1 & 0xFFFF0000) >> 16);
                                diff1_chunk1[row] = ( diff1 & 0xFFFF );
                                auto diff3 = call_commit.call_id - call_commit.items[i].w_id_before;
                                diff2_chunk0[row] = (( diff3 & 0xFFFF0000) >> 16);
                                diff2_chunk1[row] = ( diff3 & 0xFFFF );
                                
                                if( i == 0 ) {
                                    diff_ind[row] = 1;
                                    diff[row] = call_id_chunk0[row];
                                } else {
                                    if( call_id_chunk0[row] == call_id_chunk0[row-1] ){
                                        if( call_id_chunk1[row] == call_id_chunk1[row-1] ){
                                            diff_ind[row] = 0;
                                        } else {
                                            diff_ind[row] = 2;
                                            diff[row] = call_id_chunk1[row] > call_id_chunk1[row-1] ? call_id_chunk1[row] - call_id_chunk1[row-1] : call_id_chunk1[row-1] - call_id_chunk1[row];
                                        }
                                    } else {
                                        diff_ind[row] = 1;
                                        diff[row] = call_id_chunk0[row] > call_id_chunk0[row-1] ? call_id_chunk0[row] - call_id_chunk0[row-1] : call_id_chunk0[row-1] - call_id_chunk0[row];
                                    }
                                }
                            }
                            if( row != 0 ) is_last[row - 1] = 1;
                        }
                    }
                    for( std::size_t i = 0; i < max_call_commits; i++){
                        std::size_t current_column = RWTable::get_witness_amount() + CallCommitTable::get_witness_amount();
                        allocate(new_value_hi[i], current_column++, i);
                        allocate(new_value_lo[i], current_column++, i);
                        allocate(w_id_before[i], current_column++, i);
                        allocate(parent_id[i], current_column++, i);
                        allocate(call_id_chunk0[i], current_column++, i);
                        allocate(call_id_chunk1[i], current_column++, i);
                        allocate(rw_counter_chunk0[i], current_column++, i);
                        allocate(rw_counter_chunk1[i], current_column++, i);
                        allocate(call_end_chunk0[i], current_column++, i);
                        allocate(call_end_chunk1[i], current_column++, i);
                        allocate(diff[i], current_column++, i);
                        allocate(diff_ind[i], current_column++, i);
                        allocate(call_id_inv[i], current_column++, i);
                        allocate(is_last[i], current_column++, i);
                        allocate(real_call_id[i], current_column++, i);
                        allocate(depth[i], current_column++, i);
                        allocate(depth_inv[i], current_column++, i);
                        allocate(diff0_chunk0[i], current_column++, i);
                        allocate(diff0_chunk1[i], current_column++, i);
                        allocate(diff1_chunk0[i], current_column++, i);
                        allocate(diff1_chunk1[i], current_column++, i);
                        allocate(diff2_chunk0[i], current_column++, i);
                        allocate(diff2_chunk1[i], current_column++, i);
                    }
                    // Constraints for 0 row
                    //A trace with only a pure function call does not have any items
                    constrain((diff_ind[0] - 1) * call_id[0]);
                    constrain((call_id[0] * call_id_inv[0] - 1) * call_id[0]);


                    if constexpr ( stage == GenerationStage::CONSTRAINTS) {
                        std::vector<TYPE> every;
                        std::vector<TYPE> non_first;
                        std::vector<TYPE> chunked_16_lookups;

                        // Prove chunking correctness
                        every.push_back(call_id[1] - call_id_chunk0[1] * 0x10000 - call_id_chunk1[1]);
                        chunked_16_lookups.push_back(call_id_chunk0[1]);
                        chunked_16_lookups.push_back(call_id_chunk1[1]);
                        chunked_16_lookups.push_back(diff[1]);
                        chunked_16_lookups.push_back(rw_counter_chunk0[1]);
                        chunked_16_lookups.push_back(rw_counter_chunk1[1]);
                        chunked_16_lookups.push_back(call_end_chunk0[1]);
                        chunked_16_lookups.push_back(call_end_chunk1[1]);
                        chunked_16_lookups.push_back(diff0_chunk0[1]);
                        chunked_16_lookups.push_back(diff0_chunk1[1]);
                        chunked_16_lookups.push_back(diff1_chunk0[1]);
                        chunked_16_lookups.push_back(diff1_chunk1[1]);
                        chunked_16_lookups.push_back(diff2_chunk0[1]);
                        chunked_16_lookups.push_back(diff2_chunk1[1]);

                        // Prove call_id inversion
                        every.push_back(call_id[1] * (call_id[1] * call_id_inv[1] - 1));
                        every.push_back(call_id_inv[1] * (call_id[1] * call_id_inv[1] - 1));

                        // call_id = 0 means padding
                        non_first.push_back((call_id[0] * call_id_inv[0] - 1) * call_id[1] );

                        every.push_back(diff_ind[1] * (diff_ind[1] - 1) * (diff_ind[1] - 2));
                        // diff_ind == 0 => call_id = call_id_prev
                        non_first.push_back(call_id[1] * (diff_ind[1] - 1) * (diff_ind[1] - 2) * (call_id_chunk0[1] - call_id_chunk0[0]));
                        non_first.push_back(call_id[1] * (diff_ind[1] - 1) * (diff_ind[1] - 2) * (call_id_chunk1[1] - call_id_chunk1[0]));

                        // diff_ind == 1 => difference between call_id and call_id_prev is in the first chunk
                        non_first.push_back(call_id[1] * diff_ind[1] * (diff_ind[1] - 2) * (call_id_chunk0[1] - call_id_chunk0[0] - diff[1]));

                        // diff_ind == 2 => difference between call_id and call_id_prev is in the second chunk
                        non_first.push_back(call_id[1] * diff_ind[1] * (diff_ind[1] - 1) * (call_id_chunk0[1] - call_id_chunk0[0] - diff[1]));
                        non_first.push_back(call_id[1] * diff_ind[1] * (diff_ind[1] - 1) * (call_id_chunk1[1] - call_id_chunk1[0] - diff[1]));

                        // counter for first position is 1
                        every.push_back(diff_ind[1] * (counter[1] - 1));
                        non_first.push_back( call_id[1] * (diff_ind[1] - 1) * (diff_ind[1] - 2) * (counter[1] - counter[0] - 1));

                        // is_last is correct
                        every.push_back(is_last[1] * (is_last[1] - 1));
                        non_first.push_back( (call_id[1] * call_id_inv[1] - 1) * call_id[0] * (is_last[0] - 1));
                        non_first.push_back( diff_ind[1] * (is_last[0] - 1));
                        non_first.push_back( (call_id[1] * call_id_inv[1] - 1) * is_last[1]);

                        // each row is presented in rw_table
                        TYPE rw_counter = rw_counter_chunk0[1] * 0x10000 + rw_counter_chunk1[1];
                        std::vector<TYPE> tmp = {
                            op[1],
                            id[1],
                            address[1],
                            field_type[1],                                            // field
                            storage_key_hi[1],                                        // storage_key_hi
                            storage_key_lo[1],                                        // storage_key_lo
                            rw_counter,                                            // rw_counter
                            call_id[1] * call_id_inv[1] * TYPE(1),                    // is_write
                            new_value_hi[1],
                            new_value_lo[1],
                            value_hi[1],
                            value_lo[1],
                            real_call_id[1],
                            w_id_before[1]
                        };
                        for(std::size_t j = 0; j < tmp.size(); j++){
                            tmp[j] = context_object.relativize(tmp[j], -1);
                        }
                        context_object.relative_lookup(tmp, "zkevm_rw", 0, max_call_commits - 1);

                        // reverted item types are state, access_list, transient_storage
                        every.push_back(
                            call_id[1] *
                            (op[1] - rw_op_to_num(rw_operation_type::state)) *
                            (op[1] - rw_op_to_num(rw_operation_type::access_list)) *
                            (op[1] - rw_op_to_num(rw_operation_type::transient_storage))
                        );

                        // parent_id is correct
                        tmp = rw_table<FieldType, stage>::call_context_lookup(
                            call_id[1],
                            std::size_t(call_context_field::parent_id),
                            TYPE(0),
                            parent_id[1]
                        );
                        for(std::size_t j = 0; j < tmp.size(); j++){
                            tmp[j] = context_object.relativize(call_id[1] * call_id_inv[1] * tmp[j], -1);
                        }
                        context_object.relative_lookup(tmp, "zkevm_rw", 0, max_call_commits - 1);

                        // depth is correct
                        tmp = rw_table<FieldType, stage>::call_context_lookup(
                            call_id[1],
                            std::size_t(call_context_field::depth),
                            TYPE(0),
                            depth[1] + 1
                        );
                        for(std::size_t j = 0; j < tmp.size(); j++){
                            tmp[j] = context_object.relativize(call_id[1] * call_id_inv[1] * tmp[j], -1);
                        }
                        context_object.relative_lookup(tmp, "zkevm_rw", 0, max_call_commits - 1);
                        every.push_back( depth[1] * (depth[1] * depth_inv[1] - 1));
                        every.push_back( depth_inv[1] * (depth[1] * depth_inv[1] - 1));

                        // call_end is correct
                        TYPE call_end = call_end_chunk0[1] * 0x10000 + call_end_chunk1[1];
                        tmp = rw_table<FieldType, stage>::call_context_lookup(
                            call_id[1],
                            std::size_t(call_context_field::end),
                            TYPE(0),
                            call_end
                        );
                        for(std::size_t j = 0; j < tmp.size(); j++){
                            tmp[j] = context_object.relativize(call_id[1] * call_id_inv[1] * tmp[j], -1);
                        }
                        context_object.relative_lookup(tmp, "zkevm_rw", 0, max_call_commits - 1);

                        // If not transaction then item for each call is presented in parent call
                        tmp = {
                            parent_id[1],
                            op[1],
                            id[1],
                            address[1],
                            field_type[1],
                            storage_key_hi[1],
                            storage_key_lo[1]
                        };
                        for(std::size_t j = 0; j < tmp.size(); j++){
                            tmp[j] = context_object.relativize(depth[1] * depth_inv[1] * tmp[j], -1);
                        };
                        context_object.relative_lookup(tmp, "zkevm_call_commit_items", 0, max_call_commits - 1);

                        // Each rw operation was inside CALL: call_id < rw_counter
                        every.push_back(rw_counter - call_id[1] - diff0_chunk0[1] * 0x10000 - diff0_chunk1[1]);
                        // Each rw operation was inside CALL: rw_counter < call_end
                        every.push_back(call_end - rw_counter - diff1_chunk0[1] * 0x10000 - diff1_chunk1[1]);
                        // It's the first write in the CALL: w_id_before < call_id
                        every.push_back(call_id[1] - w_id_before[1] - diff2_chunk0[1] * 0x10000 - diff2_chunk1[1]);

                        for( std::size_t i = 0; i < every.size(); i++ ){
                            context_object.relative_constrain(context_object.relativize(every[i], -1), 0, max_call_commits - 1);
                        }
                        for( std::size_t i = 0; i < non_first.size(); i++ ){
                            context_object.relative_constrain(context_object.relativize(non_first[i],-1), 1, max_call_commits - 1);
                        }
                        for( auto &constraint:chunked_16_lookups ){
                            context_object.relative_lookup({context_object.relativize(constraint, -1)}, "chunk_16_bits/full", 0, max_call_commits - 1);
                        }
                    }

                }
            };
        }
    }
}
