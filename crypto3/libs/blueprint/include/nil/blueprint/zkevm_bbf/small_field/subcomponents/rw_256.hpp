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
    class rw_256_instance : public generic_component<FieldType, stage> {
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
        using rw_256_table_instance_type = rw_256_table_instance<FieldType, stage>;

        // using value = typename FieldType::value_type;
        // using integral_type = nil::crypto3::multiprecision::big_uint<257>;

        // Chunks 7: op -- 1, id -- 2, address -- 2, rw_id -- 2;
        // Diff for each chunk has its own selector
        // Each op also has its ownn selector

        static constexpr std::size_t id_chunks_amount = 2;
        static constexpr std::size_t rw_id_chunks_amount = 2;
        static constexpr std::size_t chunks_amount = 6;
        static constexpr std::size_t op_selectors_amount = 2;

    protected:
        std::size_t last_assigned_internal_counter;
    public:
        std::size_t get_last_assigned_internal_counter() const {
            return last_assigned_internal_counter;
        }

        static std::size_t get_witness_amount() {
            return (id_chunks_amount + rw_id_chunks_amount   // Additional chunks
                + chunks_amount                              // Diff selectors
                + op_selectors_amount                        // Selectors for op
                + 10);
        }

        std::size_t max_rw_size;

        std::vector<TYPE> internal_counter;                         // 2  chunks fitted in field element less than 2^25
        std::vector<TYPE> is_filled;                                // bool
        std::vector<TYPE> call_context_selector;
        std::vector<TYPE> stack_selector;
        std::vector<std::array<TYPE,chunks_amount>> diff_index_selectors;
        std::vector<std::pair<TYPE, TYPE>> id_chunks;
        std::vector<std::pair<TYPE, TYPE>> rw_id_chunks;

        std::vector<TYPE> is_first;
        std::vector<TYPE> diff;
        std::vector<TYPE> inv_diff;
        std::vector<TYPE> is_diff_non_zero; // For lower constraints degree

        static constexpr std::size_t get_is_filled_column_index() {
            return 0;
        }
        static constexpr std::size_t get_internal_counter_column_index() {
            return 1;
        }

        rw_256_instance(context_type &context_object,
            const rw_256_table_instance_type &t,
            std::size_t starting_internal_counter
        ) :generic_component<FieldType,stage>(context_object),
            max_rw_size(t.get_max_rw_size()),
            internal_counter(max_rw_size),
            is_filled(max_rw_size),
            call_context_selector(max_rw_size),
            stack_selector(max_rw_size),
            diff_index_selectors(max_rw_size),
            id_chunks(max_rw_size),
            rw_id_chunks(max_rw_size),
            is_first(max_rw_size),
            diff(max_rw_size),
            inv_diff(max_rw_size),
            is_diff_non_zero(max_rw_size)
        {
            BOOST_LOG_TRIVIAL(trace) << "RW256 instance construction";

            const std::vector<TYPE> &op = t.op;                                   // stack, call_context
            const std::vector<TYPE> &id = t.id;                                   // 2 chunks fitted in field element less than 2^25
            const std::vector<TYPE> &address = t.address;                         // < 1024
            const std::vector<TYPE> &rw_id = t.rw_id;                             // 2 chunks fitted in field element less than 2^25
            const std::vector<TYPE> &is_write = t.is_write;                       // bool
            const std::vector<std::array<TYPE, 16>> &value = t.value;             // 16 chunks

            if constexpr  (stage == GenerationStage::ASSIGNMENT) {
                last_assigned_internal_counter = starting_internal_counter;
                for( std::size_t i = 0; i < max_rw_size; i++ ){
                    is_filled[i] = ((op[i] != std::size_t(rw_operation_type::padding)) && ( op[i] != std::size_t(rw_operation_type::start)))? 1: 0;
                    if( op[i] != std::size_t(rw_operation_type::padding) ){
                        if( i == 0 ) {
                            internal_counter[i] = starting_internal_counter;
                        } else {
                            internal_counter[i] = internal_counter[i-1];
                            if( op[i] != op[i-1] || id[i] != id[i-1] || address[i] != address[i-1] ){
                                internal_counter[i] = internal_counter[i-1] + 1;
                                last_assigned_internal_counter++;
                            }
                        }
                    }
                }

                std::size_t current_row = 0;

                std::array<TYPE, chunks_amount> sorted;
                std::array<TYPE, chunks_amount> sorted_prev;
                for( std::size_t i = 0; i < max_rw_size; i++ ){
                    call_context_selector[i] = op[i] == std::size_t(rw_operation_type::call_context)? 1: 0;
                    stack_selector[i] = op[i] == std::size_t(rw_operation_type::stack)? 1: 0;

                    id_chunks[i].first = ((id[i].to_integral() & 0xFFFF0000) >> 16);
                    id_chunks[i].second = id[i].to_integral() & 0xFFFF;

                    rw_id_chunks[i].first = ((rw_id[i].to_integral() & 0xFFFF0000) >> 16);
                    rw_id_chunks[i].second = rw_id[i].to_integral() & 0xFFFF;

                    sorted_prev = sorted;
                    sorted[0] = op[i];
                    sorted[1] = id_chunks[i].first;
                    sorted[2] = id_chunks[i].second;
                    sorted[3] = address[i];
                    sorted[4] = rw_id_chunks[i].first;
                    sorted[5] = rw_id_chunks[i].second;
                    if( i != 0) {
                        std::size_t diff_ind;
                        for( diff_ind= 0; diff_ind < chunks_amount; diff_ind++ ){
                            if(sorted[diff_ind] != sorted_prev[diff_ind]) break;
                        }
                        if( is_filled[i] != 0 ) BOOST_ASSERT(diff_ind < chunks_amount);
                        if( diff_ind < chunks_amount ) {
                            diff_index_selectors[i][diff_ind] = 1;
                            diff[i] = sorted[diff_ind] - sorted_prev[diff_ind];
                            inv_diff[i] = diff[i] == 0? 0: diff[i].inversed();
                            is_diff_non_zero[i] = diff[i] * inv_diff[i];
                        } else {
                            BOOST_ASSERT(op[i] == std::size_t(rw_operation_type::padding));
                        }

                        if( diff_ind < sorted.size() - 2){
                            is_first[i] = 1;
                        }
                    }
                }
            }

            for( std::size_t i = 0; i < max_rw_size; i++ ){
                std::size_t current_columm = 0;
                allocate(is_filled[i], current_columm++, i);
                allocate(internal_counter[i], current_columm++, i);
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
            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                _timeline_lookup = {
                    is_filled[1] * rw_id[1],
                    TYPE(0),
                    is_filled[1],
                    TYPE(0),
                    is_filled[1] * internal_counter[1]
                };
            }


            if constexpr  (stage == GenerationStage::CONSTRAINTS) {
                std::vector<std::pair<TYPE, std::string>> every_row_constraints;
                std::vector<std::pair<TYPE, std::string>> non_first_row_constraints;
                std::vector<TYPE> chunked_16_lookups;

                // Rw_operation_type selectors may be only 0 or 1
                every_row_constraints.push_back({call_context_selector[1] * (call_context_selector[1] - 1), "Call context selector is 0 or 1"});
                every_row_constraints.push_back({stack_selector[1] * (stack_selector[1] - 1), "Stack selector is 0 or 1"});

                // is_filled is sum of rw_operation_type selectors
                every_row_constraints.push_back({is_filled[1] - (
                    call_context_selector[1] + stack_selector[1]
                ), "is_filled is sum of rw_operation_type selectors"});

                // is_filled is always 0 and 1, so two rw_operation_type selectors cannot be 1 simultaneously
                every_row_constraints.push_back({is_filled[1] * (is_filled[1] - 1), "is_filled is always 0 or 1"});

                // Rw_operation_type selectors encodes op correctly.
                // First is start rw_operation_type::start and was constrained earlier
                non_first_row_constraints.push_back({op[1] - (
                    call_context_selector[1] * std::size_t(rw_operation_type::call_context) +
                    stack_selector[1] * std::size_t(rw_operation_type::stack) +
                    (1 - is_filled[1]) * std::size_t(rw_operation_type::padding)
                ), "Op is encoded correctly by rw_operation_type selectors"});

                // id is encoded correctly
                every_row_constraints.push_back({id[1] - (id_chunks[1].first * (0x10000) + id_chunks[1].second), "Id is splitted in chunks correctly"});

                // rw_id is encoded correctly
                every_row_constraints.push_back({rw_id[1] - (rw_id_chunks[1].first * (0x10000) + rw_id_chunks[1].second), "Rw_id is splitted in chunks correctly"});

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
                    every_row_constraints.push_back({diff_index_selectors[1][i] * (diff_index_selectors[1][i] - 1), "Diff index selector is 0 or 1"});
                    diff_ind_selectors_sum += diff_index_selectors[1][i];
                }
                // only one of diff_index_selectors may be 1
                every_row_constraints.push_back({diff_ind_selectors_sum * (diff_ind_selectors_sum - 1), "Only one diff_index_selector may be 1"});

                // diff_index (encoded by diff_index_selector) correctness
                for( std::size_t s_ind = 0; s_ind < sorted.size() - 1; s_ind++ ){
                    TYPE eq_selector;
                    for( std::size_t d_ind = s_ind+1; d_ind < chunks_amount; d_ind++){
                        eq_selector += diff_index_selectors[1][d_ind];
                    }
                    non_first_row_constraints.push_back({
                        eq_selector * (sorted[s_ind] - sorted_prev[s_ind]),
                        "If diff_index_selector is 1, then sorted and sorted_prev are equal for all indices before diff_index"
                    });
                    non_first_row_constraints.push_back({
                        diff_index_selectors[1][s_ind] * (sorted[s_ind] - sorted_prev[s_ind] - diff[1]),
                        "If diff_index_selector is 1, then diff is difference between sorted and sorted_prev"
                    });
                }

                // is_first is correct
                TYPE is_first_constraint;
                for( std::size_t i = 0; i < chunks_amount - 2; i++ ){
                    is_first_constraint +=  diff_index_selectors[1][i];
                }
                non_first_row_constraints.push_back({is_first_constraint - is_first[1], "Is_first defined by diff_index_selectors"});

                // inv_diff and is_diff_non_zero are correct
                non_first_row_constraints.push_back({diff[1] * inv_diff[1] - is_diff_non_zero[1], "Diff and inv_diff are correct"});
                non_first_row_constraints.push_back({diff[1] * (is_diff_non_zero[1] - 1), "Diff and inv_diff are correct"});
                non_first_row_constraints.push_back({inv_diff[1] * (is_diff_non_zero[1] - 1), "Diff and inv_diff are correct"});
                non_first_row_constraints.push_back({is_filled[1] * (is_diff_non_zero[1] - 1), "For all filled rows diff is non-zero"});

                // is_write is always 0 or 1
                every_row_constraints.push_back({is_write[1] * (is_write[1] - 1), "Is_write is always 0 or 1"});

                // internal counter is incremented only for new item
                non_first_row_constraints.push_back({
                    is_filled[1] * (internal_counter[1] - internal_counter[0] - is_first[1]),
                    "Internal counter is incremented only for new item"
                });

                // read-after-write constraint
                for( std::size_t i = 0; i < 16; i++ ){
                    non_first_row_constraints.push_back({
                        (1 - is_first[1]) * (1 - is_write[1]) * (value[1][i] - value[0][i]),
                        "Read-after-write constraint for value " + std::to_string(i) + " chunk"
                    });
                }

                // Situation when stack[1] and stack[3] were used, but stack[2] not is impossible
                // For call_context this mean that the whole call_context was read
                non_first_row_constraints.push_back({
                    stack_selector[1] * diff_index_selectors[1][3] * (address[1] - address[0] - 1), "Stack addreses are continuous"
                });

                // First operation for each stack item is W
                non_first_row_constraints.push_back({
                    stack_selector[1] * is_first[1] * (1 - is_write[1]),
                    "First operation for each stack item is write"
                });

                // range-checks
                chunked_16_lookups.push_back(diff[1]);
                chunked_16_lookups.push_back(stack_selector[1] * (1024 - address[1]));
                chunked_16_lookups.push_back(512 - id_chunks[1].first); // id < 2^25 => id_chunks.first < 2^9
                chunked_16_lookups.push_back(512 - rw_id_chunks[1].first); // rw_id < 2^25 => rw_id_chunks.first < 2^9
                for( std::size_t i = 0; i < chunks_amount; i++ ){
                    chunked_16_lookups.push_back(sorted[i]);
                }

                for( auto& constraint: every_row_constraints){
                    context_object.relative_constrain(context_object.relativize(constraint.first, -1), 0, max_rw_size-1, constraint.second);
                }
                for( auto &constraint: non_first_row_constraints ){
                    context_object.relative_constrain(context_object.relativize(constraint.first, -1), 1, max_rw_size - 1, constraint.second);
                }
                for( auto &constraint:chunked_16_lookups ){
                    std::vector<TYPE> tmp = {context_object.relativize(constraint, -1)};
                    context_object.relative_lookup(tmp, "chunk_16_bits/full", 0, max_rw_size-1);
                }
            }
        }
        std::vector<TYPE> timeline_lookup(){
            return _timeline_lookup;
        }
    protected:
        std::vector<TYPE> _timeline_lookup;
    };

    template<typename FieldType, GenerationStage stage>
    class rw_256 : public generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;
        using generic_component<FieldType, stage>::multi_lookup_table;
    public:
        using typename generic_component<FieldType, stage>::table_params;
        using typename generic_component<FieldType,stage>::TYPE;

        using rw_256_table_type = rw_256_table<FieldType, stage>;
        using rw_256_instance_type = rw_256_instance<FieldType, stage>;

        using input_type = typename rw_256_table_type::input_type;

        // Chunks 6: op -- 1, id -- 2, address -- 1, rw_id -- 2;
        // Diff for each chunk has its own selector
        // Each op also has its ownn selector

        static constexpr std::size_t id_chunks_amount = 2;
        static constexpr std::size_t rw_id_chunks_amount = 2;
        static constexpr std::size_t chunks_amount = 6;
        static constexpr std::size_t op_selectors_amount = 2;

        static std::size_t get_witness_amount(std::size_t instances_rw_256 ) {
            return rw_256_instance_type::get_witness_amount() * instances_rw_256 +
                rw_256_table_type::get_witness_amount(instances_rw_256);
        }

        static table_params get_minimal_requirements(
            std::size_t max_rw_size,
            std::size_t instances_rw_256
        ) {
            std::size_t witness_amount = rw_256<FieldType, stage>::get_witness_amount(instances_rw_256);
            BOOST_LOG_TRIVIAL(info) << "RW256 subcomponent witness amount = " << witness_amount;
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

        std::vector<rw_256_instance_type> instances;

        rw_256(context_type &context_object,
            const input_type &input,
            std::size_t max_rw_size,
            std::size_t instances_rw_256
        ) :generic_component<FieldType,stage>(context_object) {
            BOOST_LOG_TRIVIAL(trace) << "RW256 subcomponent";
            std::size_t current_column = 0;

            std::vector<std::size_t> rw_256_table_area;
            for( std::size_t i = 0; i < rw_256_table_type::get_witness_amount(instances_rw_256); i++ )
                rw_256_table_area.push_back(current_column++);
            context_type rw_256_table_ct = context_object.subcontext(rw_256_table_area,0,max_rw_size);
            rw_256_table_type t(rw_256_table_ct, input, max_rw_size, instances_rw_256);

            std::vector<std::vector<std::size_t>> rw_256_instance_areas(instances_rw_256);
            for( std::size_t i = 0; i < instances_rw_256; i++ ){
                for( std::size_t j = 0; j < rw_256_instance<FieldType, stage>::get_witness_amount(); j++ ){
                    rw_256_instance_areas[i].push_back(current_column++);
                }
                context_type instance_context = context_object.subcontext(rw_256_instance_areas[i], 0, max_rw_size);
                instances.emplace_back(instance_context, t.instances[i], i==0? 0: instances[i-1].get_last_assigned_internal_counter());
            }

            std::vector<std::vector<std::size_t>> rw_256_timeline_lookup_areas(instances_rw_256);
            for( std::size_t i = 0; i < instances_rw_256; i++ ){
                rw_256_timeline_lookup_areas[i] = {
                    rw_256_instance_areas[i][rw_256_instance_type::get_is_filled_column_index()],
                    rw_256_table_area[t.get_rw_id_column_index(i)],
                    rw_256_instance_areas[i][rw_256_instance_type::get_internal_counter_column_index()]
                };
            }
            multi_lookup_table("zkevm_rw_256_timeline", rw_256_timeline_lookup_areas, 0, max_rw_size);

            constrain(t.instances[0].op[0] - std::size_t(rw_operation_type::start), "First rw_256 operation must be start");
            constrain(instances[0].internal_counter[0], "First rw_256 instance internal counter must be 0");
            for( std::size_t i = 1; i < instances_rw_256; i++ ) {
                constrain(instances[i].internal_counter[0] - instances[i-1].internal_counter[max_rw_size - 1],
                    "Internal counter of rw_256 instances must be connected", true);
                constrain(t.instances[i].op[0] - t.instances[i-1].op[max_rw_size - 1],
                    "Op of rw_256 instances must be connected", true);
                constrain(t.instances[i].id[0] - t.instances[i-1].id[max_rw_size - 1],
                    "Id of rw_256 instances must be connected", true);
                constrain(t.instances[i].address[0] - t.instances[i-1].address[max_rw_size - 1],
                    "Address of rw_256 instances must be connected", true);
                constrain(t.instances[i].rw_id[0] - t.instances[i-1].rw_id[max_rw_size - 1],
                    "Rw_id of rw_256 instances must be connected", true);
                constrain(t.instances[i].is_write[0] - t.instances[i-1].is_write[max_rw_size - 1],
                    "Is_write of rw_256 instances must be connected", true);
                for( std::size_t j = 0; j < 16; j++ ) {
                    constrain(t.instances[i].value[0][j] - t.instances[i-1].value[max_rw_size - 1][j],
                        "Value of rw_256 instances must be connected", true);
                }
            }
       }
    public:
        std::vector<std::vector<TYPE>> timeline_lookups() const {
            return _timeline_lookups;
        }
    protected:
        std::vector<std::vector<TYPE>> _timeline_lookups;
    };
}