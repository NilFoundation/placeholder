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
#include <nil/blueprint/zkevm_bbf/small_field/tables/state.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/tables/timeline_table.hpp>

#include <nil/blueprint/zkevm_bbf/small_field/subcomponents/rw_8.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/subcomponents/rw_256.hpp>

namespace nil::blueprint::bbf::zkevm_small_field{
    template<typename FieldType, GenerationStage stage>
    class rw : public generic_component<FieldType, stage> {
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

        using rw_tables_input_type = typename std::conditional<stage==GenerationStage::ASSIGNMENT, short_rw_operations_vector, std::nullptr_t>::type;

        using rw_8_type = rw_8<FieldType, stage>;
        using rw_256_type = rw_256<FieldType, stage>;
        using state_table_type = state_table<FieldType, stage>;
        using timeline_table_type = timeline_table<FieldType, stage>;

        struct input_type{
            rw_tables_input_type                             rw_trace;
            typename timeline_table_type::input_type         timeline;
            typename state_table_type::input_type   state_trace;
        };

        // using value = typename FieldType::value_type;
        // using integral_type = nil::crypto3::multiprecision::big_uint<257>;

        // Chunks 7: op -- 1, id -- 2, address -- 2, rw_id -- 2;
        // Diff for each chunk has its own selector
        // Each op also has its ownn selector

        static table_params get_minimal_requirements(
            std::size_t max_rw_size,
            std::size_t instances_rw_8,
            std::size_t instances_rw_256,
            std::size_t max_state_size
        ) {
            std::size_t witness_amount =
                rw_8_type::get_witness_amount(instances_rw_8)
                + rw_256_type::get_witness_amount(instances_rw_256)
                + state_table_type::get_witness_amount(state_table_mode::timeline)
                + timeline_table_type::get_witness_amount() * (instances_rw_8 + instances_rw_256 + 1)
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
            context_type &context, input_type &input,
            std::size_t max_rw_size,
            std::size_t instances_rw_8,
            std::size_t instances_rw_256,
            std::size_t max_state
        ) {}

        rw(context_type &context_object, const input_type &input,
            std::size_t max_rw_size,
            std::size_t instances_rw_8,
            std::size_t instances_rw_256,
            std::size_t max_state
        ) :generic_component<FieldType,stage>(context_object) {
            std::size_t current_column = 0;

            std::vector<std::size_t> rw_8_area;
            for( std::size_t i = 0; i < rw_8_type::get_witness_amount(instances_rw_8); i++ ) rw_8_area.push_back(current_column++);
            context_type rw_8_ct = context_object.subcontext(rw_8_area,0,max_rw_size);
            rw_8_type t8(rw_8_ct, input.rw_trace, max_rw_size, instances_rw_8);

            std::vector<std::size_t> rw_256_area;
            for( std::size_t i = 0; i < rw_256_type::get_witness_amount(instances_rw_256); i++ ) rw_256_area.push_back(current_column++);
            context_type rw_256_ct = context_object.subcontext(rw_256_area,0,max_rw_size);
            rw_256_type t256(rw_256_ct, input.rw_trace, max_rw_size, instances_rw_256);

            std::vector<std::size_t> state_table_area;
            for( std::size_t i = 0; i < state_table_type::get_witness_amount(state_table_mode::timeline); i++ )
                state_table_area.push_back(current_column++);
            context_type state_table_ct = context_object.subcontext(state_table_area,0,max_state);
            state_table_type st(state_table_ct, input.state_trace, max_state, state_table_mode::timeline);

            std::size_t instances_timeline = instances_rw_8 + instances_rw_256 + 1;
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                BOOST_ASSERT(input.timeline.size() < instances_timeline * (max_rw_size - 1));
            }

            std::vector<std::vector<std::size_t>> timeline_table_areas(instances_timeline);
            std::vector<timeline_table_type> tts;
            for( std::size_t tl_ind = 0; tl_ind < instances_timeline; tl_ind++){
                for( std::size_t i = 0; i < timeline_table_type::get_witness_amount(); i++ ) {
                    timeline_table_areas[tl_ind].push_back(current_column++);
                }
                context_type timeline_table_ct = context_object.subcontext(timeline_table_areas[tl_ind],0,max_rw_size);
                tts.emplace_back(
                    timeline_table_ct,
                    input.timeline,
                    (max_rw_size - 1) * tl_ind,
                    max_rw_size
                );
                if( tl_ind > 0 ) {
                    constrain(tts[tl_ind].rw_id[0] - tts[tl_ind - 1].rw_id[max_rw_size - 1], "Timeline table instances rw_id connection", true);
                    constrain(tts[tl_ind].rw_8_table_selector[0] - tts[tl_ind - 1].rw_8_table_selector[max_rw_size - 1], "Timeline table instances rw_8_table_selector connection", true);
                    constrain(tts[tl_ind].rw_256_table_selector[0] - tts[tl_ind - 1].rw_256_table_selector[max_rw_size - 1], "Timeline table instances rw_256_table_selector connection", true);
                    constrain(tts[tl_ind].state_table_selector[0] - tts[tl_ind - 1].state_table_selector[max_rw_size - 1], "Timeline table instances state_table_selector connection", true);
                    constrain(tts[tl_ind].internal_counter[0] - tts[tl_ind - 1].internal_counter[max_rw_size - 1], "Timeline table instances internal_counter connection", true);
                }
                BOOST_LOG_TRIVIAL(trace) << "Timeline table instance " << tl_ind << " constrained";
            }
            multi_lookup_table("zkevm_timeline", timeline_table_areas, 0, max_rw_size);
            constrain(tts[0].rw_id[0], "first rw_operation in timeline is start operation");

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                // All memory, calldata, returndata rw operations are presented in timeline.
                auto rw_8_to_timeline_lookups = t8.timeline_lookups();
                for( std::size_t i = 0; i < rw_8_to_timeline_lookups.size(); i++ ){
                    rw_8_to_timeline_lookups[i] = context_object.relativize(rw_8_to_timeline_lookups[i], -1);
                    context_object.relative_lookup(rw_8_to_timeline_lookups[i], "zkevm_timeline", 0, max_rw_size);
                }

                // All stack and call_context rw operations are presented in timeline.
                auto rw_256_to_timeline_lookups = t256.timeline_lookups();
                for( std::size_t i = 0; i < rw_256_to_timeline_lookups.size(); i++ ){
                    rw_256_to_timeline_lookups[i] = context_object.relativize(rw_256_to_timeline_lookups[i], -1);
                    context_object.relative_lookup(rw_256_to_timeline_lookups[i], "zkevm_timeline", 0, max_rw_size);
                }

                // All original state operations are presented in timeline
                std::vector<TYPE> state_to_timeline_lookup = {
                    st.is_original[1] * st.rw_id[1],
                    TYPE(0),
                    TYPE(0),
                    st.is_original[1],
                    st.is_original[1] * st.internal_counter[1]
                };
                for( std::size_t i = 0; i < state_to_timeline_lookup.size(); i++ )
                    state_to_timeline_lookup[i] = context_object.relativize(state_to_timeline_lookup[i], -1);
                context_object.relative_lookup(state_to_timeline_lookup, "zkevm_timeline", 0, max_state);

                for( std::size_t tl_ind = 0; tl_ind < instances_timeline; tl_ind++){
                    std::vector<TYPE> timeline_to_rw_8 = {
                        tts[tl_ind].rw_8_table_selector[1],
                        tts[tl_ind].rw_8_table_selector[1] * tts[tl_ind].rw_id[1],
                        tts[tl_ind].rw_8_table_selector[1] * tts[tl_ind].internal_counter[1]
                    };
                    for( std::size_t i = 0; i < timeline_to_rw_8.size(); i++ ){
                        timeline_to_rw_8[i] = context_object.relativize(timeline_to_rw_8[i], -1);
                    }
                    context_object.relative_lookup(timeline_to_rw_8, "zkevm_rw_8_timeline", 0, max_rw_size);
                }

                for( std::size_t tl_ind = 0; tl_ind < instances_timeline; tl_ind++){
                    std::vector<TYPE> timeline_to_rw_256 = {
                        tts[tl_ind].rw_256_table_selector[1],
                        tts[tl_ind].rw_256_table_selector[1] * tts[tl_ind].rw_id[1],
                        tts[tl_ind].rw_256_table_selector[1] * tts[tl_ind].internal_counter[1]
                    };
                    for( std::size_t i = 0; i < timeline_to_rw_256.size(); i++ ){
                        timeline_to_rw_256[i] = context_object.relativize(timeline_to_rw_256[i], -1);
                    }
                    context_object.relative_lookup(timeline_to_rw_256, "zkevm_rw_256_timeline", 0, max_rw_size);
                }

                for( std::size_t tl_ind = 0; tl_ind < instances_timeline; tl_ind++){
                    std::vector<TYPE> timeline_to_state = {
                        tts[tl_ind].state_table_selector[1],
                        tts[tl_ind].state_table_selector[1] * tts[tl_ind].rw_id[1],
                        tts[tl_ind].state_table_selector[1] * tts[tl_ind].internal_counter[1]
                    };
                    for( std::size_t i = 0; i < timeline_to_state.size(); i++ ){
                        timeline_to_state[i] = context_object.relativize(timeline_to_state[i], -1);
                    }
                    context_object.relative_lookup(timeline_to_state, "zkevm_state_timeline", 0, max_rw_size);
                }
            }
        }
    };
}