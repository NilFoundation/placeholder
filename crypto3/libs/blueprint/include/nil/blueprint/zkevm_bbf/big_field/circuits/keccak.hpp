//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
// Copyright (c) 2025 Antoine Cyr <antoinecyr@nil.foundation>
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

#include <nil/blueprint/bbf/components/hashes/keccak/keccak_dynamic.hpp>
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/subcomponents/keccak_table.hpp>

namespace nil::blueprint::bbf::zkevm_big_field{
    template<typename FieldType, GenerationStage stage>
    class zkevm_keccak : public generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

    public:
        using KeccakDynamic = typename bbf::keccak_dynamic<FieldType, stage>;
        using KeccakTable = typename zkevm_big_field::keccak_table<FieldType, stage>;

        using typename generic_component<FieldType, stage>::table_params;
        using typename generic_component<FieldType, stage>::TYPE;
        using integral_type = nil::crypto3::multiprecision::big_uint<257>;
        using private_input_type =
            typename std::conditional<stage == GenerationStage::ASSIGNMENT,
                                    zkevm_keccak_buffers, std::nullptr_t>::type;

        struct input_type {
            TYPE rlc_challenge;
            private_input_type private_input;
        };

        static table_params get_minimal_requirements(
            std::size_t max_keccak_blocks) {
            return {
                .witnesses = 20,
                .public_inputs = 1,
                .constants = 3,
                .rows = KeccakDynamic::get_minimal_requirements(max_keccak_blocks)
                            .rows};
        }

        static void allocate_public_inputs(context_type& context,
                                        input_type& input,
                                        std::size_t max_keccak_blocks) {
            context.allocate(input.rlc_challenge, 0, 0,
                            column_type::public_input);
        }

        zkevm_keccak(context_type& context_object, const input_type& input,
                    std::size_t max_keccak_blocks)
            : generic_component<FieldType, stage>(context_object) {
            std::vector<std::size_t> keccak_lookup_area;
            std::vector<std::size_t> keccak_dynamic_lookup_area;
            std::size_t current_column = 0;
            std::size_t dynamic_rows =
                KeccakDynamic::get_minimal_requirements(max_keccak_blocks).rows;

            for (std::size_t i = 0; i < KeccakTable::get_witness_amount(); i++) {
                keccak_lookup_area.push_back(current_column++);
            }

            for (std::size_t i = 0;
                i < KeccakDynamic::get_minimal_requirements(max_keccak_blocks)
                        .witnesses;
                i++) {
                keccak_dynamic_lookup_area.push_back(current_column++);
            }

            context_type keccak_ct = context_object.subcontext(
                keccak_lookup_area, 1, dynamic_rows + 1);

            context_type keccak_dynamic_ct = context_object.subcontext(
                keccak_dynamic_lookup_area, 1, dynamic_rows + 1);
            typename KeccakDynamic::input_type input_dynamic;
            typename KeccakTable::input_type input_keccak_table;
            TYPE rlc_challenge;

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                rlc_challenge = input.rlc_challenge;
                input_dynamic.rlc_challenge = input.rlc_challenge;
                for (const auto& item : input.private_input.get_data()) {
                    const auto& buffer = item.first;
                    const auto& zkevm_word = item.second;

                    TYPE hi = w_hi<FieldType>(zkevm_word);
                    TYPE lo = w_lo<FieldType>(zkevm_word);
                    std::pair<TYPE, TYPE> pair_values = {hi, lo};

                    input_dynamic.input.emplace_back(buffer, pair_values);
                }
                input_keccak_table.rlc_challenge = input.rlc_challenge;
                input_keccak_table.private_input = input.private_input;
            }
            KeccakTable kt =
                KeccakTable(keccak_ct, input_keccak_table, max_keccak_blocks);

            allocate(rlc_challenge, 0, 0);
            input_dynamic.rlc_challenge = rlc_challenge;
            KeccakDynamic kd = KeccakDynamic(keccak_dynamic_ct, input_dynamic,
                                            max_keccak_blocks);

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                std::vector<TYPE> tmp;
                for (std::size_t i = 0; i < max_keccak_blocks; i++) {
                    tmp = {TYPE(1), kt.RLC[i], kt.hash_hi[i], kt.hash_lo[i],
                        kt.is_last[i]};
                    lookup(tmp, "keccak_dynamic");
                    tmp = {kd.m[i].h.is_last, kd.m[i].h.RLC, kd.m[i].h.hash_hi,
                        kd.m[i].h.hash_lo};
                    lookup(tmp, "keccak_table");
                }
            }
        }
    };
}