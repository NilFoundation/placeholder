//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
// Copyright (c) 2025 Alexander Vasilyev <mizabrik@nil.foundation>
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

#include <numeric>
#include <algorithm>

#include <nil/blueprint/zkevm_bbf/small_field/opcodes/abstract_opcode.hpp>

namespace nil::blueprint::bbf::zkevm_small_field{
    template<typename FieldType, GenerationStage stage>
    class zkevm_exp_bbf : generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;
    public:
        using typename generic_component<FieldType,stage>::TYPE;

        zkevm_exp_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state):
            generic_component<FieldType,stage>(context_object, false)
        {
            // ! Not implemented yet
            // std::vector<TYPE> A(16);
            // std::vector<TYPE> D(16);
            // std::vector<TYPE> R(16);
            // TYPE s; // flags if we use a lookup from exp circuit rather than calculate inplace

            // std::vector<TYPE> D_gt_255(16);
            // std::vector<TYPE> D_gt_diff(16);
            // std::vector<TYPE> D_first_inv(16); // D_inv[i] for min i s.t. D[i] != 0, else 0

            // if constexpr (stage == GenerationStage::ASSIGNMENT) {
            //     auto a = w_to_16(current_state.stack_top());
            //     auto d = w_to_16(current_state.stack_top(1));
            //     auto r = w_to_16(exp_by_squaring(current_state.stack_top(), current_state.stack_top(1)));
            //     s = 1;
            //     if (current_state.stack_top(1) == 0) s = 0;
            //     if (current_state.stack_top(1) == 1) s = 0;

            //     std::cout << "\t"
            //         << current_state.stack_top() << " ^ "
            //         << current_state.stack_top(1) << " = "
            //         << exp_by_squaring(current_state.stack_top(), current_state.stack_top(1))
            //         << std::endl;

            //     bool had_nonzero = false;
            //     for (std::size_t i = 0; i < 16; ++i) {
            //         A[i] = a[i];
            //         D[i] = d[i];
            //         R[i] = r[i];

            //         D_gt_255[i] = d[i] > 0xFF;
            //         D_gt_diff[i] = 0xFF + (d[i] > 0xFF) * 0x10000 - d[i];

            //         if (!had_nonzero && d[i]) {
            //             had_nonzero = true;
            //             D_first_inv[i] = D[i].inversed();
            //         }
            //     }
            // }

            // TYPE d_sum;
            // TYPE d_first_nonzero_sum;
            // for (std::size_t i = 0; i < 16; ++i) {
            //     allocate(A[i], i, 2);
            //     allocate(R[i], 16 + i, 2);
            //     allocate(D[i], i, 1);

            //     allocate(D_gt_diff[i], 16 + i, 1);
            //     allocate(D_gt_255[i], i, 0);
            //     constrain(D_gt_255[i] * (1 - D_gt_255[i]));
            //     constrain(D[i] + D_gt_diff[i] - 0xFF - D_gt_255[i] * 0x10000);

            //     allocate(D_first_inv[i], 32 + i, 1);
            //     // D_first_inv[i] != 0 => it is an inverse
            //     constrain(D_first_inv[i] * (1 - D[i] * D_first_inv[i]));

            //     d_sum += D[i];
            //     d_first_nonzero_sum += D[i] * D_first_inv[i];
            // }


            // auto A_128 = chunks16_to_chunks128<TYPE>(A);
            // auto D_128 = chunks16_to_chunks128<TYPE>(D);
            // auto R_128 = chunks16_to_chunks128<TYPE>(R);

            // // If d[i] != 0, for j > i D_first_inv[j] = 0, since it isn't first
            // for (std::size_t i = 0; i < 15; ++i) {
            //     TYPE next_invs;
            //     for (int j = i + 1; j < 16; ++j) next_invs += D[j] * D_first_inv[j];
            //     constrain(D[i] * next_invs);
            // }

            // // If d != 0, d_first_inv has a non-zero element
            // constrain(d_sum * (1 - d_first_nonzero_sum));
            // // else, the sum is 0 so it's a [D != 0] too
            // TYPE d_ne_0 = d_first_nonzero_sum;
            // allocate(d_ne_0, 37, 2);

            // TYPE d_len;
            // for (std::size_t i = 0; i < 16; ++i) {
            //     d_len += D[i] * D_first_inv[i] * (
            //         D_gt_255[i] + 1 // this word's bytes
            //         + 2 * (15 - i)  // less significant bytes
            //     );
            // }
            // allocate(d_len, 32, 2);

            // // D = 1 <=> d[15] is first non-zero and d[15] = 1
            // TYPE d_is_1_w;
            // if constexpr (stage == GenerationStage::ASSIGNMENT)
            //     d_is_1_w = D[15] == 1 ? 0 : (D[15] - 1).inversed();
            // allocate(d_is_1_w, 33, 2);
            // constrain((D[15] - 1) * (1 - (D[15] - 1) * d_is_1_w));

            // TYPE d_is_1_aux = D[15] * D_first_inv[15];
            // allocate(d_is_1_aux, 34, 2);
            // // TYPE d_is_1 = (1 - (D[15] - 1) * d_is_1_w) * D[15] * D_first_inv[15];
            // TYPE d_is_1 = (1 - (D[15] - 1) * d_is_1_w) * d_is_1_aux;
            // allocate(d_is_1, 35, 2);

            // allocate(s, 36, 2);
            // constrain(s * (s-1));

            // // s == 0 => d == 0 || d == 1
            // constrain((1 - s) * d_ne_0 * (1 - d_is_1));

            // //  d == 0 => s == 0 && R == 1
            // constrain((1 - d_ne_0) * s);
            // constrain((1 - d_ne_0) * R_128.first);
            // constrain((1 - d_ne_0) * (R_128.second - 1));

            // //  d == 1 => s == 0 && R == A
            // constrain(d_is_1 * s);
            // constrain(d_is_1 * (R_128.first - A_128.first));
            // constrain(d_is_1 * (R_128.second - A_128.second));

            // if constexpr( stage == GenerationStage::CONSTRAINTS ){
            //     constrain(current_state.pc_next() - current_state.pc(2) - 1);                   // PC transition
            //     constrain(current_state.gas(2) - current_state.gas_next() - 10 - 50 * d_len);   // GAS transition
            //     constrain(current_state.stack_size(2) - current_state.stack_size_next() - 1);   // stack_size transition
            //     constrain(current_state.memory_size(2) - current_state.memory_size_next());     // memory_size transition
            //     constrain(current_state.rw_counter_next() - current_state.rw_counter(2) - 3);   // rw_counter transition
            //     std::vector<TYPE> tmp;
            //     tmp = rw_table<FieldType, stage>::stack_lookup(
            //         current_state.call_id(0),
            //         current_state.stack_size(0) - 1,
            //         current_state.rw_counter(0),
            //         TYPE(0),// is_write
            //         A_128.first,
            //         A_128.second
            //     );
            //     lookup(tmp, "zkevm_rw");
            //     tmp = rw_table<FieldType, stage>::stack_lookup(
            //         current_state.call_id(1),
            //         current_state.stack_size(1) - 2,
            //         current_state.rw_counter(1) + 1,
            //         TYPE(0),// is_write
            //         D_128.first,
            //         D_128.second
            //     );
            //     lookup(tmp, "zkevm_rw");
            //     tmp = rw_table<FieldType, stage>::stack_lookup(
            //         current_state.call_id(0),
            //         current_state.stack_size(0) - 2,
            //         current_state.rw_counter(0) + 2,
            //         TYPE(1),// is_write
            //         R_128.first,
            //         R_128.second
            //     );
            //     lookup(tmp, "zkevm_rw");
            //     tmp = {
            //         s,
            //         s * A_128.first,
            //         s * A_128.second,
            //         s * D_128.first,
            //         s * D_128.second,
            //         s * R_128.first,
            //         s * R_128.second
            //     };
            //     lookup(tmp, "zkevm_exp");
            // }
        }
    };

    template<typename FieldType>
    class zkevm_exp_operation : public opcode_abstract<FieldType> {
    public:
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
        )  override {
            zkevm_exp_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
        }
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
        ) override  {
            zkevm_exp_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
        }
        virtual std::size_t rows_amount() override {
            return 3;
        }
    };
}
