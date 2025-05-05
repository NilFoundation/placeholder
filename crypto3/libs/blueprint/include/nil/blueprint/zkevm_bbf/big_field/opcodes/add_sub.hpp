//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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

#include <nil/blueprint/zkevm_bbf/big_field/opcodes/abstract_opcode.hpp>

namespace nil::blueprint::bbf::zkevm_big_field{
    template<typename FieldType, GenerationStage stage>
    class zkevm_add_sub_bbf : generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;
    public:
        using typename generic_component<FieldType,stage>::TYPE;

        zkevm_add_sub_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state, bool is_add):
            generic_component<FieldType,stage>(context_object, false)
        {
            zkevm_word_type two_128 = zkevm_word_type(1) << 128;

            std::vector<TYPE> A(16);
            std::vector<TYPE> B(16);
            std::vector<TYPE> S(16); // S = A+B
            TYPE carry0;
            TYPE carry1;

            if constexpr( stage == GenerationStage::ASSIGNMENT ){
                auto a = w_to_16(current_state.stack_top());
                auto b = w_to_16(current_state.stack_top(1));
                auto s = is_add
                            ? w_to_16(wrapping_add(current_state.stack_top(),
                                                    current_state.stack_top(1)))
                            : w_to_16(wrapping_sub(current_state.stack_top(),
                                                    current_state.stack_top(1)));

                for( std::size_t i = 0; i < 16; i++){
                    A[i] = is_add? a[i]: s[i];
                    B[i] = b[i];
                    S[i] = is_add? s[i] : a[i];
                }
                auto A_128 = chunks16_to_chunks128<TYPE>(A);
                auto B_128 = chunks16_to_chunks128<TYPE>(B);
                auto S_128 = chunks16_to_chunks128<TYPE>(S);
                carry0 = (A_128.second + B_128.second >= two_128);
                carry1 = (A_128.first + B_128.first + carry0 >= two_128);
            }
            for( std::size_t i = 0; i < 16; i++){
                allocate(A[i], i, 0);
                allocate(B[i], i + 16, 0);
                allocate(S[i], i, 1);
            }
            allocate(carry0, 32, 0);
            allocate(carry1, 33, 0);
            auto A_128 = chunks16_to_chunks128<TYPE>(A);
            auto B_128 = chunks16_to_chunks128<TYPE>(B);
            auto S_128 = chunks16_to_chunks128<TYPE>(S);
            constrain(carry0 * (carry0 - 1));
            constrain(carry1 * (carry1 - 1));
            constrain(A_128.second + B_128.second - carry0 * two_128 - S_128.second);
            constrain(A_128.first + B_128.first + carry0 - carry1 * two_128 - S_128.first);
            if constexpr( stage == GenerationStage::CONSTRAINTS ){
                constrain(current_state.pc_next() - current_state.pc(1) - 1);                   // PC transition
                constrain(current_state.gas(1) - current_state.gas_next() - 3);                 // GAS transition
                constrain(current_state.stack_size(1) - current_state.stack_size_next() - 1);   // stack_size transition
                constrain(current_state.memory_size(1) - current_state.memory_size_next());     // memory_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(1) - 3);   // rw_counter transition
                std::vector<TYPE> tmp;
                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(1),
                    current_state.stack_size(1) - 1,
                    current_state.rw_counter(1),
                    TYPE(0),// is_write
                    is_add? A_128.first: S_128.first,
                    is_add? A_128.second: S_128.second
                );
                lookup(tmp, "zkevm_rw");
                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(1),
                    current_state.stack_size(1) - 2,
                    current_state.rw_counter(1) + 1,
                    TYPE(0),// is_write
                    B_128.first,
                    B_128.second
                );
                lookup(tmp, "zkevm_rw");
                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(1),
                    current_state.stack_size(1) - 2,
                    current_state.rw_counter(1) + 2,
                    TYPE(1),// is_write
                    is_add? S_128.first: A_128.first,
                    is_add? S_128.second: A_128.second
                );
                lookup(tmp, "zkevm_rw");
            }
        }
    };

    template<typename FieldType>
    class zkevm_add_sub_operation : public opcode_abstract<FieldType> {
    public:
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
        ) override {
            zkevm_add_sub_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state, is_add);
        }
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
        ) override  {
            zkevm_add_sub_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state, is_add);
        }
        zkevm_add_sub_operation(bool _is_add):is_add(_is_add){
        }
        std::size_t rows_amount() override {
            return 2;
        }
    protected:
        bool is_add;
    };
}
