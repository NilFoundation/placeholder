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

#include "nil/blueprint/zkevm_bbf/small_field/opcodes/abstract_opcode.hpp"
#include <nil/blueprint/zkevm_bbf/small_field/tables/rw_256.hpp>
#include "nil/blueprint/zkevm_bbf/types/opcode_enum.hpp"

namespace nil::blueprint::bbf::zkevm_small_field {

template<typename FieldType>
class opcode_abstract;

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

    zkevm_add_sub_bbf(context_type &context_object,
                      const opcode_input_type<FieldType, stage> &current_state,
                      bool is_add)
                : generic_component<FieldType, stage>(context_object, false) {
        const auto two_16 = zkevm_word_type{1} << 16;

        // A + B = S + carry * 2^256
        std::array<TYPE, 16> A;
        std::array<TYPE, 16> B;
        std::array<TYPE, 16> S;
        std::array<TYPE, 16> carries;
        TYPE carry;

        if constexpr (stage == GenerationStage::ASSIGNMENT) {
            auto x = current_state.stack_top(0);
            auto y = current_state.stack_top(1);
            auto result = is_add ? wrapping_add(x, y)
                                 : wrapping_sub(x, y);

            A = w_to_16_le<TYPE>(is_add ? x : result);
            B = w_to_16_le<TYPE>(y);
            S = w_to_16_le<TYPE>(is_add ? result : x);

            carry = 0;
            for (size_t i = 0; i < 16; ++i) {
                carry = (A[i] + B[i] + carry >= two_16);
                carries[i] = carry;
            }
        }

        carry = 0;
        for (size_t i = 0; i < 16; ++i) {
            allocate(A[i], i, 0);
            allocate(B[i], i + 16, 0);
            allocate(S[i], i, 1);

            allocate(carries[i], 32 + i, 1);
            constrain(carries[i] * (carries[i] - 1));
            constrain(A[i] + B[i] + carry - S[i] - carries[i] * two_16);
            carry = carries[i];
        }

        if constexpr (stage == GenerationStage::CONSTRAINTS) {
            constrain(current_state.pc_next() - current_state.pc(1) - 1);                                     // PC transition
            constrain(current_state.gas(1) - current_state.gas_next() - 3);                                 // GAS transition
            constrain(current_state.stack_size(1) - current_state.stack_size_next() - 1);     // stack_size transition
            constrain(current_state.memory_size(1) - current_state.memory_size_next());         // memory_size transition
            constrain(current_state.rw_counter_next() - current_state.rw_counter(1) - 3);     // rw_counter transition

            lookup(rw_256_table<FieldType, stage>::stack_16_bit_lookup_reversed(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 1,
                    current_state.rw_counter(0),
                    TYPE(0),// is_write
                    is_add ? A : S), "zkevm_rw_256");

            lookup(rw_256_table<FieldType, stage>::stack_16_bit_lookup_reversed(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 2,
                    current_state.rw_counter(0) + 1,
                    TYPE(0),// is_write
                    B), "zkevm_rw_256");

            lookup(rw_256_table<FieldType, stage>::stack_16_bit_lookup_reversed(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 2,
                    current_state.rw_counter(0) + 2,
                    TYPE(1),// is_write
                    is_add ? S : A), "zkevm_rw_256");
        }
    }
};

template<typename FieldType>
class zkevm_add_sub_operation : public opcode_abstract<FieldType> {
  public:
    zkevm_add_sub_operation(bool is_add) : is_add_(is_add) {}

    virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state) override {
        zkevm_add_sub_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state, is_add_);
    }

    virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state) override {
        zkevm_add_sub_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state, is_add_);
    }


    std::size_t rows_amount() override {
        return 2;
    }

  protected:
    bool is_add_;
};

} // namespace bbf::blueprint::nil::zkevm_small_field
