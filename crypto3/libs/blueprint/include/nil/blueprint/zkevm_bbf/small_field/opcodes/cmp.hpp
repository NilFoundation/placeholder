//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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

#include "nil/blueprint/zkevm_bbf/small_field/opcodes/abstract_opcode.hpp"
#include <nil/blueprint/zkevm_bbf/small_field/tables/rw_256.hpp>
#include "nil/blueprint/zkevm_bbf/types/opcode_enum.hpp"

namespace nil::blueprint::bbf::zkevm_small_field {

template<typename Field>
class opcode_abstract;

enum class cmp_type { C_LT, C_GT, C_SLT, C_SGT, C_EQ };

template<typename Field, GenerationStage stage>
class zkevm_cmp_bbf : generic_component<Field, stage> {
  public:
    using Context = generic_component<Field, stage>::context_type;
    using typename generic_component<Field, stage>::TYPE;

    zkevm_cmp_bbf(
            Context &context, const opcode_input_type<Field, stage> &current_state,
            cmp_type operation)
            : generic_component<Field,stage>(context, false) {
        const auto two_16 = zkevm_word_type{1} << 16;

        const bool is_equals = (operation == cmp_type::C_EQ);
        const bool is_less = (operation == cmp_type::C_LT) || (operation == cmp_type::C_SLT);
        const bool is_unsigned = (operation == cmp_type::C_LT) || (operation == cmp_type::C_GT);

        TYPE result;

        TYPE a_neg;
        TYPE s_neg;

        // Let's begin with the unsigned case.
        // If x < y, B = (x - y) + 2^256 < 2^256 and y + B = x + 2^256. Otherwise,
        // picking B as x - y > 2^255 we get y + B = x = x + 0 * 2^256. Thus,
        // with A = y, B = x - y mod 2^256 and S = x, equation A + B = S +
        // + I(x < y) * 2^256 holds. Reversing this logic, it can be easily shown
        // that if y + B = x + c * 2^256 for c equal to 0 or 1 and 0 <= B < 2^256,
        // then c = I(x < y).    For "x > y" we can just swap the arguments.

        // A + B = S + carry * 2^256
        std::array<TYPE, 16> A;
        std::array<TYPE, 16> B;
        std::array<TYPE, 16> S;
        std::array<TYPE, 16> carries;
        TYPE carry; // = carries[15]

        if constexpr (stage == GenerationStage::ASSIGNMENT) {
            auto x = current_state.stack_top(0);
            auto y = current_state.stack_top(1);

            auto a = is_less ? y : x;
            auto s = is_less ? x : y;
            auto b = wrapping_sub(s, a);

            A = w_to_16_le<TYPE>(a);
            B = w_to_16_le<TYPE>(b);
            S = w_to_16_le<TYPE>(s);

            carry = 0;
            for (size_t i = 0; i < 16; ++i) {
                carry = (A[i] + B[i] + carry >= two_16);
                carries[i] = carry;
            }

            BOOST_ASSERT(carry == s < a);

            if (!is_unsigned) {
                a_neg = a.bit_test(255);
                s_neg = s.bit_test(255);
            }
        }

        carry = 0;
        for (size_t i = 0; i < 16; ++i) {
            allocate(A[i], i, 0);
            allocate(B[i], i + 16, 0);
            allocate(S[i], i, 1);

            allocate(carries[i], 32 + i, 0);
            constrain(carries[i] * (carries[i] - 1));
            constrain(A[i] + B[i] + carry - S[i] - carries[i] * two_16);
            carry = carries[i];
        }

        if (is_equals) {
            TYPE b_sum;
            for (auto &b : B) b_sum += b;

            TYPE b_sum_inv;
            if constexpr (stage == GenerationStage::ASSIGNMENT)
                b_sum_inv = (b_sum == 0) ? 0 : b_sum.inversed();

            allocate(b_sum_inv, 16, 1);
            constrain(b_sum * (1 - b_sum * b_sum_inv));

            result = 1 - b_sum * b_sum_inv;
        } else if (is_unsigned) {
            result = carry;
        } else {
            allocate(a_neg, 17, 1);
            allocate(s_neg, 18, 1);

            // When s < a dependin on the sign?
            // a) s < 0, a >= 0: always
            // b) s >= 0, a >= 0: if s < a as unsigned values
            // c) s >= 0, a < 0: never
            // d) s < 0, a < 0: s < a <=> 2^256 + a < 2^256 + b;
            //        these are the encodings of negative numbers as uint!
            //        i.e. when a < b if interpreded in unsigned comparison.
            // Note that these cases are mutually exclusive, and we can add them up.
            result = s_neg * (1 - a_neg) +
                     (1 - s_neg) * (1 - a_neg) * carry +
                     s_neg * a_neg * carry;

            allocate(result, 16, 1);

            TYPE a_diff;
            TYPE s_diff;

            // Check the sign bit by adding 2^15 to the biggest chunk.
            // The carry-on bit is 1 iff the sign bit is 1
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                a_diff = a_neg != 0 ? A[15] - (1<<15) : A[15] + (1<<15);
                s_diff = s_neg != 0 ? S[15] - (1<<15) : S[15] + (1<<15);
            }

            allocate(a_diff, 19, 1);
            allocate(s_diff, 20, 1);

            constrain(a_neg * (1 - a_neg));
            constrain(A[15] + (1<<15) - (1ull<<16) * a_neg - a_diff);

            constrain(s_neg * (1 - s_neg));
            constrain(S[15] + (1<<15) - (1ull<<16) * s_neg - s_diff);
        }

        if constexpr (stage == GenerationStage::CONSTRAINTS) {
            constrain(current_state.pc_next() - current_state.pc(1) - 1);                                     // PC transition
            constrain(current_state.gas(1) - current_state.gas_next() - 3);                                 // GAS transition
            constrain(current_state.stack_size(1) - current_state.stack_size_next() - 1);     // stack_size transition
            constrain(current_state.memory_size(1) - current_state.memory_size_next());         // memory_size transition
            constrain(current_state.rw_counter_next() - current_state.rw_counter(1) - 3);     // rw_counter transition

            lookup(rw_256_table<Field, stage>::stack_16_bit_lookup_reversed(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 1,
                    current_state.rw_counter(0),
                    TYPE(0),// is_write
                    is_less ? S : A), "zkevm_rw_256");

            lookup(rw_256_table<Field, stage>::stack_16_bit_lookup_reversed(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 2,
                    current_state.rw_counter(0) + 1,
                    TYPE(0),// is_write
                    is_less ? A : S), "zkevm_rw_256");

            lookup(rw_256_table<Field, stage>::stack_16_bit_lookup_reversed(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 2,
                    current_state.rw_counter(0) + 2,
                    TYPE(1),// is_write
                    std::array<TYPE, 16>{result}), "zkevm_rw_256");
        }
    }

  private:
    using generic_component<Field, stage>::allocate;
    using generic_component<Field, stage>::copy_constrain;
    using generic_component<Field, stage>::constrain;
    using generic_component<Field, stage>::lookup;
    using generic_component<Field, stage>::lookup_table;
};

template<typename Field>
class zkevm_cmp_operation : public opcode_abstract<Field> {
  public:
    zkevm_cmp_operation(cmp_type cmp_operation) : cmp_operation_(cmp_operation) {}

    virtual std::size_t rows_amount() override {
        return 2;
    }

    virtual void fill_context(
            typename generic_component<Field, GenerationStage::ASSIGNMENT>::context_type &context,
            const opcode_input_type<Field, GenerationStage::ASSIGNMENT> &current_state) override {
        zkevm_cmp_bbf<Field, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state, cmp_operation_);
    }

    virtual void fill_context(
            typename generic_component<Field, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<Field, GenerationStage::CONSTRAINTS> &current_state) override {
        zkevm_cmp_bbf<Field, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state, cmp_operation_);
    }

  private:
    cmp_type cmp_operation_;
};

} // namespace bbf::blueprint::nil::zkevm_small_field
