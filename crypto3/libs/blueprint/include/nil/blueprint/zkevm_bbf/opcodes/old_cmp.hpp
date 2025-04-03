//---------------------------------------------------------------------------//
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

#include <nil/blueprint/zkevm_bbf/subcomponents/rw_table.hpp>
#include <nil/blueprint/zkevm_bbf/types/opcode.hpp>

namespace nil::blueprint::bbf {

template<typename Field>
class opcode_abstract;

enum old_cmp_type { OC_LT, OC_GT, OC_SLT, OC_SGT, OC_EQ };

template<typename Field, GenerationStage stage>
class zkevm_old_cmp_bbf : generic_component<Field, stage> {
 public:
  using Context = generic_component<Field, stage>::context_type;
  using typename generic_component<Field, stage>::TYPE;

  zkevm_old_cmp_bbf(
      Context &context, const opcode_input_type<Field, stage> &current_state,
      old_cmp_type cmp_operation)
      : generic_component<Field,stage>(context, false) {
    // a + b = c + r*2^T
    std::vector<TYPE> A(16);
    std::vector<TYPE> B(16);
    std::vector<TYPE> R(16);
    TYPE result;

    zkevm_word_type r;
 
    bool is_less = (cmp_operation == OC_LT) || (cmp_operation == OC_SLT);

    if constexpr (stage == GenerationStage::ASSIGNMENT) {
      auto x = current_state.stack_top();
      auto y = current_state.stack_top(1);

      auto a = is_less ? y : x;
      auto c = is_less ? x : y;
      
      auto a16 = w_to_16(a);
      auto c16 = w_to_16(c);

      r = a > c;

      if (cmp_operation == OC_SLT) {
        result = (is_negative(x) && !is_negative(y)) || ((is_negative(x) == is_negative(y)) && r);
      } else if (cmp_operation == OC_SGT) {
        result = (!is_negative(x) && is_negative(y)) || ((is_negative(x) == is_negative(y)) && r);
      } else if (cmp_operation == OC_EQ) {
        result = (x == y);
      } else {
        result = r;
      }

      auto b = wrapping_sub(c, a);
      auto b16 = w_to_16(b);

      for (size_t i = 0; i < 16; ++i) {
        A[i] = a16[i];
        B[i] = b16[i];
        R[i] = c16[i];
      }
    }

    std::cout << "assmnt done\n";

    TYPE b_sum;
    for (size_t i = 0; i < 16; ++i) {
      allocate(A[i], i, 0);
      allocate(B[i], i, 1);
      allocate(R[i], i, 2);

      b_sum += B[i];
    }

    allocate(result, 16, 1);

    auto A_48 = chunks_to_48(A);
    auto B_48 = chunks_to_48(B);
    auto R_48 = chunks_to_48(R);

    const size_t n_carries = 16 / 3 + 1;
    std::vector<TYPE> carries(n_carries + 1); // 0 for uniformity

    if constexpr (stage == GenerationStage::ASSIGNMENT) {
      bool carry = 0;
      carries.back() = 0;
      for (size_t i = n_carries - 1; i > 0; --i) { // MS chunk order!
        carry = (carry + A_48[i] + B_48[i]) >= (1ull << 48);
        carries[i] = carry;
      }
      carry = (carry + A[0] + B[0]) >= (1ull << 16);
      BOOST_ASSERT(carry == r);
      carries[0] = carry;
    }

    for (size_t i = 0; i < n_carries; ++i) {
      allocate(carries[i], 16 + i, 2);
      constrain(carries[i] * (1 - carries[i]));
    }
    
    for (size_t i = 0; i < n_carries; ++i) {
      auto overflow = carries[i] * (i > 0 ? 1ull<<48 : 1ull<<16);
      constrain(carries[i+1] + A_48[i] + B_48[i] - R_48[i] - overflow);
    }

    if (cmp_operation == OC_EQ) {
      TYPE b_sum_inv;
      if constexpr (stage == GenerationStage::ASSIGNMENT)
        b_sum_inv = b_sum == 0 ? 0 : b_sum.inversed();

      allocate(b_sum_inv, 32, 1);
      constrain(b_sum * (1 - b_sum * b_sum_inv)); // added

      // constrain(b_sum * result) seems redundant
      constrain(result - (1 - b_sum * b_sum_inv));
    } else if (cmp_operation == OC_SLT || cmp_operation == OC_SGT) {
      // find the sign bit by adding 2^15 to the biggest chunk. The carry-on bit is 1 iff the sign bit is 1
      TYPE a_neg, a_diff;
      TYPE r_neg, r_diff;

      if constexpr (stage == GenerationStage::ASSIGNMENT) {
        a_neg = A[0] >= 1<<15;
        a_diff = a_neg != 0 ? A[0] - (1<<15) : A[0] + (1<<15);

        r_neg = R[0] >= 1<<15;
        r_diff =  r_neg != 0 ? R[0] - (1<<15) : R[0] + (1<<15);
      }

      allocate(a_diff, 17, 1);
      allocate(a_neg, 18, 1);
      allocate(r_diff, 19, 1);
      allocate(r_neg, 20, 1);

      constrain(a_neg * (1 - a_neg));
      constrain(A[0] + (1<<15) - (1ull<<16) * a_neg - a_diff);

      constrain(r_neg * (1 - r_neg));
      constrain(R[0] + (1<<15) - (1ull<<16) * r_neg - r_diff);

      // result = (r_neg & !a_neg) | ((r_neg&a_neg | !r_neg & !a_neg) & c) =
      // = (r_neg & !a_neg) | (c & !a_neg) | (c & r_neg) =
      // = r_neg(1-a_neg) + c(1-a_neg) + c r_neg - 2*r_neg(1-a_neg)c
      constrain(result - r_neg * (1 - a_neg)
                       - carries[0] * (1 - a_neg)
                       - carries[0] * r_neg
                       + 2 * carries[0] * r_neg * (1 - a_neg));
    } else {
      constrain(result - carries[0]);
    }

    auto A_128 = chunks16_to_chunks128<TYPE>(A);
    auto R_128 = chunks16_to_chunks128<TYPE>(R);

    if constexpr (stage == GenerationStage::CONSTRAINTS) {
      constrain(current_state.pc_next() - current_state.pc(1) - 1);                   // PC transition
      constrain(current_state.gas(1) - current_state.gas_next() - 3);                 // GAS transition
      constrain(current_state.stack_size(1) - current_state.stack_size_next() - 1);   // stack_size transition
      constrain(current_state.memory_size(1) - current_state.memory_size_next());     // memory_size transition
      constrain(current_state.rw_counter_next() - current_state.rw_counter(1) - 3);   // rw_counter transition

      lookup({
        TYPE(rw_op_to_num(rw_operation_type::stack)),
        current_state.call_id(1),
        current_state.stack_size(1) - (is_less ? 2 : 1),
        TYPE(0),// storage_key_hi
        TYPE(0),// storage_key_lo
        TYPE(0),// field
        current_state.rw_counter(1),
        TYPE(0),// is_write
        A_128.first,
        A_128.second
      }, "zkevm_rw");

      lookup({
        TYPE(rw_op_to_num(rw_operation_type::stack)),
        current_state.call_id(2),
        current_state.stack_size(2) - (is_less ? 1 : 2),
        TYPE(0),// storage_key_hi
        TYPE(0),// storage_key_lo
        TYPE(0),// field
        current_state.rw_counter(2) + 1,
        TYPE(0),// is_write
        R_128.first,
        R_128.second
      }, "zkevm_rw");

      lookup({
        TYPE(rw_op_to_num(rw_operation_type::stack)),
        current_state.call_id(1),
        current_state.stack_size(1) - 2,
        TYPE(0),// storage_key_hi
        TYPE(0),// storage_key_lo
        TYPE(0),// field
        current_state.rw_counter(1) + 2,
        TYPE(1),// is_write
        TYPE(0),
        result
      }, "zkevm_rw");

      // using RwTable = rw_table<FieldType, stage>;

      // lookup(RwTable::stack_lookup(
      //            current_state.call_id(1), current_state.stack_size(1) - 1,
      //            current_state.rw_counter(1), /* is_write = */ TYPE(0),
      //            A_128.first, A_128.second), "zkevm_rw");

      // lookup(RwTable::stack_lookup(
      //            current_state.call_id(1), current_state.stack_size(1) - 2,
      //            current_state.rw_counter(1) + 1, /* is_write = */ TYPE(0),
      //            B_128.first, B_128.second), "zkevm_rw");

      // lookup(RwTable::stack_lookup(
      //            current_state.call_id(1), current_state.stack_size(1) - 2,
      //            current_state.rw_counter(1) + 2, /* is_write = */ TYPE(1),
      //            TYPE(0), result), "zkevm_rw");
    } else {
      std::cout << "\tASSIGNMENT implemented" << std::endl;
    }
  }

 private:
  using generic_component<Field, stage>::allocate;
  using generic_component<Field, stage>::copy_constrain;
  using generic_component<Field, stage>::constrain;
  using generic_component<Field, stage>::lookup;
  using generic_component<Field, stage>::lookup_table;

  static std::vector<TYPE> chunks_to_48(const std::vector<TYPE> &chunks) {
    std::vector<TYPE> res(6);
    res[0] = chunks[0];
    for (size_t i = 0; i < 5; ++i)
      res[i + 1] = chunks[3*i + 3]
        + chunks[3*i + 2] * (1ull<<16)
        + chunks[3*i + 1] * (1ull<<32);
    return res;
  }
};

template<typename Field>
class zkevm_old_cmp_operation : public opcode_abstract<Field> {
 public:
  zkevm_old_cmp_operation(old_cmp_type _cmp_operation) : cmp_operation(_cmp_operation) {}

  virtual std::size_t rows_amount() override {
    return 3;
  }

  virtual void fill_context(
      typename generic_component<Field, GenerationStage::ASSIGNMENT>::context_type &context,
      const opcode_input_type<Field, GenerationStage::ASSIGNMENT> &current_state) override {
    zkevm_old_cmp_bbf<Field, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state, cmp_operation);
  }

  virtual void fill_context(
      typename generic_component<Field, GenerationStage::CONSTRAINTS>::context_type &context,
      const opcode_input_type<Field, GenerationStage::CONSTRAINTS> &current_state) override {
    zkevm_old_cmp_bbf<Field, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state, cmp_operation);
  }

 private:
  old_cmp_type cmp_operation;
};

} // namespace bbf::blueprint::nil
