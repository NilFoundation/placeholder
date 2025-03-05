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

#include <nil/blueprint/zkevm/zkevm_word.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/rw_table.hpp>
#include <nil/blueprint/zkevm_bbf/types/opcode.hpp>

namespace nil::blueprint::bbf {

template<typename Field>
class opcode_abstract;

enum cmp_type { C_LT, C_GT };

template<typename Field, GenerationStage stage>
class zkevm_cmp_bbf : generic_component<Field, stage> {
 public:
  using Context = generic_component<Field, stage>::context_type;
  using typename generic_component<Field, stage>::TYPE;

  zkevm_cmp_bbf(
      Context &context, const opcode_input_type<Field, stage> &current_state,
      cmp_type cmp_operation)
      : generic_component<Field,stage>(context, false) {
    std::vector<TYPE> A(16);
    std::vector<TYPE> B(16);

    // We use the absolute difference between the most significant chunks
    // that differ in A and B to check which one is larger; we also mark it
    // to ensure the "most significant" constraint.
    TYPE diff;
    TYPE diff_inv;
    std::vector<TYPE> S(16);

    TYPE lt, gt;

    if constexpr (stage == GenerationStage::ASSIGNMENT) {
      auto a = current_state.stack_top();
      auto b = current_state.stack_top(1);
      
      auto a16 = w_to_16(a);
      auto b16 = w_to_16(b);
      for (size_t i = 0; i < 16; ++i) {
        A[i] = a16[i];
        B[i] = b16[i];
      }

      lt = a < b;
      gt = a > b;

      switch (cmp_operation) {
        case cmp_type::C_LT:
          std::cout << "\t" << a << "<" <<  a << " = " << lt << std::endl;
          break;
        case cmp_type::C_GT:
          std::cout << "\t" << b << ">" <<  b << " = " << gt << std::endl;
          break;
      }

      for (size_t i = 0; i < 16; ++i) {
        if (a16[i] == b16[i]) continue;

        std::cout << "\tNOT equal" << std::endl;
        diff = a16[i] < b16[i] ? b16[i] - a16[i]: a16[i] - b16[i];
        diff_inv = diff.inversed();
        S[i] = 1;
        break;
      }
    }

    auto A_128 = chunks16_to_chunks128<TYPE>(A);
    auto B_128 = chunks16_to_chunks128<TYPE>(B);

    for (size_t i = 0; i < 16; ++i) {
      allocate(A[i], i, 0);
      allocate(B[i], i + 16, 0);

      allocate(S[i], i, 1);
      constrain(S[i] * (S[i] - 1));
    }

    allocate(diff, 16, 1 );
    allocate(diff_inv, 32, 0);
    constrain(diff * (diff * diff_inv - 1));
    constrain(diff_inv * (diff * diff_inv - 1));

    allocate(lt, 17, 1);
    allocate(gt, 18, 1);
    constrain(lt * (lt - 1));
    constrain(gt * (gt - 1));

    TYPE result;
    switch (cmp_operation) {
      case cmp_type::C_LT: result = lt; break;
      case cmp_type::C_GT: result = gt; break;
    }

    // S must not have more than one one (sic!)
    TYPE s_sum;
    for (size_t i = 0; i < 16; ++i) s_sum += S[i];
    constrain(s_sum * (s_sum - 1));

    // If A != B, a chunk is actually marked
    constrain((1 - s_sum) * (A_128.first - B_128.first));
    constrain((1 - s_sum) * (A_128.second - B_128.second));

    // ... and either lt or gt is true
    constrain(lt + gt - s_sum);

    // diff is calluclated for the marked chunk
    TYPE diff_constraint;
    for (size_t i = 0; i < 16; ++i)
      diff_constraint += S[i] * (gt * (A[i] - B[i]) + lt * (B[i] - A[i]));
    constrain(diff - diff_constraint);

    // Finally, S marks *most significant* differing chunk
    for (size_t i = 0; i < 15; ++i) {
      TYPE c;
      for (size_t j = i + 1; j < 16; ++j) c += S[j];

      // A[i] != B[i] => for j > i, S[j] = 0
      constrain(c * (A[i] - B[i]));
    }

    if constexpr (stage == GenerationStage::CONSTRAINTS) {
      constrain(current_state.pc_next() - current_state.pc(1) - 1);                   // PC transition
      constrain(current_state.gas(1) - current_state.gas_next() - 3);                 // GAS transition
      constrain(current_state.stack_size(1) - current_state.stack_size_next() - 1);   // stack_size transition
      constrain(current_state.memory_size(1) - current_state.memory_size_next());     // memory_size transition
      constrain(current_state.rw_counter_next() - current_state.rw_counter(1) - 3);   // rw_counter transition

      lookup({
        TYPE(rw_op_to_num(rw_operation_type::stack)),
        current_state.call_id(1),
        current_state.stack_size(1) - 1,
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
        current_state.call_id(1),
        current_state.stack_size(1) - 2,
        TYPE(0),// storage_key_hi
        TYPE(0),// storage_key_lo
        TYPE(0),// field
        current_state.rw_counter(1) + 1,
        TYPE(0),// is_write
        B_128.first,
        B_128.second
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
};

template<typename Field>
class zkevm_cmp_operation : public opcode_abstract<Field> {
 public:
  zkevm_cmp_operation(cmp_type _cmp_operation) : cmp_operation(_cmp_operation) {}

  virtual std::size_t rows_amount() override {
    return 2;
  }

  virtual void fill_context(
      typename generic_component<Field, GenerationStage::ASSIGNMENT>::context_type &context,
      const opcode_input_type<Field, GenerationStage::ASSIGNMENT> &current_state) override {
    zkevm_cmp_bbf<Field, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state, cmp_operation);
  }

  virtual void fill_context(
      typename generic_component<Field, GenerationStage::CONSTRAINTS>::context_type &context,
      const opcode_input_type<Field, GenerationStage::CONSTRAINTS> &current_state) override {
    zkevm_cmp_bbf<Field, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state, cmp_operation);
  }

 private:
  cmp_type cmp_operation;
};

} // namespace bbf::blueprint::nil
