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

#include <algorithm>
#include <numeric>

#include <nil/blueprint/zkevm_bbf/types/opcode.hpp>

namespace nil {
namespace blueprint {
namespace bbf {
template<typename FieldType>
class opcode_abstract;

// Revert tstorage with revert
// Empty tstorage at the end of tx

template<typename FieldType, GenerationStage stage>
class zkevm_tstore_bbf : generic_component<FieldType, stage> {
  using typename generic_component<FieldType, stage>::context_type;
  using generic_component<FieldType, stage>::allocate;
  using generic_component<FieldType, stage>::copy_constrain;
  using generic_component<FieldType, stage>::constrain;
  using generic_component<FieldType, stage>::lookup;
  using generic_component<FieldType, stage>::lookup_table;

public:
  using typename generic_component<FieldType, stage>::TYPE;
  using value_type = typename FieldType::value_type;
  constexpr static const value_type two_128 =
      0x100000000000000000000000000000000_big_uint254;

  zkevm_tstore_bbf(context_type &context_object,
                   const opcode_input_type<FieldType, stage> &current_state)
      : generic_component<FieldType, stage>(context_object, false) {
    TYPE K_hi;  // Storage key
    TYPE K_lo;
    TYPE U_hi;  // Old storage value
    TYPE U_lo;
    TYPE V_hi;  // New storage value
    TYPE V_lo;
    TYPE call_context_address_hi;
    TYPE call_context_address_lo;
    TYPE tx_id;
    TYPE transient_w_id_before;

    if constexpr (stage == GenerationStage::ASSIGNMENT) {
      auto storage_key = current_state.stack_top();
      auto call_context_address = current_state.call_context_address();

      K_hi = w_hi<FieldType>(storage_key);
      K_lo = w_lo<FieldType>(storage_key);
      std::cout << "\tKey = " << current_state.stack_top() << "=[" << storage_key
                << "] value = " << current_state.stack_top(1) << std::endl;
      transient_w_id_before = current_state.last_write(
          rw_operation_type::transient_storage, call_context_address, 0, storage_key);

      U_hi = w_hi<FieldType>(current_state.transient_storage(storage_key));
      U_lo = w_lo<FieldType>(current_state.transient_storage(storage_key));
      V_hi = w_hi<FieldType>(current_state.stack_top(1));
      V_lo = w_lo<FieldType>(current_state.stack_top(1));

      tx_id = current_state.tx_id();

      call_context_address_hi = w_hi<FieldType>(call_context_address);
      call_context_address_lo = w_lo<FieldType>(call_context_address);

      std::cout << "\taddress = " << std::hex << call_context_address_hi << " "
                << call_context_address_lo << std::dec << std::endl;
      std::cout << "\tK = " << std::hex << K_hi << " " << K_lo << std::dec << std::endl;
      std::cout << "\tu = " << std::hex << current_state.transient_storage(storage_key)
                << std::dec << std::endl;
      std::cout << "\tv = " << std::hex << current_state.stack_top(1) << std::dec
                << std::endl;
      std::cout << "\ttx_id = " << tx_id << std::endl;
    }

    allocate(call_context_address_hi, 32, 0);
    allocate(call_context_address_lo, 33, 0);
    allocate(K_hi, 34, 0);
    allocate(K_lo, 35, 0);
    allocate(tx_id, 36, 0);
    allocate(V_hi, 37, 0);
    allocate(V_lo, 38, 0);
    allocate(U_hi, 39, 0);
    allocate(U_lo, 40, 0);
    allocate(transient_w_id_before, 44, 0);

    // TODO: Append refunds
    if constexpr (stage == GenerationStage::CONSTRAINTS) {
      constrain(current_state.pc_next() - current_state.pc(0) - 1);      // PC transition
      constrain(current_state.gas(0) - current_state.gas_next() - 100);  // GAS transition
      constrain(current_state.stack_size(0) - current_state.stack_size_next() -
                2);  // stack_size transition
      constrain(current_state.memory_size(0) -
                current_state.memory_size_next());  // memory_size transition
      constrain(current_state.rw_counter_next() - current_state.rw_counter(0) -
                3);  // rw_counter transition

      std::vector<TYPE> tmp;
      // Prove tx_id correctness
      tmp = rw_table<FieldType, stage>::call_context_lookup(
          current_state.call_id(0), std::size_t(call_context_field::tx_id), TYPE(0),
          tx_id);
      lookup(tmp, "zkevm_rw");
      // Prove call_context_address correctness
      tmp = rw_table<FieldType, stage>::call_context_lookup(
          current_state.call_id(0), std::size_t(call_context_field::call_context_address),
          call_context_address_hi, call_context_address_lo);
      lookup(tmp, "zkevm_rw");
      // 1. Read address from stack
      tmp = rw_table<FieldType, stage>::stack_lookup(current_state.call_id(0),
                                                     current_state.stack_size(0) - 1,
                                                     current_state.rw_counter(0),
                                                     TYPE(0),  // is_write
                                                     K_hi, K_lo);
      lookup(tmp, "zkevm_rw");
      // 2. Read new value from stack
      tmp = rw_table<FieldType, stage>::stack_lookup(current_state.call_id(0),
                                                     current_state.stack_size(0) - 2,
                                                     current_state.rw_counter(0) + 1,
                                                     TYPE(0),  // is_write
                                                     V_hi, V_lo);
      lookup(tmp, "zkevm_rw");

      // 3. Write new value to transient storage
      tmp = {TYPE(rw_op_to_num(rw_operation_type::transient_storage)),
             tx_id,
             call_context_address_hi * two_128 + call_context_address_lo,
             TYPE(0),  // field
             K_hi,     // storage_key_hi
             K_lo,     // storage_key_lo
             current_state.rw_counter(0) + 2,
             TYPE(1),  // is_write
             V_hi,     // value_hi
             V_lo,     // value_lo
             U_hi,     // value_before_hi
             U_lo,     // value_before_lo
             current_state.call_id(0),
             transient_w_id_before};
      lookup(tmp, "zkevm_rw");
    }
  }
};

template<typename FieldType>
class zkevm_tstore_operation : public opcode_abstract<FieldType> {
public:
  virtual void fill_context(
      typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type
          &context,
      const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state)
      override {
    zkevm_tstore_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context,
                                                                     current_state);
  }
  virtual void fill_context(
      typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type
          &context,
      const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state)
      override {
    zkevm_tstore_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context,
                                                                      current_state);
  }
  virtual std::size_t rows_amount() override { return 1; }
};
}  // namespace bbf
}  // namespace blueprint
}  // namespace nil
