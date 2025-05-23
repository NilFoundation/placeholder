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

#include <nil/blueprint/zkevm_bbf/big_field/opcodes/abstract_opcode.hpp>

namespace nil::blueprint::bbf::zkevm_big_field {

enum bitwise_type { B_AND, B_OR, B_XOR };

/*
*  Opcode: 0x16 AND, 0x17 OR, 0x18 XOR
*  Description: Bitwise operations (AND, OR, XOR)
*  GAS: 3
*  PC: +1
*  Memory: Unchanged
*  Stack Input: a, b
*  Stack Output: a & b / a | b / a ^ b
*  Stack Read  Lookup: a, b
*  Stack Write Lookup: a & b / a | b / a ^ b
*  rw_counter: +3
*/
template<typename FieldType, GenerationStage stage>
class zkevm_bitwise_bbf : generic_component<FieldType, stage> {
  using typename generic_component<FieldType, stage>::context_type;
  using generic_component<FieldType, stage>::allocate;
  using generic_component<FieldType, stage>::copy_constrain;
  using generic_component<FieldType, stage>::constrain;
  using generic_component<FieldType, stage>::lookup;
  using generic_component<FieldType, stage>::lookup_table;
 public:
  using typename generic_component<FieldType,stage>::TYPE;

  zkevm_bitwise_bbf(
     context_type &context_object, const opcode_input_type<FieldType, stage> &current_state,
     bitwise_type bitwise_operation)
     : generic_component<FieldType,stage>(context_object, false) {
    std::vector<TYPE> A(32); // 8-bit chunks of a (stack top)
    std::vector<TYPE> B(32); // 8-bit chunks of b (stack second top)
    std::vector<TYPE> AND(32); // 8-bit chunks of result a & b
    std::vector<TYPE> XOR(32); // 8-bit chunks of result a ^ b

    if constexpr( stage == GenerationStage::ASSIGNMENT ) {
      // split a and b into 8-bit chunks
      zkevm_word_type a_word = current_state.stack_top();
      zkevm_word_type b_word = current_state.stack_top(1);
      auto a = w_to_8(a_word);
      auto b = w_to_8(b_word);
      auto and_chunks = w_to_8(a_word & b_word);
      auto xor_chunks = w_to_8(a_word ^ b_word);

      for(std::size_t i = 0; i <32; i++){
        A[i] = a[i];
        B[i] = b[i];
        AND[i] = and_chunks[i];
        XOR[i] = xor_chunks[i];
      }
    }

    /* Layout:          range_checked_opcode_area
            0     ...    7      8      ...    15     16      ...    23     24       ...    31
        +------+------+------+------+------+------+-------+------+------+--------+------+-------+--
        | A[0] |  ... | A[7] | B[0] |  ... | B[7] |AND[0] |  ... |AND[7] |XOR[0] |  ... |XOR[7] |
        +------+------+------+------+------+------+-------+------+-------+-------+------+-------+--
        | A[8] |  ... | A[15]| B[8] |  ... | B[15]|AND[8] |  ... |AND[15]|XOR[8] |  ... |XOR[15]|
        +------+------+------+------+------+------+-------+------+-------+-------+------+-------+--
        | A[16]|  ... | A[23]| B[16]|  ... | B[23]|AND[16]|  ... |AND[23]|XOR[16]|  ... |XOR[23]|
        +------+------+------+------+------+------+-------+------+-------+-------+------+-------+--
        | A[24]|  ... | A[31]| B[24]|  ... | B[31]|AND[24]|  ... |AND[31]|XOR[24]|  ... |XOR[31]|
        +------+------+------+------+------+------+-------+------+-------+-------+------+-------+--

                        not_range_checked_opcode_area
                    32           33             34              35         36    ...   47
        ----+-------------+-------------+---------------+---------------+-----+-----+-----+
            | A_128.first | B_128.first | AND_128.first | XOR_128.first | OR0 |     |     |
        ----+-------------+-------------+---------------+---------------+-----+-----+-----+
            |             |             |               |               |     |     |     |
        ----+-------------+-------------+---------------+---------------+-----+-----+-----+
            | A_128.second| B_128.second| AND_128.second| XOR_128.second| OR1 |     |     |
        ----+-------------+-------------+---------------+---------------+-----+-----+-----+
            |             |             |               |               |     |     |     |
        ----+-------------+-------------+---------------+---------------+-----+-----+-----+


        Note: This layout is not compatible with small field rw_table. In that case we need to arrange chunks of A, B
              AND, XOR, in closer proximity (currently spans 4 rows, but needs to be at most 3). Also, we should use 8-bit chunks
              of OR instead of 128. Placing chunks in consequent rows won't help either due to byte_and_xor_table lookups.
    */
    for(std::size_t i = 0; i < 32; i++){
      allocate(A[i], i%8, i/8);
      allocate(B[i], i%8 + 8, i/8);
      allocate(AND[i], i%8 + 16, i/8);
      allocate(XOR[i], i%8 + 24, i/8);
    }

    std::vector<TYPE> tmp;
    for(std::size_t i = 0; i < 32; i++){
      lookup({
        A[i],
        B[i],
        AND[i],
        XOR[i]
      }, "byte_and_xor_table/full");
    }

    // combine 8-bit chunks to make 128-bit chunks
    auto A_128 = chunks8_to_chunks128(A); // 128-bit chunks of a
    auto B_128 = chunks8_to_chunks128(B); // 128-bit chunks of b
    auto AND_128 = chunks8_to_chunks128(AND); // 128-bit chunks of a&b
    auto XOR_128 = chunks8_to_chunks128(XOR); // 128-bit chunks of a^b

    allocate(A_128.first, 32, 0); allocate(A_128.second, 32, 2);
    allocate(B_128.first, 33, 0); allocate(B_128.second, 33, 2);
    allocate(AND_128.first, 34, 0); allocate(AND_128.second, 34, 2);
    allocate(XOR_128.first, 35, 0); allocate(XOR_128.second, 35, 2);

    TYPE OR0 = AND_128.first + XOR_128.first;  // 128-bit chunks of a|b
    TYPE OR1 = AND_128.second + XOR_128.second; // 128-bit chuns of a|b

    allocate(OR0, 36, 0); // implicit constraint OR0 - (AND_128.first + XOR_128.first)
    allocate(OR1, 36, 2); // implicit constraint OR1 - (AND_128.second + XOR_128.second)

    // std::cout << "\tA = "<< std::hex << A0 << " " << A1 << std::endl;
    // std::cout << "\tB = "<< std::hex << B0 << " " << B1 << std::endl;
    // std::cout << "\tAND = "<< std::hex << AND0 << " " << AND1 << std::endl;
    // std::cout << "\tOR = "<< std::hex << OR0 << " " << OR1 << std::endl;
    // std::cout << "\tXOR = "<< std::hex << XOR0 << " " << XOR1 << std::endl;
    if constexpr( stage == GenerationStage::CONSTRAINTS ){
      constrain(current_state.pc_next() - current_state.pc(3) - 1);                   // PC transition
      constrain(current_state.gas(3) - current_state.gas_next() - 3);                 // GAS transition
      constrain(current_state.stack_size(3) - current_state.stack_size_next() - 1);   // stack_size transition
      constrain(current_state.memory_size(3) - current_state.memory_size_next());     // memory_size transition
      constrain(current_state.rw_counter_next() - current_state.rw_counter(3) - 3);   // rw_counter transition

      lookup(rw_table<FieldType, stage>::stack_lookup(
        current_state.call_id(1),
        current_state.stack_size(1) - 1,
        current_state.rw_counter(1),
        TYPE(0),// is_write
        A_128.first,// high bits of a
        A_128.second// low bits of a
      ),"zkevm_rw");

      lookup(rw_table<FieldType, stage>::stack_lookup(
        current_state.call_id(1),
        current_state.stack_size(1) - 2,
        current_state.rw_counter(1) + 1,
        TYPE(0),// is_write
        B_128.first,// high bits of b
        B_128.second// low bits of b
      ), "zkevm_rw");

        switch(bitwise_operation){
        case B_AND:
            lookup(rw_table<FieldType, stage>::stack_lookup(
              current_state.call_id(1),
              current_state.stack_size(1) - 2,
              current_state.rw_counter(1) + 2,
              TYPE(1),       // is_write
              AND_128.first, // high bits of a&b
              AND_128.second // low bits of a&b
            ), "zkevm_rw");
            break;
        case B_OR:
            lookup(rw_table<FieldType, stage>::stack_lookup(
              current_state.call_id(1),
              current_state.stack_size(1) - 2,
              current_state.rw_counter(1) + 2,
              TYPE(1),       // is_write
              OR0,           // high bits of a|b
              OR1            // low bits of a|b
            ), "zkevm_rw");
            break;
        case B_XOR:
            lookup(rw_table<FieldType, stage>::stack_lookup(
              current_state.call_id(1),
              current_state.stack_size(1) - 2,
              current_state.rw_counter(1) + 2,
              TYPE(1),           // is_write
              XOR_128.first,     // high bits of a^b
              XOR_128.second     // low bits of a^b
            ), "zkevm_rw");
            break;
        }
    }
  }
};

template<typename FieldType>
class zkevm_bitwise_operation : public opcode_abstract<FieldType> {
 public:
  zkevm_bitwise_operation(bitwise_type _bit_operation): bit_operation(_bit_operation) { }

  virtual std::size_t rows_amount() override {
    // It may be three if we don't want to minimize lookup constraints amount.
    // It's a tradeoff between rows_amount and lookup constraints amount
    return 4;
  }

  virtual void fill_context(
      typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
      const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state) override  {
    zkevm_bitwise_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state, bit_operation);
  }

  virtual void fill_context(
      typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
      const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state) override  {
    zkevm_bitwise_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state, bit_operation);
  }

 private:
  bitwise_type bit_operation;
};

} // namespace bbf::blueprint::nil
