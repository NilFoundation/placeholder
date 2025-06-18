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

#include <algorithm>
#include <numeric>

#include <nil/blueprint/zkevm_bbf/small_field/opcodes/abstract_opcode.hpp>

namespace nil::blueprint::bbf::zkevm_small_field {

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
        using typename generic_component<FieldType, stage>::TYPE;

        zkevm_bitwise_bbf(context_type &context_object,
                          const opcode_input_type<FieldType, stage> &current_state,
                          bitwise_type bitwise_operation)
            : generic_component<FieldType, stage>(context_object, false) {

            std::array<TYPE, 32> A;    // 8-bit chunks of a (stack top)
            std::array<TYPE, 32> B;    // 8-bit chunks of b (stack second top)
            std::array<TYPE, 32> AND;  // 8-bit chunks of result a & b
            std::array<TYPE, 32> XOR;  // 8-bit chunks of result a ^ b

            std::array<TYPE, 16> A16;    // 16-bit chunks of a (stack top)
            std::array<TYPE, 16> B16;    // 16-bit chunks of b (stack second top)
            std::array<TYPE, 16> AND16;  // 16-bit chunks of result a & b
            std::array<TYPE, 16> XOR16;  // 16-bit chunks of result a ^ b
            std::array<TYPE, 16> OR16;   // 16-bit chunks of result a | b

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                // split a and b into 8-bit chunks
                zkevm_word_type a_word = current_state.stack_top();
                zkevm_word_type b_word = current_state.stack_top(1);
                auto a = w_to_8(a_word);
                auto b = w_to_8(b_word);
                auto and_chunks = w_to_8(a_word & b_word);
                auto xor_chunks = w_to_8(a_word ^ b_word);

                for (std::size_t i = 0; i < 32; i++) {
                    A[i] = a[i];                // range checked by byte_and_xor_table
                    B[i] = b[i];                // range checked by byte_and_xor_table
                    AND[i] = and_chunks[i];     // range checked by byte_and_xor_table
                    XOR[i] = xor_chunks[i];     // range checked by byte_and_xor_table
                }
                for (std::size_t i = 0; i < 16; i++) {
                    A16[i] = (a[i * 2] << 8) + (a[i * 2 + 1]);
                    B16[i] = (b[i * 2] << 8) + (b[i * 2 + 1]);
                    AND16[i] = (and_chunks[i * 2] << 8) + and_chunks[i * 2 + 1];
                    XOR16[i] = (xor_chunks[i * 2] << 8) + xor_chunks[i * 2 + 1];
                }
            }

            // Layout:          range_checked_opcode_area
            //   0            7      8             15     16             23      24            31
            // +------+------+------+------+------+------+-------+------+-------+-------+-----+-------+
            // | A[0] |  ... | A[7] | B[0] |  ... | B[7] |AND[0] |  ... |AND[7] |XOR[0] | ... |XOR[7]
            // +------+------+------+------+------+------+-------+------+-------+-------+------+------+
            // | A[8] |  ... | A[15]| B[8] |  ... | B[15]|AND[8] |  ... |AND[15]|XOR[8] | ... |XOR[15]
            // +------+------+------+------+------+------+-------+------+-------+-------+------+------+
            // | A[16]|  ... | A[23]| B[16]|  ... | B[23]|AND[16]|  ... |AND[23]|XOR[16]| ... |XOR[23]
            // +------+------+------+------+------+------+-------+------+-------+-------+------+------+
            // | A[24]|  ... | A[31]| B[24]|  ... | B[31]|AND[24]|  ... |AND[31]|XOR[24]| ... |XOR[31]
            // +------+------+------+------+------+------+-------+------+-------+-------+------+------+

            //     not_range_checked_opcode_area
            // 32           33                39          40         41         ...  47
            // -----------+-----------+------+----------+----------+----------+-----+-----------+
            // | A16[0]   |  A16[1]   |  ... | A16[7]   | B16[0]   | B16[1]   | ... | B16[7]
            // -----------+-----------+------+----------+----------+----------+-----+-----------+
            // | AND16[0] |  AND16[1] |  ... | AND16[7] | XOR16[0] | XOR16[1] | ... | XOR16[7]      -- stack lookups for A and B
            // -----------+-----------+------+----------+----------+----------+-----+-----------+
            // | A16[8]   |  A16[9]   |  ... | A16[15]  | B16[8]   | B16[9]   | ... | B16[15]
            // -----------+-----------+------+----------+----------+----------+-----+-----------+
            // | AND16[8] |  AND16[9] |  ... | AND16[15]| XOR16[8] | XOR16[9] | ... | XOR16[15]
            // -----------+-----------+------+----------+----------+----------+-----+-----------+

            for (std::size_t i = 0; i < 32; i++) {
                allocate(A[i], i % 8, i / 8);
                allocate(B[i], i % 8 + 8, i / 8);
                allocate(AND[i], i % 8 + 16, i / 8);
                allocate(XOR[i], i % 8 + 24, i / 8);
            }
            for (std::size_t i = 0; i < 8; i++ ){
                allocate(A16[i], 32 + i, 0); allocate(A16[i + 8], 32 + i, 2);
                allocate(B16[i], 32 + i + 8, 0); allocate(B16[i + 8], 32 + i + 8, 2);
                allocate(AND16[i], 32 + i, 1); allocate(AND16[i + 8], 32 + i, 3);
                allocate(XOR16[i], 32 + i + 8, 1); allocate(XOR16[i + 8], 32 + i + 8, 3);
            }
            for ( std::size_t i = 0; i < 16; i++ ){
                OR16[i] = AND16[i] + XOR16[i];
            }

            std::vector<TYPE> tmp;
            for (std::size_t i = 0; i < 32; i++) {
                lookup({A[i], B[i], AND[i], XOR[i]}, "byte_and_xor_table/full");
            }

            for ( std::size_t i = 0; i < 16; i++){
                constrain( A16[i] - (A[i * 2] * 256 + (A[i * 2 + 1])) );
                constrain( B16[i] - (B[i * 2] * 256 + (B[i * 2 + 1])) );
                constrain( AND16[i] - (AND[i * 2] * 256 + (AND[i * 2 + 1])) );
                constrain( XOR16[i] - (XOR[i * 2] * 256 + (XOR[i * 2 + 1])) );
            }

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                constrain(current_state.pc_next() - current_state.pc(3) - 1);  // PC transition
                constrain(current_state.gas(3) - current_state.gas_next() - 3);  // GAS transition
                constrain(current_state.stack_size(3) - current_state.stack_size_next() - 1);  // stack_size transition
                constrain(current_state.memory_size(3) - current_state.memory_size_next());  // memory_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(3) - 3);  // rw_counter transition

                lookup(rw_256_table<FieldType, stage>::stack_16_bit_lookup(
                    current_state.call_id(1), current_state.stack_size(1) - 1,
                    current_state.rw_counter(1),
                    TYPE(0),      // is_write
                    A16
                ), "zkevm_rw_256");

                lookup(rw_256_table<FieldType, stage>::stack_16_bit_lookup(
                    current_state.call_id(1), current_state.stack_size(1) - 2,
                    current_state.rw_counter(1) + 1,
                    TYPE(0),      // is_write
                    B16
                ), "zkevm_rw_256");

                switch (bitwise_operation) {
                case B_AND:
                    lookup(rw_256_table<FieldType, stage>::stack_16_bit_lookup(
                        current_state.call_id(1),
                        current_state.stack_size(1) - 2,
                        current_state.rw_counter(1) + 2,
                        TYPE(1),        // is_write
                        AND16
                    ), "zkevm_rw_256");
                    break;
                case B_OR:
                    lookup( rw_256_table<FieldType, stage>::stack_16_bit_lookup(
                        current_state.call_id(1),
                        current_state.stack_size(1) - 2,
                        current_state.rw_counter(1) + 2,
                        TYPE(1),  // is_write
                        OR16
                    ), "zkevm_rw_256");
                    break;
                case B_XOR:
                    lookup( rw_256_table<FieldType, stage>::stack_16_bit_lookup(
                        current_state.call_id(1),
                        current_state.stack_size(1) - 2,
                        current_state.rw_counter(1) + 2,
                        TYPE(1),        // is_write
                        XOR16
                    ), "zkevm_rw_256");
                    break;
                }
            }
        }
    };

    template<typename FieldType>
    class zkevm_bitwise_operation : public opcode_abstract<FieldType> {
    public:
        zkevm_bitwise_operation(bitwise_type _bit_operation)
            : bit_operation(_bit_operation) {}

        virtual std::size_t rows_amount() override {
            // It may be three if we don't want to minimize lookup constraints amount.
            // It's a tradeoff between rows_amount and lookup constraints amount
            return 4;
        }

    virtual void fill_context(
        typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
        const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state) override
    {
        zkevm_bitwise_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state, bit_operation);
    }

    virtual void fill_context(
        typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
        const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state) override
    {
        zkevm_bitwise_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state, bit_operation);
    }

    private:
        bitwise_type bit_operation;
    };

}  // namespace nil::blueprint::bbf::zkevm_small_field
