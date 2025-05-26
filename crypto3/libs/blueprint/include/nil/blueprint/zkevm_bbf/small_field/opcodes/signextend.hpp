//---------------------------------------------------------------------------//
// Copyright (c) 2025 Alexey Yashunsky <a.yashunsky@nil.foundation>
// Copyright (c) 2024 Antoine Cyr <antoine.cyr@nil.foundation>
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
#include <iostream>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/abstract_opcode.hpp>
#include <numeric>

namespace nil::blueprint::bbf::zkevm_small_field{
    /*
    *  Opcode: 0xB SIGNEXTEND
    *  Description: sign extend x from (b+1) bytes to 32 bytes
    *  x = x[31]   x[30] ... x[b+1] x[b] x[b-1] ... x[0]
    *  s = x[b] >> 7
    *  y = s*0xFF s*0xFF ... s*0xFF x[b] x[b-1] ... x[0]
    *
    *  GAS: 5
    *  PC: +1
    *  Memory: Unchanged
    *  Stack Input: b, x
    *  Stack Output: y
    *  Stack Read  Lookup: b, x
    *  Stack Write Lookup: y
    *  rw_counter: +3
    */

    template<typename FieldType, GenerationStage stage>
    class zkevm_signextend_bbf : public generic_component<FieldType, stage> {
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

        using value_type = typename FieldType::value_type;

        constexpr static const std::size_t chunk_amount = 16;

    public:
        using typename generic_component<FieldType, stage>::TYPE;
        using typename generic_component<FieldType, stage>::context_type;

    public:
        zkevm_signextend_bbf(context_type &context_object,
                            const opcode_input_type<FieldType, stage> &current_state)
            : generic_component<FieldType, stage>(context_object, false) {

            // Allocated variables:
            std::vector<TYPE> b_chunks(chunk_amount); // 16-bit chunks of b
            std::vector<TYPE> x_chunks(chunk_amount); // 16-bit chunks of x
            std::vector<TYPE> y_chunks(chunk_amount); // 16-bit chunks of y
            std::vector<TYPE> indic(chunk_amount);    // 16 auxiliary values for creating an indicator function

            TYPE b0; // modified version of b_chunks[0], set to 32 if b exceeds 2^16
            TYPE b_sum_inverse; // inverse of b_chunks[1] + ... + b_chunks[15]
            TYPE parity; // see below
            TYPE n;    // b0 = 2*n + parity; NB: n may exceed 15
            TYPE xn_u;   // upper byte of x_chunks[n]
            TYPE xn_l;  // lower byte of x_chunks[n]
            TYPE sb;   // the byte from which the sign is extracted
            TYPE sgn;  // the sign
            TYPE saux; // auxiliary variable for computing the sign
            TYPE tr_c; // transition chunk

            TYPE range_check_n;    //
            TYPE range_check_xn_u; // Auxiliary variables for range-checking
            TYPE range_check_xn_l; // n, xn_u, xn_l, saux
            TYPE range_check_saux; //

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                zkevm_word_type b = current_state.stack_top();
                zkevm_word_type x = current_state.stack_top(1);

                int len = (b < 32) ? (int(b) + 1) : 32; // len is the number of bytes to be copied from x into y
                                                        // as x has 32 bytes, a value of b >= 32 should leave x unchanged
                // (32 - len) = number of bytes to be dropped from x
                // 8*(32-len) = number of bits  to be dropped from x
                zkevm_word_type sign = (x << (8 * (32 - len))) >> 255; // sign = most significant bit in the kept part of x
                zkevm_word_type result =
                    wrapping_add(
                        wrapping_mul(                                                           // (32-len) bytes|len bytes
                            (wrapping_sub(zkevm_word_type(1) << 8 * (32 - len), 1) << 8 * len), // 0xFF........FF|00.....00
                            sign // Depending on sign the result is either 0x00...00 or 0xFF...FF00...00
                        ),
                        ((x << (8 * (32 - len))) >> (8 * (32 - len))) // leaves only len bytes in x
                    );

                b_chunks = zkevm_word_to_field_element<FieldType>(b);
                x_chunks = zkevm_word_to_field_element<FieldType>(x);
                y_chunks = zkevm_word_to_field_element<FieldType>(result);

                // conversion of field elements to integers for computing division remainders
                auto field_to_int = [](TYPE x) {return static_cast<unsigned int>(x.to_integral()); };

                // the following values are necessary to bind b,x and y
                b0 = (b > 65535) ? 32 : b_chunks[0]; // b0 is either the first chunk of b, or 32 if other chunks are not all 0s
                parity = field_to_int(b0) % 2;
                n = (b0 - parity) / 2; // n is the number of the x chunk, that contains byte number b0, b0 = 2*n + parity
                TYPE xn = (n > 15) ? 0 : x_chunks[field_to_int(n)]; // n-th chunk of x, for further computations only
                xn_l = field_to_int(xn) % 256;  // lower byte of xn
                xn_u = (xn - xn_l) / 256;         // upper byte of xn
                sb = (parity == 0) ? xn_l : xn_u; // the sign byte
                sgn = (sb > 128);              // the sign bit

                // auxiliary values for an indicator function that will distinguish the n-th chunk
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    indic[i] = (TYPE(i) == n) ? 0 : (i-n).inversed();
                }
            }

            /* Layout:                    range_checked_opcode_area                                      |non-range-checked area
                0  ...  15 16 17   18    19  20     21     22     23    24  25  26     27     28  ... 31         32      ... 47
                +----------+--+--+------+---+----+--------+----+--------+--+---+----+--------+----+---+--+---------------+---+--+
            0 | b_chunks |                     x_chunks                                                |         indic        |
                +----------+--+--+------+---+----+--------+----+--------+--+---+----+--------+----+---+--+---------------+------+
            1 | y_chunks | n|b0|parity|2*n|xn_u|256*xn_u|xn_l|256*xn_l|sb|sgn|saux|256*saux|tr_c|...   | b_sum_inverse |  ... |
                +----------+--+--+------+---+----+--------+----+--------+--+---+----+--------+----+---+--+---------------+------+
                0  ...  15 16 17   18    19  20     21     22     23    24  25  26     27     28  ... 31         32      ... 47
            */

            // we need n allocated to create valid constraints on indic chunks
            allocate(n, 16, 1);

            // b,x,y chunks and indication function auxiliaries
            for (std::size_t i = 0; i < chunk_amount; i++) {
                allocate(b_chunks[i], i, 0);
                allocate(x_chunks[i], i + chunk_amount, 0);
                allocate(y_chunks[i], i, 1);

                allocate(indic[i], i + 2 * chunk_amount, 0);
                constrain((i - n) * (1 - (i - n) * indic[i]));
            }

            // Constraints to check whether b < 2^16 holds
            TYPE b_sum;
            // compute b_chunk[1] + ... b_chunk[15], skipping b_chunk[0]
            // NB: the sum takes at most log2(16) + 16 = 20 bits, so it is small-field-safe
            for (std::size_t i = 1; i < chunk_amount; i++) {
                b_sum += b_chunks[i];
            }
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                b_sum_inverse = b_sum.is_zero() ? 0 : b_sum.inversed();
            }
            allocate(b_sum_inverse, 32, 1); // allocated to non-range-cheked area
            constrain(b_sum * (1 - b_sum_inverse * b_sum));
            // now we have (1 - b_sum_invers * b_sum) = [b < 2^16]

            allocate(b0, 17, 1);
            constrain(b0 - b_chunks[0] * (1 - b_sum * b_sum_inverse) - 32 * b_sum * b_sum_inverse); // assure b0 is either b_chunks[0] or 32

            allocate(parity, 18, 1);
            constrain(parity * (1 - parity)); // parity is 0 or 1
            constrain(b0 - parity - 2 * n);   // b0 = 2*n + parity
            range_check_n = 2 * n;
            allocate(range_check_n,19,1); // n < 32768 range check

            // Below we check xn_u, xn_l and saux to be between 0 and 255
            // by allocating both the value and its product with 256 to 16-bit range-checked cells,
            // leveraging: t < 2^16, t*256 < 2^16 <=> t < 256

            allocate(xn_u, 20, 1);
            range_check_xn_u = xn_u * 256;
            allocate(range_check_xn_u,21,1);

            allocate(xn_l, 22, 1);
            range_check_xn_l  = xn_l * 256;
            allocate(range_check_xn_l,23,1);

            TYPE xn_expr;
            for (std::size_t i = 0; i < chunk_amount; i++) {
                xn_expr += x_chunks[i] * (1 - (i - n) * indic[i]); // expression for x_chunks[n] via x_chunks, n and the indicator function
            }
            constrain(xn_expr - xn_u * 256 - xn_l); // assure xn_u and xn_l are the bytes of x_chunks[n]

            allocate(sb, 24, 1);
            constrain(sb - (1 - parity) * xn_l - parity * xn_u); // depending on parity, sb is either the upper or lower byte of x_chunks[n]

            allocate(sgn, 25, 1);
            constrain(sgn * (1 - sgn)); // sgn is 0 or 1

            // assuring that sgn is indeed the upper bit of sb
            saux = sb + 128 - sgn * 256;
            allocate(saux, 26, 1);
            range_check_saux = saux * 256;
            allocate(range_check_saux,27,1);
            //
            // case 1:
            // sb <  128   =>   sb + 128 <  256   =>   saux = sb + 128 - sgn * 256 < 256*(1-sgn)
            // saux >= 0   =>   256*(1-sgn) > 0   =>    sgn == 0
            //
            // case 2:
            // sb >= 128   =>   sb + 128 >= 256   =>   saux = sb + 128 - sgn * 256 >= 256*(1-sgn)
            // saux < 256  =>   256*(1-sgn) < 256 =>   sgn == 1

            // link y_chunks to everything else:
            std::vector<TYPE> is_transition(chunk_amount);
            std::vector<TYPE> is_sign(chunk_amount);

            for(std::size_t i = 0; i < chunk_amount; i++) {
                is_transition[i] = 1 - (i - n)*indic[i]; // is_transition[n] == 1, is_transition[i] == 0 for i != n
                for(std::size_t j = i + 1; j < chunk_amount; j++) {
                    is_sign[j] += is_transition[i]; // is_sign[i] = is_transition[0] + .... + is_transition[i-1] <=>
                                                    // is_sign[i] == 0 for i <= n, is_sign[i] == 1 for i > n
                }
            }
            // the transition chunk:
            tr_c = parity * (xn_u * 256 + xn_l)              // parity == 1 => use whole chunk
                + (1 - parity) * (sgn * 0xFF * 256 + sb); // parity == 0 => transition in the middle of chunk
            allocate(tr_c,28,1);
            for(std::size_t i = 0; i < chunk_amount; i++) {
                constrain(y_chunks[i] - is_sign[i] * sgn * 0xFFFF                 // sign chunks: fill with sgn * 0xFFFF
                                    - is_transition[i] * tr_c                   // the transition chunk
                                    - (1 - is_sign[i] - is_transition[i]) * x_chunks[i] // other chunks: keep the original x chunk
                        );
            }

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                constrain(current_state.pc_next() - current_state.pc(1) - 1);  // PC transition
                constrain(current_state.gas(1) - current_state.gas_next() - 5);  // GAS transition
                constrain(current_state.stack_size(1) - current_state.stack_size_next() - 1); // stack_size transition
                constrain(current_state.memory_size(1) - current_state.memory_size_next());  // memory_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(1) - 3);  // rw_counter transition

                using RwTable = rw_256_table<FieldType, stage>;
                lookup(RwTable::stack_16_bit_lookup_reversed(
                    current_state.call_id(1),
                    current_state.stack_size(1) - 1,
                    current_state.rw_counter(1),
                    TYPE(0), // is_write
                    b_chunks
                ), "zkevm_rw_256" );

                lookup(RwTable::stack_16_bit_lookup_reversed(
                    current_state.call_id(1),
                    current_state.stack_size(1) - 2,
                    current_state.rw_counter(1) + 1,
                    TYPE(0), // is_write
                    x_chunks
                ), "zkevm_rw_256");

                lookup(RwTable::stack_16_bit_lookup_reversed(
                    current_state.call_id(1),
                    current_state.stack_size(1) - 2,
                    current_state.rw_counter(1) + 2,
                    TYPE(1), // is_write
                    y_chunks
                ), "zkevm_rw_256");
            }
        }
    };

    template<typename FieldType>
    class zkevm_signextend_operation : public opcode_abstract<FieldType> {
    public:
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type
                &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT>
                &current_state)  override {
            zkevm_signextend_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(
                context, current_state);
        }
        virtual void fill_context(
            typename generic_component<FieldType,
                                    GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS>
                &current_state)  override {
            zkevm_signextend_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(
                context, current_state);
        }
        virtual std::size_t rows_amount() override { return 2; }
    };
}
