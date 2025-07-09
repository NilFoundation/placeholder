//---------------------------------------------------------------------------//
// Copyright (c) 2025 Elena Tatuzova <e.tatuzova@nil.foundation>
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

// #include <functional>

#pragma once

#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/subcomponents/word_size.hpp>
#include "nil/blueprint/zkevm_bbf/types/zkevm_word.hpp"

namespace nil::blueprint::bbf::zkevm_small_field {

    template<typename FieldType, GenerationStage stage>
    class memory_range : public generic_component<FieldType, stage> {
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;

        using value_type = typename FieldType::value_type;

        constexpr static const std::size_t chunk_amount = 6;
        constexpr static const value_type two_7 = 128;
        constexpr static const value_type two_15 = 32768;
        constexpr static const value_type two_16 = 65536;
        constexpr static const value_type two_18 = 262144;
        constexpr static const value_type two_23 = 8388608;

      public:
        using typename generic_component<FieldType, stage>::TYPE;
        using typename generic_component<FieldType, stage>::context_type;

        using input_type = std::conditional_t<stage == GenerationStage::ASSIGNMENT, zkevm_word_type, std::monostate>;

        static const std::size_t range_checked_witness_amount = 19;
        static const std::size_t non_range_checked_witness_amount = 3;

        // Not assigned
        std::array<TYPE, 16> chunks;
        TYPE chunks_sum;
        // assigned
        TYPE is_overflow;
        TYPE value;
      public:
        memory_range(context_type &context_object, input_type memory_input)
            : generic_component<FieldType, stage>(context_object, false)
        {
            // Range checked
            std::array<TYPE, 15> hi_chunks;
            TYPE diff_chunk_14;
            TYPE chunk_hi, diff_chunk_hi;
            TYPE chunk_lo;
            // Non range checked
            TYPE hi_chunks_sum;
            TYPE hi_chunks_sum_inv;

            const std::size_t hi_chunk_bound = (1 << (MAX_ZKEVM_MEMORY_SIZE_LOG2 - 16) ) - 1;

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                auto input_chunks = w_to_16(memory_input);
                TYPE sum;
                for( std::size_t i = 0; i < 14; i++ ){
                    hi_chunks[i] = input_chunks[i];
                    sum += hi_chunks[i];
                }
                hi_chunks[14] = (input_chunks[14] >> (MAX_ZKEVM_MEMORY_SIZE_LOG2 - 16));
                sum += hi_chunks[14];
                hi_chunks_sum_inv = sum == 0 ? 0 : sum.inversed();
                is_overflow = sum == 0? 0: 1;

                chunk_hi = input_chunks[14] & hi_chunk_bound;
                diff_chunk_hi = hi_chunk_bound - chunk_hi;
                chunk_lo = input_chunks[15];
            }
            for( std::size_t i = 0; i < 15; i++ ) {
                allocate(hi_chunks[i], i, 0);
                hi_chunks_sum += hi_chunks[i];
            }
            allocate(diff_chunk_14, 15, 0);
            allocate(chunk_hi, 16, 0);
            allocate(diff_chunk_hi, 17, 0);
            allocate(chunk_lo, 18, 0);
            // Non range checked
            allocate(hi_chunks_sum_inv, 19, 0);
            allocate(is_overflow, 20, 0);

            for( std::size_t i = 0; i < 14; i++)
                chunks[i] = hi_chunks[i];
            chunks[14] = hi_chunks[14] * (hi_chunk_bound + 1) + chunk_hi;
            chunks[15] = chunk_lo;
            for( std::size_t i = 0; i < 16; i++ ) {
                chunks_sum += chunks[i];
            }

            constrain(is_overflow * (is_overflow - 1));
            constrain(hi_chunks_sum * hi_chunks_sum_inv - is_overflow);
            constrain(hi_chunks_sum * (1 - is_overflow));
            constrain(hi_chunks_sum_inv * (1 - is_overflow));
            value = chunk_hi * 0x10000 + chunk_lo;
        };
    };
}  // namespace nil::blueprint::bbf::zkevm_small_field
