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
    class memory_cost : public generic_component<FieldType, stage> {
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

      public:
        // Output expressions (not assigned)
        TYPE cost;

        static std::size_t range_checked_witness_amount() {
            return 6; // low, diff_low, high, diff_high
        }

        // context should be 16-bit range-checked
        // mem_words-- range-checked memory size in words
        memory_cost(context_type &context_object, TYPE mem_words)
            : generic_component<FieldType, stage>(context_object, false)
        {
            constexpr std::size_t hi_chunk_bound = (MAX_ZKEVM_MEMORY_SIZE / 32 / 512) - 1;

            // Assigned cells
            TYPE low, diff_low;     // memory_words % 512                   < 512
            TYPE high;   // memory_words / 512                   < MAX_ZKEVM_MEMORY_SIZE / 32 / 512 = 256
            TYPE q, r;
            TYPE diff_r;

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                low = mem_words.to_integral() % 512;
                diff_low = 511 - low;
                high = mem_words.to_integral() / 512;
                q = (low * low).to_integral() / 512;
                r = (low * low).to_integral() % 512;
                diff_r = 511 - r;
            }
            allocate(low, 0, 0);
            allocate(diff_low, 1, 0);
            allocate(high, 2, 0);
            allocate(q, 3, 0);
            allocate(r, 4, 0);
            allocate(diff_r, 5, 0);

            // Range-checks
            constrain(low + diff_low - 511);
            constrain(r + diff_r - 511);
            constrain(low * low - q * 512 - r);
            constrain(mem_words - low - high * 512);
            cost = 3 * mem_words + (q + 2 * high * low  +  high * high * 512 );
        };
    };
}  // namespace nil::blueprint::bbf::zkevm_small_field
