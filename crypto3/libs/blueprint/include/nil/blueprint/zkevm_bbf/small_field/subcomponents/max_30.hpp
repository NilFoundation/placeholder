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
    // Maximum of two numbers < 2^30 (fit into one field element)
    template<typename FieldType, GenerationStage stage>
    class max_30 : public generic_component<FieldType, stage> {
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;

        using value_type = typename FieldType::value_type;
      public:
        using typename generic_component<FieldType, stage>::TYPE;
        using typename generic_component<FieldType, stage>::context_type;

        static const std::size_t range_checked_witness_amount = 3;
        static const std::size_t non_range_checked_witness_amount = 3;

        // assigned
        TYPE gt;
        TYPE eq;
        // not assigned
        TYPE max;
        TYPE min;
        TYPE ge;
      public:
        // Needs three range checked chunks and three non-range checked chunks
        max_30(context_type &context_object, TYPE a, TYPE b)
            : generic_component<FieldType, stage>(context_object, false)
        {
            const std::size_t hi_chunk_bound = (1 << 14) - 1; // 16383

            TYPE diff_hi;
            TYPE range_hi;
            TYPE diff_lo;
            TYPE diff_inv;
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                auto diff = (a > b) ? a - b : b - a;
                diff_lo = diff.to_integral() % 0x10000;
                diff_hi = diff.to_integral() / 0x10000;
                range_hi = hi_chunk_bound - diff_hi;
                gt = (a > b) ? 1 : 0;
                eq = (a == b) ? 1 : 0;
                diff_inv = (diff_hi + diff_lo) == 0 ? 0 : (diff_hi + diff_lo).inversed();
            }
            allocate(diff_hi, 0, 0);
            allocate(diff_lo, 1, 0);
            allocate(range_hi, 2, 0);
            allocate(gt, 3, 0);       // May be range checked, but not necessary
            allocate(eq, 4, 0);       // May be range checked, but not necessary
            allocate(diff_inv, 5, 0); // Non-range checked

            constrain(diff_hi + range_hi - hi_chunk_bound);
            constrain(gt * (gt - 1));
            constrain(gt * (a - b - diff_lo - diff_hi * 0x10000));
            constrain((1 - gt) * (b - a - diff_lo - diff_hi * 0x10000));
            constrain(eq * (eq - 1));
            constrain((1 - eq) - diff_inv * (diff_hi + diff_lo));
            constrain(eq * (diff_hi + diff_lo));
            constrain(eq * diff_inv);
            constrain(gt * eq);

            max = gt * a + (1 - gt) * b;
            min = (1 - gt) * a + gt * b;
            ge = gt + eq;
        };
    };
}  // namespace nil::blueprint::bbf::zkevm_small_field

