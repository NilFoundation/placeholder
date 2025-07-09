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
    class max_chunk : public generic_component<FieldType, stage> {
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;

        using value_type = typename FieldType::value_type;
      public:
        using typename generic_component<FieldType, stage>::TYPE;
        using typename generic_component<FieldType, stage>::context_type;

        static const std::size_t range_checked_witness_amount = 19;
        static const std::size_t non_range_checked_witness_amount = 3;

        // assigned
        TYPE gt;
        TYPE eq;
        // not assigned
        TYPE ge;
        TYPE max;
        TYPE min;
      public:
        // a and b are 16-bit chunks
        // 1st cell is range checked. 2nd and 3rd cell may be not range checked. 4th cell shouldn't be range checked
        max_chunk(context_type &context_object, TYPE a, TYPE b)
            : generic_component<FieldType, stage>(context_object, false)
        {
            TYPE diff;
            TYPE diff_inv;

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                diff = (a > b) ? a - b : b - a;
                gt = (a > b) ? 1 : 0;
                eq = (a == b) ? 1 : 0;
                diff_inv = (diff == 0) ? 0 : diff.inversed();

                // BOOST_LOG_TRIVIAL(trace) << "\t" << std::hex
                //     << "a = " << a
                //     << ", b = " << b
                //     << ", diff = " << diff
                //     << ", gt = " << gt
                //     << ", eq = " << eq
                //     << std::dec;
            }
            allocate(diff, 0, 0);
            allocate(gt, 1, 0);
            allocate(eq, 2, 0);
            allocate(diff_inv, 3, 0);

            constrain(gt * (1 - gt));
            constrain(gt * (a - b - diff) + (1 - gt) * (b - a - diff));
            constrain(eq * (1 - eq));
            constrain(diff * diff_inv - (1 - eq));
            constrain(eq * diff);
            constrain(diff_inv * eq);
            constrain(gt*eq);

            max = gt * a + (1 - gt) * b;
            min = (1 - gt) * a + gt * b;
            ge = gt + eq;
        };
    };
}  // namespace nil::blueprint::bbf::zkevm_small_field

