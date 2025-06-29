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
        // Assigned cells
        TYPE low, diff_low;   // size in words. (memory_input + 31)%32  < 32
        TYPE mid, diff_mid;   // memory_words % 512                     < 512
        TYPE high, diff_high;   // memory_words / 512                   < 256
        // Output expressions (not assigned)
        TYPE cost;
        TYPE word_size;

        memory_cost(context_type &context_object, TYPE memory_input)
            : generic_component<FieldType, stage>(context_object, false)
        {
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                zkevm_word_type mem_words = (memory_input.to_integral() + 31) / 32;
                low = (memory_input.to_integral() + 31) % 32;
                diff_low = 31 - low;
                mid = mem_words % 512;
                diff_mid = 511 - mid;
                high = mem_words / 512;
                diff_high = 255 - high;
            }
            allocate(low, 0, 0);
            allocate(diff_low, 1, 0);
            allocate(mid, 2, 0);
            allocate(diff_mid, 3, 0);
            allocate(high, 4, 0);
            allocate(diff_high, 5, 0);

            // Range-checks
            constrain(low + diff_low - 255);
            constrain(mid + diff_mid - 511);
            constrain(high + diff_high - 31);

            // (memory_input + 31) decomposition.
            constrain(memory_input + 31 - low - mid * 32 - high * 512 * 32);
            cost = 3 * (mid + 512 * high) + (mid * mid + 1024 * high * high * 512 * 512 );
            word_size = mid + 512 * high;
        };
    };
}  // namespace nil::blueprint::bbf::zkevm_small_field
