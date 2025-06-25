//---------------------------------------------------------------------------//
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

// #include <functional>

#pragma once

#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/subcomponents/word_size.hpp>

namespace nil::blueprint::bbf::zkevm_small_field{

    template<typename FieldType, GenerationStage stage>
    class memory_cost : public generic_component<FieldType, stage> {
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;

        public:
        using typename generic_component<FieldType, stage>::TYPE;
        using typename generic_component<FieldType, stage>::context_type;

        public:
        TYPE cost;
        TYPE word_size;

        memory_cost(context_type &context_object, TYPE memory_input)
            : generic_component<FieldType, stage>(context_object, false) {
            using integral_type = typename FieldType::integral_type;
            using Word_Size = typename zkevm_small_field::word_size<FieldType, stage>;

            TYPE mem_words, mem_cost, R;
            std::vector<std::size_t> word_size_lookup_area = {0, 1, 2};

            context_type word_size_ct =
                context_object.subcontext(word_size_lookup_area, 0, 1);

            Word_Size word = Word_Size(word_size_ct, memory_input);
            mem_words = word.size;

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                integral_type memory2 =
                    integral_type(mem_words.to_integral()) * integral_type(mem_words.to_integral());
                mem_cost = memory2 / 512 + 3 * integral_type(mem_words.to_integral());
                R = memory2 % 512;
            }

            allocate(mem_words, 3, 0);
            allocate(mem_cost, 4, 0);
            allocate(R, 5, 0);
            constrain((mem_cost - 3 * mem_words) * 512 - mem_words * mem_words + R);

            cost = mem_cost;
            word_size = word.size;
        };
    };
}