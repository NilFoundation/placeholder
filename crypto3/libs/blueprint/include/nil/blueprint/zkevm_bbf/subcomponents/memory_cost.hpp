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

#ifndef CRYPTO3_BBF_MEMORY_COST_HPP
#define CRYPTO3_BBF_MEMORY_COST_HPP

#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/word_size.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {

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

                memory_cost(context_type &context_object, TYPE memory_input,
                            std::vector<int> columns, std::vector<int> rows)
                    : generic_component<FieldType, stage>(context_object, false) {
                    assert(columns.size() == 8);
                    assert(rows.size() == 8);

                    using integral_type = typename FieldType::integral_type;
                    TYPE mem_words, mem_cost, C, R;
                    using Word_Size = typename bbf::word_size<FieldType, stage>;

                    Word_Size word =
                        Word_Size(context_object, memory_input,
                                  std::vector<int>(columns.begin(), columns.begin() + 4),
                                  std::vector<int>(rows.begin(), rows.begin() + 4));
                    mem_words = word.size;

                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        integral_type memory2 =
                            integral_type(mem_words.data) * integral_type(mem_words.data);
                        mem_cost = memory2 / 512 + 3 * integral_type(mem_words.data);
                        R = memory2 % 512;
                        R.is_zero() ? C = 0 : C = 1;
                    }

                    allocate(mem_words, columns[4], rows[4]);
                    allocate(mem_cost, columns[5], rows[5]);
                    allocate(R, columns[6], rows[6]);
                    allocate(C, columns[7], rows[7]);

                    constrain(C * (1 - C));
                    constrain((1 - C) * R);
                    constrain((mem_cost - 3 * mem_words) * 512 - mem_words * mem_words +
                              C * R);

                    cost = mem_cost;
                };
            };
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil

#endif  // CRYPTO3_BBF_MEMORY_COST_HPP
