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

#ifndef CRYPTO3_BBF_WORD_SIZE_HPP
#define CRYPTO3_BBF_WORD_SIZE_HPP

#include <nil/blueprint/bbf/generic.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {

            template<typename FieldType, GenerationStage stage>
            class word_size : public generic_component<FieldType, stage> {
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;

              public:
                using typename generic_component<FieldType, stage>::TYPE;
                using typename generic_component<FieldType, stage>::context_type;

              public:
                TYPE size;

                word_size(context_type &context_object, TYPE bite_size_input)
                    : generic_component<FieldType, stage>(context_object, false) {
                    using integral_type = typename FieldType::integral_type;
                    TYPE words, R, C;

                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        words = (integral_type(bite_size_input.data) + 31) / 32;
                        R = (integral_type(bite_size_input.data) + 31) % 32;
                        R.is_zero() ? C = 0 : C = 1;
                    }

                    allocate(bite_size_input, 0, 0);
                    allocate(words, 1, 0);
                    allocate(R, 2, 0);
                    allocate(C, 3, 0);

                    constrain(C * (1 - C));
                    constrain((1 - C) * R);
                    constrain(words * 32 - bite_size_input - 31 + C * R);

                    size = words;
                };
            };
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil

#endif  // CRYPTO3_BBF_WORD_SIZE_HPP
