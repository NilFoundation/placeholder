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
// @file Enumerations used for PLONK BBF context.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_PLONK_BBF_ENUMS_HPP
#define CRYPTO3_BLUEPRINT_PLONK_BBF_ENUMS_HPP

#include <ostream>
#include <map>

namespace nil {
    namespace blueprint {
        namespace bbf {
            enum class GenerationStage { ASSIGNMENT = 0, CONSTRAINTS = 1 };

            enum column_type { witness = 0, public_input = 1, constant = 2, COLUMN_TYPES_COUNT = 3};

            std::ostream &operator<<(std::ostream &os, const column_type &t) {
                static std::map<column_type, std::string> type_map = {
                    {column_type::witness, "witness"},
                    {column_type::public_input, "public input"},
                    {column_type::constant, "constant"},
                    {column_type::COLUMN_TYPES_COUNT, " "}
                };
                os << type_map[t];
                return os;
            }
         } // namespace bbf
    } // namespace blueprint
} // namespace nil

#endif // CRYPTO3_BLUEPRINT_PLONK_BBF_ENUMS_HPP
