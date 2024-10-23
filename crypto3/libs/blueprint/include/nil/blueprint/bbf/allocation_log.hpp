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
// @file A class allocation_log which is used to store the usage map of assignment table.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_PLONK_BBF_ALLOCATION_LOG_HPP
#define CRYPTO3_BLUEPRINT_PLONK_BBF_ALLOCATION_LOG_HPP

#include <functional>
#include <sstream>
#include <vector>

#include <boost/log/trivial.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>
#include <nil/blueprint/bbf/enums.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {

            // A class for storing the information on which cells in the assignment table is already allocated/used.
            template<typename FieldType>
            class allocation_log {
            public:
                using assignment_description_type = nil::crypto3::zk::snark::plonk_table_description<FieldType>;

                allocation_log(const assignment_description_type& desc) {
                    log[column_type::witness] = std::vector<std::vector<bool>>(
                        desc.witness_columns, std::vector<bool>(desc.usable_rows_amount));
                    log[column_type::public_input] = std::vector<std::vector<bool>>(
                        desc.public_input_columns, std::vector<bool>(desc.usable_rows_amount));
                    log[column_type::constant] = std::vector<std::vector<bool>>(
                        desc.constant_columns, std::vector<bool>(desc.usable_rows_amount));
                }

                bool is_allocated(std::size_t col, std::size_t row, column_type t) {
                    if (col >= log[t].size()) {
                        std::stringstream error;
                        error << "Invalid value col = " << col 
                            << " when checking if a " << t << " cell is allocated. We have "
                            << log[t].size() << " columns.";
                        throw std::out_of_range(error.str());
                    }
                    if (row >= log[t][col].size()) {
                        std::stringstream error;
                        error << "Invalid value row = " << row 
                            << " when checking if a " << t << " cell is allocated. Column " << col << " has "
                            << log[t][col].size() << " rows.";
                        throw std::out_of_range(error.str());
                    }
                    return log[t][col][row];
                }

                void mark_allocated(std::size_t col, std::size_t row, column_type t) {
                    if (col >= log[t].size()) {
                        std::stringstream error;
                        error << "Invalid value col = " << col 
                            << " when marking a " << t << " cell allocated. We have "
                            << log[t].size() << " columns.";
                        throw std::out_of_range(error.str());
                    }
                    if (row >= log[t][col].size()) {
                        std::stringstream error;
                        error << "Invalid value row = " << row 
                            << " when marking a " << t << " cell allocated. Column " << col << " has "
                            << log[t][col].size() << " rows.";
                        throw std::out_of_range(error.str());
                    }
                    log[t][col][row] = true;
                }

            private:
                std::vector<std::vector<bool>> log[column_type::COLUMN_TYPES_COUNT];
            };

        } // namespace bbf
    } // namespace blueprint
} // namespace nil

#endif // CRYPTO3_BLUEPRINT_PLONK_BBF_ALLOCATION_LOG_HPP
