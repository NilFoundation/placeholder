//---------------------------------------------------------------------------//
// Copyright (c) 2024 Daniil Kogtev <oclaw@nil.foundation>
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


#ifndef PARALLEL_CRYPTO3_ZK_PLONK_PLACEHOLDER_TABLE_EXPORT_HPP
#define PARALLEL_CRYPTO3_ZK_PLONK_PLACEHOLDER_TABLE_EXPORT_HPP

#include <ostream>
#include <vector>

#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                using ranges = std::vector<std::pair<std::size_t, std::size_t>>;

                template <typename FieldType>
                void export_table(const plonk_assignment_table<FieldType>& table,
                                  const plonk_table_description<FieldType>& desc,
                                  std::ostream &out, 
                                  const ranges& witnesses, 
                                  const ranges& public_inputs, 
                                  const ranges& constants,
                                  const ranges& selectors, 
                                  const ranges& rows, 
                                  bool wide_export = false) { // wide_export is for e.g. potentiall fuzzer: does fixed width elements

                    
                    std::ios_base::fmtflags os_flags(out.flags());
                    out << std::dec;

                    out << "witnesses_size: " << table.witnesses_amount() << " "
                        << "public_inputs_size: " << table.public_inputs_amount() << " "
                        << "constants_size: " << table.constants_amount() << " "
                        << "selectors_size: " << table.selectors_amount() << " "
                        << "usable_rows_amount: " << desc.usable_rows_amount << "\n";

                    out << std::hex << std::setfill('0');
                    std::uint32_t width = wide_export ? (FieldType::modulus_bits + 4 - 1) / 4 : 0;

                    for (auto [lower_row, upper_row] : rows) {
                        for (std::uint32_t i = lower_row; i <= upper_row; i++) {

                            for (auto [lower_witness, upper_witness] : witnesses) {
                                for (std::uint32_t j = lower_witness; j <= upper_witness; j++) {
                                    out << std::setw(width)
                                        << (i < table.witness_column_size(j)
                                                ? table.witness(j)[i]
                                                : 0)
                                        << " ";
                                }
                            }
                            out << "| ";

                            for (auto [lower_public_input, upper_public_input] : public_inputs) {
                                for (std::uint32_t j = lower_public_input; j <= upper_public_input; j++) {
                                    out << std::setw(width)
                                        << (i < table.public_input_column_size(j)
                                                ? table.public_input(j)[i]
                                                : 0)
                                        << " ";
                                }
                            }
                            out << "| ";

                            for (auto [lower_constant, upper_constant] : constants) {
                                for (std::uint32_t j = lower_constant; j <= upper_constant; j++) {
                                    out << std::setw(width)
                                        << (i < table.constant_column_size(j)
                                                ? table.constant(j)[i]
                                                : 0)
                                        << " ";
                                }
                            }
                            out << "| ";

                            for (auto [lower_selector, upper_selector] : selectors) {
                                // Selectors only need a single bit, so we do not renew the size here
                                for (std::uint32_t j = lower_selector; j <= upper_selector; j++) {
                                    out << (i < table.selector_column_size(j)
                                                ? table.selector(j)[i]
                                                : 0)
                                        << " ";
                                }
                            }
                            out << "\n";
                        }
                    }

                    out.flush();
                    out.flags(os_flags);
                }

            } // namespace snark

        } // namespace zk

    } // namespace crypto3

} // namespace nil


#endif // PARALLEL_CRYPTO3_ZK_PLONK_PLACEHOLDER_TABLE_EXPORT_HPP
