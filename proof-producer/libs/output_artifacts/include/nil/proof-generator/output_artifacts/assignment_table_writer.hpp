//---------------------------------------------------------------------------//
// Copyright (c) 2024 Daniil Kogtev <oclaw@nil.foundation>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//---------------------------------------------------------------------------//

#ifndef PROOF_GENERATOR_ASSIGNMENT_TABLE_WRITER_HPP
#define PROOF_GENERATOR_ASSIGNMENT_TABLE_WRITER_HPP

#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/trivial.hpp>
#include <boost/assert.hpp>
#include <ostream>  

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/export.hpp>
#include <nil/marshalling/types/integral.hpp>

#include <nil/proof-generator/output_artifacts/output_artifacts.hpp>


namespace nil {
    namespace proof_generator {

        template <typename Endianness, typename BlueprintField>
        class assignment_table_writer {
            public:                
                using Column = nil::crypto3::zk::snark::plonk_column<BlueprintField>;
                using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintField>;

                using AssignmentTable = nil::crypto3::zk::snark::plonk_table<BlueprintField, Column>; 
                using AssignmentTableDescription = nil::crypto3::zk::snark::plonk_table_description<BlueprintField>;

                // marshalling traits
                using TTypeBase = nil::marshalling::field_type<Endianness>;
                using BlueprintFieldValueType = typename BlueprintField::value_type;
                using MarshallingField = nil::crypto3::marshalling::types::field_element<
                    TTypeBase, 
                    BlueprintFieldValueType
                >;

            private:            
                /**
                * @brief Write size_t serialized as nil::marshalling::types::integral into output stream.
                */
                static void write_size_t(std::ostream& out, size_t input) {
                    auto integer_container = nil::marshalling::types::integral<TTypeBase, std::size_t>(input);
                    std::array<std::uint8_t, integer_container.length()> char_array{};
                    auto write_iter = char_array.begin();
                    assert(integer_container.write(write_iter, char_array.size()) ==
                        nil::marshalling::status_type::success);

                    out.write(reinterpret_cast<char*>(char_array.data()), char_array.size());
                }

                /**
                * @brief Write zero value serialized via crypto3 marshalling into output
                * stream.
                */
                static void write_zero_field(std::ostream& out) {
                    using empty_field = std::array<std::uint8_t, MarshallingField().length()>;
                    
                    empty_field field{};
                    out.write(reinterpret_cast<char*>(field.data()), field.size());
                }

                /**
                * @brief Write field element into output stream.
                */
                static void write_field(std::ostream& out, const BlueprintFieldValueType& input) {
                    MarshallingField field_container(input);
                    std::array<std::uint8_t, field_container.length()> char_array{};
                    auto write_iter = char_array.begin();
                    assert(field_container.write(write_iter, char_array.size()) ==
                        nil::marshalling::status_type::success);

                    out.write(reinterpret_cast<char*>(char_array.data()), char_array.size());
                }


                /**
                * @brief Write table column to output stream padding with zeroes up to fixed number of values.
                */
                // template<typename Endianness, typename ArithmetizationType, typename ColumnType>
                static void write_vector_value(std::ostream& out, const std::size_t padded_rows_amount, const Column& table_col) {
                    for (std::size_t i = 0; i < padded_rows_amount; i++) {
                        if (i < table_col.size()) {
                            write_field(out,table_col[i]);
                        } else {
                            write_zero_field(out);
                        }
                    }
                }


            public:
                assignment_table_writer() = delete;

                static void write_binary_assignment(std::ostream& out, const AssignmentTable& table, const AssignmentTableDescription& desc) {
                    std::uint32_t public_input_size = table.public_inputs_amount();
                    std::uint32_t witness_size = table.witnesses_amount();
                    std::uint32_t constant_size = table.constants_amount();
                    std::uint32_t selector_size = table.selectors_amount();
                    std::uint32_t usable_rows_amount = desc.usable_rows_amount;

                    std::uint32_t padded_rows_amount = std::pow(2, std::ceil(std::log2(usable_rows_amount)));
                    if (padded_rows_amount == usable_rows_amount) {
                        padded_rows_amount *= 2;
                    }
                    if (padded_rows_amount < 8) {
                        padded_rows_amount = 8;
                    }
                    
                    write_size_t(out, witness_size);
                    write_size_t(out, public_input_size);
                    write_size_t(out, constant_size);
                    write_size_t(out, selector_size);
                    write_size_t(out, usable_rows_amount);
                    write_size_t(out, padded_rows_amount);

                    write_size_t(out, witness_size * padded_rows_amount);
                    for (std::uint32_t i = 0; i < witness_size; i++) {
                        write_vector_value(out, padded_rows_amount,table.witness(i));
                    }

                    write_size_t(out, public_input_size * padded_rows_amount);
                    for (std::uint32_t i = 0; i < public_input_size; i++) {
                        write_vector_value(out, padded_rows_amount, table.public_input(i));
                    }

                    write_size_t(out, constant_size * padded_rows_amount);
                    for (std::uint32_t i = 0; i < constant_size; i++) {
                        write_vector_value(out, padded_rows_amount,table.constant(i));
                    }

                    write_size_t(out, selector_size * padded_rows_amount);
                    for (std::uint32_t i = 0; i < selector_size; i++) {
                        write_vector_value(out, padded_rows_amount, table.selector(i));
                    }
                }


                static bool write_text_assignment(
                    std::ostream& out,
                    const AssignmentTable& table,
                    const AssignmentTableDescription& desc,
                    const OutputArtifacts& artifacts) {

                    const auto extract_concrete_range = [&artifacts] (std::string_view log_prefix, const Ranges& r, size_t max_value) -> std::optional<Ranges::ConcreteRanges> {
                        if (artifacts.write_full) {
                            return Ranges::ConcreteRanges{
                                {0, max_value-1}
                            };
                        }
                        
                        Ranges::ConcreteRanges ret{};
                        if (r.empty()) {
                            return ret;
                        }

                        auto maybe_concrete_range = r.concrete_ranges(max_value - 1); // max_value is non-inclusive
                        if (!maybe_concrete_range.has_value()) {
                            BOOST_LOG_TRIVIAL(error) << log_prefix << maybe_concrete_range.error();
                            return std::nullopt;
                        }
                        return maybe_concrete_range.value();
                    };

                    auto witnesses = extract_concrete_range("Witnesses: ", artifacts.witness_columns, table.witnesses_amount());
                    if (!witnesses.has_value()) {
                        return false;
                    }

                    auto public_inputs = extract_concrete_range("Public inputs: ", artifacts.public_input_columns, table.public_inputs_amount());
                    if (!public_inputs.has_value()) {
                        return false;
                    }

                    auto constants = extract_concrete_range("Constants: ", artifacts.constant_columns, table.constants_amount());
                    if (!constants.has_value()) {
                        return false;
                    }

                    auto selectors = extract_concrete_range("Selectors: ", artifacts.selector_columns, table.selectors_amount());
                    if (!selectors.has_value()) {
                        return false;
                    }

                    auto rows = extract_concrete_range("Rows: ", artifacts.rows, desc.usable_rows_amount);
                    if (!rows.has_value()) {
                        return false;
                    }

                    nil::crypto3::zk::snark::export_table(table, desc, out, 
                              witnesses.value(), 
                              public_inputs.value(), 
                              constants.value(),
                              selectors.value(), 
                              rows.value(), 
                              true
                    );
                    return true; 
            }
        };

    } // namespace proof_generator

} // namespace nil

#endif // PROOF_GENERATOR_ASSIGNMENT_TABLE_WRITER_HPP
