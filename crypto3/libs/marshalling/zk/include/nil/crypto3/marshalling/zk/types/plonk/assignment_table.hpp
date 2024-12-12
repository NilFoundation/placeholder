//---------------------------------------------------------------------------//
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_ZK_PLONK_ASSIGNMENT_TABLE_HPP
#define CRYPTO3_MARSHALLING_ZK_PLONK_ASSIGNMENT_TABLE_HPP

#include <memory>
#include <type_traits>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>
#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                /////////////////////////////////////////////////////////////////////////////////////////////////////////////
                /////////   Marshalling the assignment table description.
                /////////////////////////////////////////////////////////////////////////////////////////////////////////////

                // Table description is marshalled separately, so it can be used in
                // other parts of system (e.g. DFRI).
                template<typename TTypeBase>
                using plonk_assignment_table_description = nil::crypto3::marshalling::types::bundle<
                    TTypeBase, std::tuple<
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>, // witness_amount
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>, // public_input_amount
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>, // constant_amount
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>, // selector_amount

                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>, // usable_rows
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t> // rows_amount
                    >
                >;

                template<typename Endianness, typename FieldType>
                plonk_assignment_table_description<nil::crypto3::marshalling::field_type<Endianness>> fill_assignment_table_description(
                    const zk::snark::plonk_table_description<FieldType>& desc
                ) {
                    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;
                    using result_type = plonk_assignment_table_description<nil::crypto3::marshalling::field_type<Endianness>>;
                    using value_type = typename FieldType::value_type;

                    return result_type(std::move(std::make_tuple(
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>(desc.witness_columns),
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>(desc.public_input_columns),
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>(desc.constant_columns),
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>(desc.selector_columns),
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>(desc.usable_rows_amount),
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>(desc.rows_amount))));
                }

                template<typename Endianness, typename FieldType>
                zk::snark::plonk_table_description<FieldType> make_assignment_table_description(
                        const plonk_assignment_table_description<nil::crypto3::marshalling::field_type<Endianness>> &filled_description) {

                    zk::snark::plonk_table_description<FieldType> desc(
                        std::get<0>(filled_description.value()).value(),
                        std::get<1>(filled_description.value()).value(),
                        std::get<2>(filled_description.value()).value(),
                        std::get<3>(filled_description.value()).value(),
                        std::get<4>(filled_description.value()).value(),
                        std::get<5>(filled_description.value()).value()
                    );
                    return desc;
                }

                /////////////////////////////////////////////////////////////////////////////////////////////////////////////
                /////////   Marshalling the assignment table.
                /////////////////////////////////////////////////////////////////////////////////////////////////////////////

                template<typename TTypeBase, typename PlonkTable>
                using plonk_assignment_table = nil::crypto3::marshalling::types::bundle<
                    TTypeBase, std::tuple<
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>, // witness_amount
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>, // public_input_amount
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>, // constant_amount
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>, // selector_amount

                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>, // usable_rows
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>, // rows_amount
                        // witnesses
                        nil::crypto3::marshalling::types::standard_array_list<
                            TTypeBase,
                            field_element<TTypeBase, typename PlonkTable::field_type::value_type>
                        >,
                        // public_inputs
                        nil::crypto3::marshalling::types::standard_array_list<
                            TTypeBase,
                            field_element<TTypeBase, typename PlonkTable::field_type::value_type>
                        >,
                        // constants
                        nil::crypto3::marshalling::types::standard_array_list<
                            TTypeBase,
                            field_element<TTypeBase, typename PlonkTable::field_type::value_type>
                        >,
                        // selectors
                        nil::crypto3::marshalling::types::standard_array_list<
                            TTypeBase,
                            field_element<TTypeBase, typename PlonkTable::field_type::value_type>
                        >
                    >
                >;

                template<typename FieldValueType, typename Endianness>
                nil::crypto3::marshalling::types::standard_array_list<
                    nil::crypto3::marshalling::field_type<Endianness>,
                    field_element<nil::crypto3::marshalling::field_type<Endianness>, FieldValueType>>
                    fill_field_element_vector_from_columns_with_padding(
                        const std::vector<std::vector<FieldValueType>> &columns,
                        const std::size_t size,
                        const FieldValueType &padding) {

                    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;
                    using field_element_type = field_element<TTypeBase, FieldValueType>;
                    using field_element_vector_type = nil::crypto3::marshalling::types::standard_array_list<
                        TTypeBase,
                        field_element_type>;

                    field_element_vector_type result;
                    result.value().reserve(size * columns.size());
                    for (std::size_t column_number = 0; column_number < columns.size(); column_number++) {
                        for (std::size_t i = 0; i < columns[column_number].size(); i++) {
                            result.value().push_back(field_element_type(columns[column_number][i]));
                        }
                        for (std::size_t i = columns[column_number].size(); i < size; i++) {
                            result.value().push_back(field_element_type(padding));
                        }
                    }
                    return result;
                }

                template<typename FieldValueType, typename Endianness>
                std::vector<std::vector<FieldValueType>>
                make_field_element_columns_vector(
                    const nil::crypto3::marshalling::types::standard_array_list<
                        nil::crypto3::marshalling::field_type<Endianness>,
                        field_element<nil::crypto3::marshalling::field_type<Endianness>, FieldValueType>>
                        &field_elem_vector,
                    const std::size_t columns_amount,
                    const std::size_t rows_amount) {

                    if (field_elem_vector.value().size() != columns_amount * rows_amount) {
                        throw std::invalid_argument(
                                "Size of vector does not match the expected data size. Expected: " +
                                std::to_string(columns_amount * rows_amount) + " got " +
                                std::to_string(field_elem_vector.value().size()));
                    }

                    std::vector<std::vector<FieldValueType>> result(
                        columns_amount, std::vector<FieldValueType>(rows_amount));

                    std::size_t cur = 0;
                    for (std::size_t i = 0; i < columns_amount; i++) {
                        for (std::size_t j = 0; j < rows_amount; j++, cur++) {
                            result[i][j] = field_elem_vector.value()[cur].value();
                        }
                    }
                    return result;
                }

                template<typename Endianness, typename PlonkTable>
                plonk_assignment_table<nil::crypto3::marshalling::field_type<Endianness>, PlonkTable> fill_assignment_table(
                    std::size_t usable_rows,
                    const PlonkTable &assignments
                ) {
                    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;
                    using result_type = plonk_assignment_table<nil::crypto3::marshalling::field_type<Endianness>, PlonkTable>;
                    using value_type = typename PlonkTable::field_type::value_type;

                    return result_type(std::move(std::make_tuple(
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>(assignments.witnesses_amount()),
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>(assignments.public_inputs_amount()),
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>(assignments.constants_amount()),
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>(assignments.selectors_amount()),
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>(usable_rows),
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>(assignments.rows_amount()),
                        fill_field_element_vector_from_columns_with_padding<value_type, Endianness>(
                            assignments.witnesses(),
                            assignments.rows_amount(),
                            0u
                        ),
                        fill_field_element_vector_from_columns_with_padding<value_type, Endianness>(
                            assignments.public_inputs(),
                            assignments.rows_amount(),
                            0u
                        ),
                        fill_field_element_vector_from_columns_with_padding<value_type, Endianness>(
                            assignments.constants(),
                            assignments.rows_amount(),
                            0u
                        ),
                        fill_field_element_vector_from_columns_with_padding<value_type, Endianness>(
                            assignments.selectors(),
                            assignments.rows_amount(),
                            0u
                        )
                    )));
                }
                template<typename Endianness, typename PlonkTable>
                std::pair<zk::snark::plonk_table_description<typename PlonkTable::field_type>, PlonkTable> make_assignment_table(
                        const plonk_assignment_table<nil::crypto3::marshalling::field_type<Endianness>, PlonkTable> &filled_assignments){

                    using value_type = typename PlonkTable::field_type::value_type;

                    zk::snark::plonk_table_description<typename PlonkTable::field_type> desc(
                        std::get<0>(filled_assignments.value()).value(),
                        std::get<1>(filled_assignments.value()).value(),
                        std::get<2>(filled_assignments.value()).value(),
                        std::get<3>(filled_assignments.value()).value(),
                        std::get<4>(filled_assignments.value()).value(),
                        std::get<5>(filled_assignments.value()).value()
                    );

                    if (desc.usable_rows_amount >= desc.rows_amount)
                        throw std::invalid_argument(
                            "Rows amount should be greater than usable rows amount. Rows amount = " +
                            std::to_string(desc.rows_amount) +
                            ", usable rows amount = " + std::to_string(desc.usable_rows_amount));

                    std::vector<std::vector<value_type>> witnesses =
                        make_field_element_columns_vector<value_type, Endianness>(
                            std::get<6>(filled_assignments.value()),
                            desc.witness_columns,
                            desc.rows_amount
                        );

                    std::vector<std::vector<value_type>> public_inputs =
                        make_field_element_columns_vector<value_type, Endianness>(
                            std::get<7>(filled_assignments.value()),
                            desc.public_input_columns,
                            desc.rows_amount
                        );

                    std::vector<std::vector<value_type>> constants =
                        make_field_element_columns_vector<value_type, Endianness>(
                            std::get<8>(filled_assignments.value()),
                            desc.constant_columns,
                            desc.rows_amount
                        );

                    std::vector<std::vector<value_type>> selectors =
                        make_field_element_columns_vector<value_type, Endianness>(
                            std::get<9>(filled_assignments.value()),
                            desc.selector_columns,
                            desc.rows_amount
                        );


                    using private_table = typename PlonkTable::private_table_type;
                    using public_table = typename PlonkTable::public_table_type;

                    return std::make_pair(desc, PlonkTable(
                        std::make_shared<private_table>(std::move(witnesses)),
                        std::make_shared<public_table>(
                            std::move(public_inputs),
                            std::move(constants),
                            std::move(selectors)
                        )
                    ));
                }

   
            } //namespace types
        } // namespace marshalling
    } // namespace crypto3
} // namespace nil

#endif
