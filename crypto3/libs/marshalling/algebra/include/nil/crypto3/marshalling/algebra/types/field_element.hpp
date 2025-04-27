//---------------------------------------------------------------------------//
// Copyright (c) 2017-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_FIELD_ELEMENT_HPP
#define CRYPTO3_MARSHALLING_FIELD_ELEMENT_HPP

#include <type_traits>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/tag.hpp>
#include <nil/marshalling/types/detail/adapt_basic_field.hpp>

#include <nil/crypto3/marshalling/multiprecision/types/integral.hpp>
#include <nil/crypto3/marshalling/algebra/inference.hpp>
#include <nil/crypto3/marshalling/algebra/type_traits.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                namespace detail {

                    template<typename FieldValueType>
                    typename std::enable_if<!(algebra::is_extended_field_element<FieldValueType>::value),
                                            std::array<typename FieldValueType::field_type::integral_type,
                                                FieldValueType::field_type::arity>>::type
                        fill_field_data(const FieldValueType &field_elem) {

                        std::array<typename FieldValueType::field_type::integral_type,
                            FieldValueType::field_type::arity> result;
                        result[0] = typename FieldValueType::field_type::integral_type(
                            field_elem.to_integral());
                        return result;
                    }

                    template<typename FieldValueType>
                    typename std::enable_if<algebra::is_extended_field_element<FieldValueType>::value,
                                            std::array<typename FieldValueType::field_type::integral_type,
                                                FieldValueType::field_type::arity>>::type
                        fill_field_data(const FieldValueType &field_elem) {

                        std::array<typename FieldValueType::field_type::integral_type,
                            FieldValueType::field_type::arity> result;

                        for (std::size_t i = 0; i < FieldValueType::field_type::arity /
                                FieldValueType::underlying_type::field_type::arity; i++) {
                            std::array<typename FieldValueType::field_type::integral_type,
                                FieldValueType::underlying_type::field_type::arity>
                                intermediate_res =
                                    fill_field_data(field_elem.data[i]);
                            std::copy(intermediate_res.begin(),
                                      intermediate_res.end(),
                                      result.begin() + i * FieldValueType::underlying_type::field_type::arity);
                        }

                        return result;
                    }

                    template<typename FieldValueType>
                    typename std::enable_if<algebra::is_field_element<FieldValueType>::value &&
                                                !(algebra::is_extended_field_element<FieldValueType>::value),
                                            FieldValueType>::type
                        make_field_element(typename std::array<typename FieldValueType::field_type::integral_type,
                                                               FieldValueType::field_type::arity>::iterator field_elem_data_iter) {

                        return FieldValueType(*field_elem_data_iter);
                    }

                    template<typename FieldValueType>
                    typename std::enable_if<algebra::is_extended_field_element<FieldValueType>::value,
                                            FieldValueType>::type
                        make_field_element(typename std::array<typename FieldValueType::field_type::integral_type,
                                                               FieldValueType::field_type::arity>::iterator field_elem_data_iter) {

                        constexpr static const std::size_t cur_arity =
                            FieldValueType::field_type::arity / FieldValueType::underlying_type::field_type::arity;

                        std::array<typename FieldValueType::underlying_type, cur_arity> data;

                        for (std::size_t i = 0; i < cur_arity; i++) {

                            data[i] = make_field_element<typename FieldValueType::underlying_type>(
                                field_elem_data_iter + i * FieldValueType::underlying_type::field_type::arity);
                        }
                        return FieldValueType(data);
                    }
                }    // namespace detail

                template<typename TTypeBase,
                         typename FieldValueType,
                         typename... TOptions>
                class pure_field_element
                    : private ::nil::crypto3::marshalling::types::detail::adapt_basic_field_type<
                          integral<TTypeBase, typename FieldValueType::field_type::integral_type>,
                          TOptions...> {

                    static_assert(algebra::is_field_element<FieldValueType>::value);
                    static_assert(!algebra::is_extended_field_element<FieldValueType>::value);

                    using base_impl_type = ::nil::crypto3::marshalling::types::detail::adapt_basic_field_type<
                        integral<TTypeBase, typename FieldValueType::field_type::integral_type>,
                        TOptions...>;

                public:
                    /// @brief endian_type used for serialization.
                    using endian_type = typename base_impl_type::endian_type;

                    /// @brief All the options provided to this class bundled into struct.
                    using parsed_options_type = ::nil::crypto3::marshalling::types::detail::options_parser<TOptions...>;

                    /// @brief Type of underlying field_element value.
                    /// @details Same as template parameter T to this class.
                    using value_type = typename base_impl_type::value_type;

                    /// @brief Default constructor
                    /// @details Initialises internal value to 0.
                    pure_field_element() = default;

                    /// @brief Constructor
                    explicit pure_field_element(const FieldValueType &field_elem)
                        : base_impl_type(
                              typename FieldValueType::field_type::integral_type(
                                  field_elem.to_integral())) {}

                    /// @brief Copy constructor
                    pure_field_element(const pure_field_element &) = default;

                    /// @brief Destructor
                    ~pure_field_element() noexcept = default;

                    /// @brief Copy assignment
                    pure_field_element &operator=(const pure_field_element &) = default;

                    /// @brief Get access to pure_field_element value storage.
                    FieldValueType const value() const {
                        return FieldValueType(base_impl_type::value());
                    }

                    /// @brief Get access to field_element value storage.
                    FieldValueType value() {
                        return FieldValueType(base_impl_type::value());
                    }

                    /// @brief Get length required to serialise the current field value.
                    /// @return Number of bytes it will take to serialise the field value.
                    static constexpr std::size_t length() {
                        return base_impl_type::length();
                    }

                    /// @brief Get length required to serialise the current field value.
                    /// @return Number of bytes it will take to serialise the field value.
                    static constexpr std::size_t bit_length() {
                        return base_impl_type::bit_length();
                    }

                    /// @brief Get minimal length that is required to serialise field of this type.
                    /// @return Minimal number of bytes required serialise the field value.
                    static constexpr std::size_t min_length() {
                        return base_impl_type::min_length();
                    }

                    /// @brief Get maximal length that is required to serialise field of this type.
                    /// @return Maximal number of bytes required serialise the field value.
                    static constexpr std::size_t max_length() {
                        return base_impl_type::max_length();
                    }

                    /// @brief Check validity of the field value.
                    bool valid() const {
                        return base_impl_type::valid();
                    }

                    /// @brief Refresh the field's value
                    /// @return @b true if the value has been updated, @b false otherwise
                    bool refresh() {
                        return base_impl_type::refresh();
                    }

                    /// @brief Read field value from input data sequence
                    /// @param[in, out] iter Iterator to read the data.
                    /// @param[in] size Number of bytes available for reading.
                    /// @return Status of read operation.
                    /// @post Iterator is advanced.
                    template<typename TIter>
                    nil::crypto3::marshalling::status_type read(TIter &iter, std::size_t size) {
                        return base_impl_type::read(iter, size);
                    }

                    /// @brief Read field value from input data sequence without error check and status report.
                    /// @details Similar to @ref read(), but doesn't perform any correctness
                    ///     checks and doesn't report any failures.
                    /// @param[in, out] iter Iterator to read the data.
                    /// @post Iterator is advanced.
                    template<typename TIter>
                    void read_no_status(TIter &iter) {
                        base_impl_type::read_no_status(iter);
                    }

                    /// @brief Write current field value to output data sequence
                    /// @param[in, out] iter Iterator to write the data.
                    /// @param[in] size Maximal number of bytes that can be written.
                    /// @return Status of write operation.
                    /// @post Iterator is advanced.
                    template<typename TIter>
                    nil::crypto3::marshalling::status_type write(TIter &iter, std::size_t size) const {
                        return base_impl_type::write(iter, size);
                    }

                    /// @brief Write current field value to output data sequence  without error check and status report.
                    /// @details Similar to @ref write(), but doesn't perform any correctness
                    ///     checks and doesn't report any failures.
                    /// @param[in, out] iter Iterator to write the data.
                    /// @post Iterator is advanced.
                    template<typename TIter>
                    void write_no_status(TIter &iter) const {
                        base_impl_type::write_no_status(iter);
                    }

                protected:
                    using base_impl_type::read_data;
                    using base_impl_type::write_data;

                private:
                    static_assert(!parsed_options_type::has_sequence_size_field_prefix,
                                  "nil::crypto3::marshalling::option::sequence_size_field_prefix option is not applicable to "
                                  "crypto3::field_element type");
                };

                template<typename TTypeBase,
                         typename FieldValueType,
                         typename... TOptions>
                class extended_field_element
                    : private ::nil::crypto3::marshalling::types::detail::adapt_basic_field_type<
                            nil::crypto3::marshalling::types::array_list<
                                nil::crypto3::marshalling::field_type<nil::crypto3::marshalling::option::little_endian>,
                                integral<TTypeBase, typename FieldValueType::field_type::integral_type>,
                                nil::crypto3::marshalling::option::fixed_size_storage<
                                    FieldValueType::field_type::arity>>,
                          TOptions...> {

                    static_assert(algebra::is_field_element<FieldValueType>::value);
                    static_assert(algebra::is_extended_field_element<FieldValueType>::value);

                    using base_impl_type = ::nil::crypto3::marshalling::types::detail::adapt_basic_field_type<
                        typename nil::crypto3::marshalling::types::array_list<
                                                  nil::crypto3::marshalling::field_type<nil::crypto3::marshalling::option::little_endian>,
                                                  integral<TTypeBase, typename FieldValueType::field_type::integral_type>,
                                                  nil::crypto3::marshalling::option::fixed_size_storage<
                                                    FieldValueType::field_type::arity>>,
                        TOptions...>;

                public:
                    /// @brief endian_type used for serialization.
                    using endian_type = typename base_impl_type::endian_type;

                    /// @brief All the options provided to this class bundled into struct.
                    using parsed_options_type = ::nil::crypto3::marshalling::types::detail::options_parser<TOptions...>;

                    /// @brief Type of underlying field_element value.
                    /// @details Same as template parameter T to this class.
                    using value_type = typename base_impl_type::value_type;

                    /// @brief Default constructor
                    /// @details Initialises internal value to 0.
                    extended_field_element() = default;

                    /// @brief Constructor
                    explicit extended_field_element(const FieldValueType &field_elem) {

                        std::array<typename FieldValueType::field_type::integral_type, FieldValueType::field_type::arity> val_container =
                            detail::fill_field_data(field_elem);
                        for (std::size_t i = 0; i < FieldValueType::field_type::arity; i++) {
                            (base_impl_type::value()).emplace_back(val_container[i]);
                        }
                    }

                    /// @brief Copy constructor
                    extended_field_element(const extended_field_element &) = default;

                    /// @brief Destructor
                    ~extended_field_element() noexcept = default;

                    /// @brief Copy assignment
                    extended_field_element &operator=(const extended_field_element &) = default;

                    /// @brief Get access to field_element value storage.
                    FieldValueType const value() const {

                        std::array<typename FieldValueType::field_type::integral_type, FieldValueType::field_type::arity> field_elem_data;

                        for (std::size_t i = 0; i < FieldValueType::field_type::arity; i++) {
                            field_elem_data[i] = base_impl_type::value()[i].value();
                        }

                        return detail::make_field_element<FieldValueType>(field_elem_data.begin());
                    }

                    /// @brief Get access to field_element value storage.
                    FieldValueType value() {

                        std::array<typename FieldValueType::field_type::integral_type, FieldValueType::field_type::arity> field_elem_data;

                        for (std::size_t i = 0; i < FieldValueType::field_type::arity; i++) {
                            field_elem_data[i] = base_impl_type::value()[i].value();
                        }

                        return detail::make_field_element<FieldValueType>(field_elem_data.begin());
                    }

                    /// @brief Get length required to serialise the current field value.
                    /// @return Number of bytes it will take to serialise the field value.
                    constexpr std::size_t length() const {
                        return base_impl_type::length();
                    }

                    /// @brief Get length required to serialise the current field value.
                    /// @return Number of bytes it will take to serialise the field value.
                    static constexpr std::size_t bit_length() {
                        return base_impl_type::bit_length();
                    }

                    /// @brief Get minimal length that is required to serialise field of this type.
                    /// @return Minimal number of bytes required serialise the field value.
                    static constexpr std::size_t min_length() {
                        return base_impl_type::min_length();
                    }

                    /// @brief Get maximal length that is required to serialise field of this type.
                    /// @return Maximal number of bytes required serialise the field value.
                    static constexpr std::size_t max_length() {
                        return base_impl_type::max_length();
                    }

                    /// @brief Check validity of the field value.
                    bool valid() const {
                        return base_impl_type::valid();
                    }

                    /// @brief Refresh the field's value
                    /// @return @b true if the value has been updated, @b false otherwise
                    bool refresh() {
                        return base_impl_type::refresh();
                    }

                    /// @brief Read field value from input data sequence
                    /// @param[in, out] iter Iterator to read the data.
                    /// @param[in] size Number of bytes available for reading.
                    /// @return Status of read operation.
                    /// @post Iterator is advanced.
                    template<typename TIter>
                    nil::crypto3::marshalling::status_type read(TIter &iter, std::size_t size) {
                        return base_impl_type::read(iter, size);
                    }

                    /// @brief Read field value from input data sequence without error check and status report.
                    /// @details Similar to @ref read(), but doesn't perform any correctness
                    ///     checks and doesn't report any failures.
                    /// @param[in, out] iter Iterator to read the data.
                    /// @post Iterator is advanced.
                    template<typename TIter>
                    void read_no_status(TIter &iter) {
                        base_impl_type::read_no_status(iter);
                    }

                    /// @brief Write current field value to output data sequence
                    /// @param[in, out] iter Iterator to write the data.
                    /// @param[in] size Maximal number of bytes that can be written.
                    /// @return Status of write operation.
                    /// @post Iterator is advanced.
                    template<typename TIter>
                    nil::crypto3::marshalling::status_type write(TIter &iter, std::size_t size) const {
                        return base_impl_type::write(iter, size);
                    }

                    /// @brief Write current field value to output data sequence  without error check and status report.
                    /// @details Similar to @ref write(), but doesn't perform any correctness
                    ///     checks and doesn't report any failures.
                    /// @param[in, out] iter Iterator to write the data.
                    /// @post Iterator is advanced.
                    template<typename TIter>
                    void write_no_status(TIter &iter) const {
                        base_impl_type::write_no_status(iter);
                    }

                protected:
                    using base_impl_type::read_data;
                    using base_impl_type::write_data;

                private:
                    static_assert(!parsed_options_type::has_sequence_size_field_prefix,
                                  "nil::crypto3::marshalling::option::sequence_size_field_prefix option is not applicable to "
                                  "crypto3::field_element type");
                };

                template<typename TTypeBase,
                         typename FieldValueType,
                         typename... TOptions>
                using field_element =
                    typename std::conditional<algebra::is_extended_field_element<FieldValueType>::value,
                                              extended_field_element<TTypeBase, FieldValueType, TOptions...>,
                                              pure_field_element<TTypeBase, FieldValueType, TOptions...>>::type;

                // /// @brief Equality comparison operator.
                // /// @param[in] field1 First field.
                // /// @param[in] field2 Second field.
                // /// @return true in case fields are equal, false otherwise.
                // /// @related field_element
                // template<typename TTypeBase, typename CurveGroupType, typename... TOptions>
                // bool operator==(const field_element<TTypeBase, CurveGroupType, TOptions...> &field1,
                //                 const field_element<TTypeBase, CurveGroupType, TOptions...> &field2) {
                //     return field1.value() == field2.value();
                // }

                // /// @brief Non-equality comparison operator.
                // /// @param[in] field1 First field.
                // /// @param[in] field2 Second field.
                // /// @return true in case fields are NOT equal, false otherwise.
                // /// @related field_element
                // template<typename TTypeBase, typename CurveGroupType, typename... TOptions>
                // bool operator!=(const field_element<TTypeBase, CurveGroupType, TOptions...> &field1,
                //                 const field_element<TTypeBase, CurveGroupType, TOptions...> &field2) {
                //     return field1.value() != field2.value();
                // }

                // template<typename FieldValueType>
                // typename
                // std::enable_if<algebra::is_field_element<FieldValueType>::value &&
                //                             !(algebra::is_extended_field_element<FieldValueType>::value),
                //                         int>::type
                //     compare_field_data(const FieldValueType &field_elem1,
                //                        const FieldValueType &field_elem2) {
                //     return (field_elem1.to_integral()  < field_elem2.to_integral()) ?
                //     -1 :
                //     ((field_elem1.to_integral()  > field_elem2.to_integral()) ? 1 : 0);
                // }

                // template<typename FieldValueType>
                // typename std::enable_if<algebra::is_extended_field_element<FieldValueType>::value, bool>::type
                //     compare_field_data(const FieldValueType &field_elem1,
                //                        const FieldValueType &field_elem2) {
                //     for (std::size_t i = 0; i < FieldValueType::field_type::arity; i++) {

                //         int compare_result = compare_field_data<typename FieldValueType::underlying_type>(
                //             field_elem1.data[i], field_elem2.data[i]);
                //         if (compare_result != 0) {
                //             return compare_result;
                //         }
                //     }
                // }

                // /// @brief Equivalence comparison operator.
                // /// @param[in] field1 First field.
                // /// @param[in] field2 Second field.
                // /// @return true in case value of the first field is lower than than the value of the second.
                // /// @related field_element
                // template<typename TTypeBase, typename CurveGroupType, typename... TOptions>
                // bool operator<(const field_element<TTypeBase, CurveGroupType, TOptions...> &field1,
                //                const field_element<TTypeBase, CurveGroupType, TOptions...> &field2) {

                //     int compared_X =
                //         compare_field_data<typename CurveGroupType::field_type>(field1.value().X, field2.value().X);
                //     int compared_Y =
                //         compare_field_data<typename CurveGroupType::field_type>(field1.value().Y, field2.value().Y);
                //     int compared_Z =
                //         compare_field_data<typename CurveGroupType::field_type>(field1.value().Z, field2.value().Z);

                //     if (compared_X == -1)
                //         return true;
                //     if (compared_X == 0 && compared_Y == -1)
                //         return true;
                //     if (compared_X == 0 && compared_Y == 0 && compared_Z == -1)
                //         return true;
                //     return false;
                // }

                // /// @brief Upcast type of the field definition to its parent nil::crypto3::marshalling::types::field_element type
                // ///     in order to have access to its internal types.
                // /// @related nil::crypto3::marshalling::types::field_element
                // template<typename TTypeBase, typename CurveGroupType, typename... TOptions>
                // inline field_element<TTypeBase, CurveGroupType, TOptions...> &
                //     to_field_base(field_element<TTypeBase, CurveGroupType, TOptions...> &field) {
                //     return field;
                // }

                // /// @brief Upcast type of the field definition to its parent nil::crypto3::marshalling::types::field_element type
                // ///     in order to have access to its internal types.
                // /// @related nil::crypto3::marshalling::types::field_element
                // template<typename TTypeBase, typename CurveGroupType, typename... TOptions>
                // inline const field_element<TTypeBase, CurveGroupType, TOptions...> &
                //     to_field_base(const field_element<TTypeBase, CurveGroupType, TOptions...> &field) {
                //     return field;
                // }


                template<typename FieldValueType, typename TTypeBase>
                using field_element_vector = nil::crypto3::marshalling::types::standard_array_list<
                    TTypeBase,
                    field_element<TTypeBase, FieldValueType>>;

                template<typename FieldValueType, typename Endianness>
                field_element_vector<FieldValueType, nil::crypto3::marshalling::field_type<Endianness>>
                    fill_field_element_vector(const std::vector<FieldValueType> &field_elem_vector) {

                    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;
                    using field_element_type = field_element<TTypeBase, FieldValueType>;

                    field_element_vector<FieldValueType, TTypeBase> result;
                    for (std::size_t i = 0; i < field_elem_vector.size(); i++) {
                        result.value().push_back(field_element_type(field_elem_vector[i]));
                    }
                    return result;
                }

                template<typename FieldValueType, typename Endianness>
                std::vector<FieldValueType> make_field_element_vector(
                    const field_element_vector<FieldValueType, nil::crypto3::marshalling::field_type<Endianness>>& field_elem_vector) {

                    std::vector<FieldValueType> result;
                    result.reserve(field_elem_vector.value().size());
                    for (std::size_t i = 0; i < field_elem_vector.value().size(); i++) {
                        result.push_back(field_elem_vector.value()[i].value());
                    }
                    return result;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_FIELD_ELEMENT_HPP
