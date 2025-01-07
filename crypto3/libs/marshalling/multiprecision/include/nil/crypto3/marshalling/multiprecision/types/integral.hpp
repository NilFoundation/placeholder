//---------------------------------------------------------------------------//
// Copyright (c) 2017-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_INTEGRAL_HPP
#define CRYPTO3_MARSHALLING_INTEGRAL_HPP

#include <cstddef>

#include <nil/crypto3/multiprecision/big_uint.hpp>

#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/tag.hpp>
#include <nil/marshalling/types/detail/adapt_basic_field.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/multiprecision/types/detail/integral/basic_type.hpp>
#include <nil/crypto3/marshalling/multiprecision/inference.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                /// @brief field_type that represent integral value.
                /// @tparam TTypeBase Base class for this field, expected to be a variant of
                ///     nil::crypto3::marshalling::field_type.
                /// @tparam T Basic underlying integral type.
                /// @tparam TOptions Zero or more options that modify/refine default behaviour
                ///     of the field. If no option is provided The field's value is serialized as is.
                ///     @code
                ///         using MyFieldBase = nil::crypto3::marshalling::field_type<nil::crypto3::marshalling::option::big_endian>;
                ///
                ///         constexpr static const std::size_t modulus_bits = 381;
                ///         using modulus_type = nil::crypto3::multiprecision::big_uint<modulus_bits>;
                ///         using MyField = nil::crypto3::marshalling::types::integral<MyFieldBase, modulus_type>;
                ///     @endcode
                ///     In the example above it will
                ///     consume ?? bytes (because sizeof(modulus_type) == ??) and will
                ///     be serialized using big endian notation.@n
                /// @extends nil::crypto3::marshalling::field_type
                /// @headerfile nil/marshalling/types/integral.hpp
                template<typename TTypeBase, typename IntegralContainer, typename... TOptions>
                class integral;

                template<typename TTypeBase,
                         std::size_t Bits,
                         typename... TOptions>
                class integral<TTypeBase, nil::crypto3::multiprecision::big_uint<Bits>, TOptions...>
                    : public detail::adapt_basic_field_type<
                          detail::basic_integral<TTypeBase, nil::crypto3::multiprecision::big_uint<Bits>>, TOptions...>
                {

                    using base_impl_type = detail::adapt_basic_field_type<
                          detail::basic_integral<TTypeBase, nil::crypto3::multiprecision::big_uint<Bits>>, TOptions...>;

                public:
                    /// @brief endian_type used for serialization.
                    using endian_type = typename base_impl_type::endian_type;

                    /// @brief All the options provided to this class bundled into struct.
                    using parsed_options_type = ::nil::crypto3::marshalling::types::detail::options_parser<TOptions...>;

                    /// @brief Tag indicating type of the field
                    using tag = ::nil::crypto3::marshalling::types::tag::integral;

                    /// @brief Type of underlying integral value.
                    /// @details Same as template parameter T to this class.
                    using value_type = typename base_impl_type::value_type;

                    /// @brief Default constructor
                    /// @details Initialises internal value to 0.
                    integral() = default;

                    /// @brief Constructor
                    explicit integral(const value_type &val) : base_impl_type(val) {
                    }

                    /// @brief Copy constructor
                    integral(const integral &) = default;

                    /// @brief Destructor
                    ~integral() noexcept = default;

                    /// @brief Copy assignment
                    integral &operator=(const integral &) = default;

                    /// @brief Get access to integral value storage.
                    const value_type &value() const {
                        return base_impl_type::value();
                    }

                    /// @brief Get access to integral value storage.
                    value_type &value() {
                        return base_impl_type::value();
                    }

                    // /// @brief Get length required to serialise the current field value.
                    // /// @return Number of bytes it will take to serialise the field value.
                    // std::size_t length() {
                    //     return base_impl_type::length();
                    // }

                    // /// @brief Get length required to serialise the current field value.
                    // /// @return Number of bytes it will take to serialise the field value.
                    // static constexpr std::size_t bit_length() {
                    //     return base_impl_type::bit_length();
                    // }

                    // /// @brief Get minimal length that is required to serialise field of this type.
                    // /// @return Minimal number of bytes required serialise the field value.
                    // static constexpr std::size_t min_length() {
                    //     return base_impl_type::min_length();
                    // }

                    // /// @brief Get maximal length that is required to serialise field of this type.
                    // /// @return Maximal number of bytes required serialise the field value.
                    // static constexpr std::size_t max_length() {
                    //     return base_impl_type::max_length();
                    // }

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
                                  "crypto3::integral type");
                    static_assert(!parsed_options_type::has_fixed_size_storage,
                                  "nil::crypto3::marshalling::option::fixed_size_storage option is not applicable to "
                                  "crypto3::integral type");
                };

                /// @brief Equality comparison operator.
                /// @param[in] field1 First field.
                /// @param[in] field2 Second field.
                /// @return true in case fields are equal, false otherwise.
                /// @related integral
                template<typename TTypeBase,
                         std::size_t Bits,
                         typename... TOptions>
                bool operator==(
                    const integral<TTypeBase, nil::crypto3::multiprecision::big_uint<Bits>, TOptions...>
                        &field1,
                    const integral<TTypeBase, nil::crypto3::multiprecision::big_uint<Bits>, TOptions...>
                        &field2) {
                    return field1.value() == field2.value();
                }

                /// @brief Non-equality comparison operator.
                /// @param[in] field1 First field.
                /// @param[in] field2 Second field.
                /// @return true in case fields are NOT equal, false otherwise.
                /// @related integral
                template<typename TTypeBase,
                         std::size_t Bits,
                         typename... TOptions>
                bool operator!=(
                    const integral<TTypeBase, nil::crypto3::multiprecision::big_uint<Bits>, TOptions...>
                        &field1,
                    const integral<TTypeBase, nil::crypto3::multiprecision::big_uint<Bits>, TOptions...>
                        &field2) {
                    return field1.value() != field2.value();
                }

                /// @brief Equivalence comparison operator.
                /// @param[in] field1 First field.
                /// @param[in] field2 Second field.
                /// @return true in case value of the first field is lower than than the value of the second.
                /// @related integral
                template<typename TTypeBase,
                         std::size_t Bits,
                         typename... TOptions>
                bool operator<(
                    const integral<nil::crypto3::multiprecision::big_uint<Bits>, TOptions...>
                        &field1,
                    const integral<nil::crypto3::multiprecision::big_uint<Bits>, TOptions...>
                        &field2) {
                    return field1.value() < field2.value();
                }

                /// @brief Upcast type of the field definition to its parent nil::crypto3::marshalling::types::integral type
                ///     in order to have access to its internal types.
                /// @related nil::crypto3::marshalling::types::integral
                template<typename TTypeBase,
                         std::size_t Bits,
                         typename... TOptions>
                inline integral<TTypeBase, nil::crypto3::multiprecision::big_uint<Bits>, TOptions...> &
                    to_field_base(
                        integral<TTypeBase, nil::crypto3::multiprecision::big_uint<Bits>, TOptions...> &field) {
                    return field;
                }

                /// @brief Upcast type of the field definition to its parent nil::crypto3::marshalling::types::integral type
                ///     in order to have access to its internal types.
                /// @related nil::crypto3::marshalling::types::integral
                template<typename TTypeBase,
                         std::size_t Bits,
                         typename... TOptions>
                inline const integral<TTypeBase, nil::crypto3::multiprecision::big_uint<Bits>, TOptions...> &
                    to_field_base(
                        const integral<TTypeBase, nil::crypto3::multiprecision::big_uint<Bits>, TOptions...>
                            &field) {
                    return field;
                }

                template<typename IntegralContainer, typename Endianness>
                nil::crypto3::marshalling::types::standard_array_list<
                    nil::crypto3::marshalling::field_type<Endianness>,
                    integral<nil::crypto3::marshalling::field_type<Endianness>, IntegralContainer>>
                    fill_integral_vector(std::vector<IntegralContainer> integral_vector) {

                    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;

                    using integral_type = integral<TTypeBase, IntegralContainer>;

                    using integral_vector_type = nil::crypto3::marshalling::types::standard_array_list<
                        TTypeBase,
                        integral_type>;

                    integral_vector_type result;

                    std::vector<integral_type> &val = result.value();
                    for (std::size_t i = 0; i < integral_vector.size(); i++) {
                        val.push_back(integral_type(integral_vector[i]));
                    }
                    return result;
                }

                template<typename IntegralContainer, typename Endianness>
                std::vector<IntegralContainer> make_integral_vector(
                    nil::crypto3::marshalling::types::standard_array_list<
                        nil::crypto3::marshalling::field_type<Endianness>,
                        integral<nil::crypto3::marshalling::field_type<Endianness>, IntegralContainer>>
                        const& integral_vector)
                {
                    std::vector<integral<nil::crypto3::marshalling::field_type<Endianness>, IntegralContainer>> const& values =
                        integral_vector.value();
                    std::size_t size = values.size();
                    std::vector<IntegralContainer> result;
                    result.reserve(size);

                    for (std::size_t i = 0; i < size; i++) {
                        result.emplace_back(values[i].value());
                    }
                    return result;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_INTEGRAL_HPP
