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

#ifndef MARSHALLING_ARRAY_LIST_HPP
#define MARSHALLING_ARRAY_LIST_HPP

#include <functional>
#include <vector>
#include <map>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/types/array_list/behaviour.hpp>
#include <nil/marshalling/types/detail/options_parser.hpp>

#include <nil/marshalling/types/tag.hpp>
#include <nil/detail/type_traits.hpp>

namespace nil::crypto3 {
    namespace marshalling {
        namespace types {
            /// @brief field_type that represents a sequential collection of fields.
            /// @details By default uses
            ///     <a href="http://en.cppreference.com/w/cpp/container/vector">std::vector</a>,
            ///     for internal storage, unless nil::crypto3::marshalling::option::fixed_size_storage option is used,
            ///     which forces usage of nil::crypto3::marshalling::container::static_vector instead.
            /// @tparam TFieldBase Base class for this field, expected to be a variant of
            ///     nil::crypto3::marshalling::field_type.
            /// @tparam TElement Element of the collection, can be either basic integral value
            ///     (such as std::uint8_t) or any other field from nil::crypto3::marshalling::types namespace.@n
            ///     For example:
            ///     @code
            ///     using MyFieldBase = nil::crypto3::marshalling::field_type<nil::crypto3::marshalling::option::BigEndian>;
            ///     using RawDataSeqField =
            ///         nil::crypto3::marshalling::types::array_list<
            ///             MyFieldBase,
            ///             std::uint8_t
            ///         >;
            ///     using CollectionOfBundlesField =
            ///         nil::crypto3::marshalling::types::array_list<
            ///             MyFieldBase,
            ///             std::types::bundle<
            ///                 MyFieldBase,
            ///                 std::tuple<
            ///                     nil::crypto3::marshalling::types::integral<MyFieldBase, std::uint16_t>
            ///                     nil::crypto3::marshalling::types::integral<MyFieldBase, std::uint8_t>
            ///                     nil::crypto3::marshalling::types::integral<MyFieldBase, std::uint8_t>
            ///                 >
            ///             >
            ///         >;
            ///     @endcode
            /// @tparam TOptions Zero or more options that modify/refine default behaviour
            ///     of the field.@n
            ///     Supported options are:
            ///     @li @ref nil::crypto3::marshalling::option::fixed_size_storage
            ///     @li @ref nil::crypto3::marshalling::option::sequence_size_field_prefix
            /// @extends nil::crypto3::marshalling::field_type
            /// @headerfile nil/marshalling/types/array_list.hpp
            template<typename TFieldBase, typename TElement, typename... TOptions>
            class array_list : private detail::array_list_base_type<TFieldBase, TElement, TOptions...> {
                using base_impl_type = detail::array_list_base_type<TFieldBase, TElement, TOptions...>;

            public:
                /// @brief endian_type used for serialization.
                using endian_type = typename base_impl_type::endian_type;

                /// @brief All the options provided to this class bundled into struct.
                using parsed_options_type = detail::options_parser<TOptions...>;

                /// @brief Tag indicating type of the field
                using tag = typename std::conditional<std::is_integral<TElement>::value, tag::raw_array_list,
                                                      tag::array_list>::type;

                /// @brief Type of underlying value.
                /// @details If nil::crypto3::marshalling::option::fixed_size_storage option is NOT used, the
                ///     value_type is std::vector<TElement>, otherwise it becomes
                ///     nil::crypto3::marshalling::container::static_vector<TElement, TSize>, where TSize is a size
                ///     provided to nil::crypto3::marshalling::option::fixed_size_storage option.
                using value_type = typename base_impl_type::value_type;

                /// @brief Type of the element.
                using element_type = typename base_impl_type::element_type;

                /// @brief Default constructor
                array_list() = default;

                /// @brief Value constructor
                explicit array_list(const value_type &val) : base_impl_type(val) {
                }

                /// @brief Value constructor
                explicit array_list(value_type &&val) : base_impl_type(std::move(val)) {
                }

                /// @brief Copy constructor
                array_list(const array_list &) = default;

                /// @brief Move constructor
                array_list(array_list &&) = default;

                /// @brief Destructor
                ~array_list() noexcept = default;

                /// @brief Copy assignment
                array_list &operator=(const array_list &) = default;

                /// @brief Move assignment
                array_list &operator=(array_list &&) = default;

                /// @brief Get access to the value storage.
                value_type &value() {
                    return base_impl_type::value();
                }

                /// @brief Get access to the value storage.
                const value_type &value() const {
                    return base_impl_type::value();
                }

                /// @brief Get length of serialized data
                constexpr std::size_t length() const {
                    return base_impl_type::length();
                }

                /// @brief Get bit length of serialized data
                constexpr std::size_t bit_length() const {
                    return base_impl_type::bit_length();
                }
                
                /// @brief Read field value from input data sequence
                /// @details By default, the read operation will try to consume all the
                ///     data available, unless size limiting option (such as
                ///     nil::crypto3::marshalling::option::sequence_size_field_prefix) is used.
                /// @param[in, out] iter Iterator to read the data.
                /// @param[in] len Number of bytes available for reading.
                /// @return Status of read operation.
                /// @post Iterator is advanced.
                template<typename TIter>
                status_type read(TIter &iter, std::size_t len) {
                    return base_impl_type::read(iter, len);
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
                /// @details By default, the write operation will write all the
                ///     elements the field contains. If nil::crypto3::marshalling::option::sequence_fixed_size option
                ///     is used, the number of elements, that is going to be written, is
                ///     exactly as the option specifies. If underlying vector storage
                ///     doesn't contain enough data, the default constructed elements will
                ///     be appended to the written sequence until the required amount of
                ///     elements is reached.
                /// @param[in, out] iter Iterator to write the data.
                /// @param[in] len Maximal number of bytes that can be written.
                /// @return Status of write operation.
                /// @post Iterator is advanced.
                template<typename TIter>
                status_type write(TIter &iter, std::size_t len) const {
                    return base_impl_type::write(iter, len);
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

                /// @brief Check validity of the field value.
                /// @details The collection is valid if all the elements are valid.
                /// @return true in case the field's value is valid, false otherwise.
                bool valid() const {
                    return base_impl_type::valid();
                }

                /// @brief Refresh the field.
                /// @details Calls refresh() on all the elements (if they are fields and not raw bytes).
                /// @brief Returns true if any of the elements has been updated, false otherwise.
                bool refresh() {
                    return base_impl_type::refresh();
                }

                /// @brief Get minimal length that is required to serialise field of this type.
                static constexpr std::size_t min_length() {
                    return base_impl_type::min_length();
                }

                /// @brief Get maximal length that is required to serialise field of this type.
                static constexpr std::size_t max_length() {
                    return base_impl_type::max_length();
                }

            protected:
                using base_impl_type::read_data;
                using base_impl_type::write_data;

            };

            /// @brief Equivalence comparison operator.
            /// @details Performs lexicographical compare of two array fields.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return true in case first field is less than second field.
            /// @related array_list
            template<typename TFieldBase, typename TElement, typename... TOptions>
            bool operator<(const array_list<TFieldBase, TElement, TOptions...> &field1,
                           const array_list<TFieldBase, TElement, TOptions...> &field2) {
                return std::lexicographical_compare(field1.value().begin(), field1.value().end(),
                                                    field2.value().begin(), field2.value().end());
            }

            /// @brief Non-equality comparison operator.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return true in case fields are NOT equal, false otherwise.
            /// @related array_list
            template<typename TFieldBase, typename TElement, typename... TOptions>
            bool operator!=(const array_list<TFieldBase, TElement, TOptions...> &field1,
                            const array_list<TFieldBase, TElement, TOptions...> &field2) {
                return (field1 < field2) || (field2 < field1);
            }

            /// @brief Equality comparison operator.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return true in case fields are equal, false otherwise.
            /// @related array_list
            template<typename TFieldBase, typename TElement, typename... TOptions>
            bool operator==(const array_list<TFieldBase, TElement, TOptions...> &field1,
                            const array_list<TFieldBase, TElement, TOptions...> &field2) {
                return !(field1 != field2);
            }

            /// @brief Upcast type of the field definition to its parent nil::crypto3::marshalling::types::array_list type
            ///     in order to have access to its internal types.
            /// @related nil::crypto3::marshalling::types::array_list
            template<typename TFieldBase, typename TElement, typename... TOptions>
            inline array_list<TFieldBase, TElement, TOptions...> &
                to_field_base(array_list<TFieldBase, TElement, TOptions...> &field) {
                return field;
            }

            /// @brief Upcast type of the field definition to its parent nil::crypto3::marshalling::types::array_list type
            ///     in order to have access to its internal types.
            /// @related nil::crypto3::marshalling::types::array_list
            template<typename TFieldBase, typename TElement, typename... TOptions>
            inline const array_list<TFieldBase, TElement, TOptions...> &
                to_field_base(const array_list<TFieldBase, TElement, TOptions...> &field) {
                return field;
            }

            // We use this type of array_list waay too often, so this is a shortcut, not to copy-paste it all the time.
            template<typename TFieldBase, typename TElement>
            using standard_array_list = array_list<
                TFieldBase,
                TElement,
                nil::crypto3::marshalling::option::size_t_sequence_size_field_prefix<TFieldBase>>;

            // Very often we just need an array list of std::size_t, so here's another shortcut.
            template<typename TFieldBase>
            using standard_size_t_array_list = array_list<
                TFieldBase,
                nil::crypto3::marshalling::types::integral<TFieldBase, std::size_t>,
                nil::crypto3::marshalling::option::size_t_sequence_size_field_prefix<TFieldBase>>;

            // Helper functions to convert to/from an arraylist.
            template<typename TFieldBase, typename TMarshalledElement, typename Range>
            typename std::enable_if<
                marshalling::detail::is_range<Range>::value, 
                standard_array_list<TFieldBase, TMarshalledElement>>::type 
            fill_standard_array_list(
                    const Range& input_range,
                    std::function<TMarshalledElement(const typename Range::value_type&)> element_marshalling) {
                standard_array_list<TFieldBase, TMarshalledElement> result;
                for (const auto& v: input_range) {
                    result.value().push_back(element_marshalling(v));
                }
                return result;
            }

            template<typename TFieldBase, typename TElement, typename TMarshalledElement> 
            std::vector<TElement> make_standard_array_list(
                const standard_array_list<TFieldBase, TMarshalledElement>& filled_array,
                std::function<TElement(const TMarshalledElement&)> element_de_marshalling)
            {
                std::vector<TElement> result;
                result.reserve(filled_array.value().size());
                for (const auto& v: filled_array.value()) {
                    result.push_back(element_de_marshalling(v));
                }
                return result;
            }

            // Helper functions to marshall an std::map.
            // We keep TKey, TValue at the end, because they can be decuded from the map type, but the other 3
            // arguments must be provided explicitly.
            template<typename TFieldBase, typename TMarshalledKey, typename TMarshalledValue, typename TKey, typename TValue>
            std::pair<standard_array_list<TFieldBase, TMarshalledKey>, standard_array_list<TFieldBase, TMarshalledValue>>
            fill_std_map(
                    const std::map<TKey, TValue>& input_map,
                    std::function<TMarshalledKey(const TKey&)> key_marshalling,
                    std::function<TMarshalledValue(const TValue&)> value_marshalling) {
                standard_array_list<TFieldBase, TMarshalledKey> result_keys;
                standard_array_list<TFieldBase, TMarshalledValue> result_values;
                for (const auto& [k, v]: input_map) {
                    result_keys.value().push_back(key_marshalling(k));
                    result_values.value().push_back(value_marshalling(v));
                }
                return {result_keys, result_values};
            }

            template<typename TFieldBase, typename TKey, typename TValue, typename TMarshalledKey, typename TMarshalledValue>
            std::map<TKey, TValue> make_std_map(
                    const standard_array_list<TFieldBase, TMarshalledKey>& filled_keys,
                    const standard_array_list<TFieldBase, TMarshalledValue>& filled_values,
                    std::function<TKey(const TMarshalledKey&)> key_de_marshalling,
                    std::function<TValue(const TMarshalledValue&)> value_de_marshalling)
            {
                if (filled_keys.value().size() != filled_values.value().size()) {
                    throw std::invalid_argument("Number of values and keys do not match");;
                }

                std::map<TKey, TValue> result;
                for (std::size_t i = 0; i < filled_keys.value().size(); ++i) {
                    result[key_de_marshalling(filled_keys.value()[i])] = value_de_marshalling(filled_values.value()[i]);
                }
                return result;
            }

        }    // namespace types
    }        // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_ARRAY_LIST_HPP
