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

#ifndef MARSHALLING_ADAPT_BASIC_FIELD_HPP
#define MARSHALLING_ADAPT_BASIC_FIELD_HPP

#include <nil/marshalling/types/adapter/sequence_size_field_prefix.hpp>
#include <nil/marshalling/types/detail/options_parser.hpp>

namespace nil::crypto3 {
    namespace marshalling {
        namespace types {
            namespace detail {

                template<bool T1 = false,
                         bool T2 = false,
                         bool T3 = false,
                         bool T4 = false,
                         bool T5 = false,
                         bool T6 = false>
                struct fields_options_compatibility_calc {
                    static const std::size_t value = static_cast<std::size_t>(T1) + static_cast<std::size_t>(T2)
                                                     + static_cast<std::size_t>(T3) + static_cast<std::size_t>(T4)
                                                     + static_cast<std::size_t>(T5) + static_cast<std::size_t>(T6);
                };

                template<bool THasSequenceSizeFieldPrefix>
                struct adapt_field_sequence_size_field_prefix;

                template<>
                struct adapt_field_sequence_size_field_prefix<true> {
                    template<typename TField, typename TOpts>
                    using type = types::adapter::
                        sequence_size_field_prefix<typename TOpts::sequence_size_field_prefix, TField>;
                };

                template<>
                struct adapt_field_sequence_size_field_prefix<false> {
                    template<typename TField, typename TOpts>
                    using type = TField;
                };
                template<typename TField, typename TOpts>
                using adapt_field_sequence_size_field_prefix_type = typename adapt_field_sequence_size_field_prefix<
                    TOpts::has_sequence_size_field_prefix>::template type<TField, TOpts>;

                template<typename TBasic, typename... TOptions>
                class adapt_basic_field {
                    using parsed_options_type = options_parser<TOptions...>;
                    using sequence_size_field_prefix_adapted
                        = adapt_field_sequence_size_field_prefix_type<TBasic, parsed_options_type>;
                public:
                    using type = sequence_size_field_prefix_adapted;
                };

                template<typename TBasic, typename... TOptions>
                using adapt_basic_field_type = typename adapt_basic_field<TBasic, TOptions...>::type;

            }    // namespace detail
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_ADAPT_BASIC_FIELD_HPP
