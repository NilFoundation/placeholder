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

#ifndef MARSHALLING_OPTIONS_PARSER_HPP
#define MARSHALLING_OPTIONS_PARSER_HPP

#include <tuple>
#include <nil/marshalling/options.hpp>

namespace nil::crypto3 {
    namespace marshalling {
        namespace types {
            namespace detail {

                template<typename... TOptions>
                class options_parser;

                template<>
                class options_parser<> {
                public:
                    static const bool has_fixed_size_storage = false;
                    static const bool has_sequence_fixed_size_use_fixed_size_storage = false;
                    static const bool has_sequence_size_field_prefix = false;
                };

                template<typename TSizeField, typename... TOptions>
                class options_parser<nil::crypto3::marshalling::option::sequence_size_field_prefix<TSizeField>, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_sequence_size_field_prefix = true;
                    using sequence_size_field_prefix = TSizeField;
                };

                template<std::size_t TSize, typename... TOptions>
                class options_parser<nil::crypto3::marshalling::option::fixed_size_storage<TSize>, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_fixed_size_storage = true;
                    static const std::size_t fixed_size_storage = TSize;
                };
                template<typename... TOptions>
                class options_parser<nil::crypto3::marshalling::option::sequence_fixed_size_use_fixed_size_storage, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_sequence_fixed_size_use_fixed_size_storage = true;
                };

                template<typename... TTupleOptions, typename... TOptions>
                class options_parser<std::tuple<TTupleOptions...>, TOptions...>
                    : public options_parser<TTupleOptions..., TOptions...> { };

            }    // namespace detail
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil::crypto3
#endif    // MARSHALLING_OPTIONS_PARSER_HPP
