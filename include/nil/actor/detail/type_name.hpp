//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#pragma once

#include <string>
#include <type_traits>
#include <vector>

#include <nil/actor/dictionary.hpp>
#include <nil/actor/fwd.hpp>
#include <nil/actor/timestamp.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            template<size_t Bytes>
            struct type_name_builder_int_size;

            template<>
            struct type_name_builder_int_size<1> {
                void operator()(std::string &result) const {
                    result += "8";
                }
            };

            template<>
            struct type_name_builder_int_size<2> {
                void operator()(std::string &result) const {
                    result += "16";
                }
            };

            template<>
            struct type_name_builder_int_size<4> {
                void operator()(std::string &result) const {
                    result += "32";
                }
            };

            template<>
            struct type_name_builder_int_size<8> {
                void operator()(std::string &result) const {
                    result += "64";
                }
            };

            template<class T, bool IsInteger = std::is_integral<T>::value>
            struct type_name_builder;

            template<>
            struct type_name_builder<bool, true> {
                void operator()(std::string &result) const {
                    result += "boolean";
                }
            };

#define ACTOR_TYPE_NAME_BUILDER_NOINT(class_name, pretty_name) \
    template<>                                               \
    struct type_name_builder<class_name, false> {            \
        void operator()(std::string &result) const {         \
            result += pretty_name;                           \
        }                                                    \
    }

            ACTOR_TYPE_NAME_BUILDER_NOINT(float, "32-bit real");

            ACTOR_TYPE_NAME_BUILDER_NOINT(double, "64-bit real");

            ACTOR_TYPE_NAME_BUILDER_NOINT(timespan, "timespan");

            ACTOR_TYPE_NAME_BUILDER_NOINT(std::string, "string");

            ACTOR_TYPE_NAME_BUILDER_NOINT(atom_value, "atom");

            ACTOR_TYPE_NAME_BUILDER_NOINT(uri, "uri");

#undef ACTOR_TYPE_NAME_BUILDER

            template<class T>
            struct type_name_builder<T, true> {
                void operator()(std::string &result) const {
                    // TODO: replace with if constexpr when switching to C++17
                    if (!std::is_signed<T>::value)
                        result += 'u';
                    result += "int";
                    type_name_builder_int_size<sizeof(T)> g;
                    g(result);
                }
            };

            template<class T>
            struct type_name_builder<std::vector<T>, false> {
                void operator()(std::string &result) const {
                    result += "list of ";
                    type_name_builder<T> g;
                    g(result);
                }
            };

            template<class T>
            struct type_name_builder<dictionary<T>, false> {
                void operator()(std::string &result) const {
                    result += "dictionary of ";
                    type_name_builder<T> g;
                    g(result);
                }
            };

            template<class T>
            std::string type_name() {
                std::string result;
                type_name_builder<T> f;
                f(result);
                return result;
            }

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
