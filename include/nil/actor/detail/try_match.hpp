//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#pragma once

#include <array>
#include <numeric>
#include <typeinfo>

#include <nil/actor/atom.hpp>
#include <nil/actor/type_nr.hpp>

#include <nil/actor/detail/type_list.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            struct meta_element {
                atom_value v;
                uint16_t typenr;
                const std::type_info *type;
                bool (*fun)(const meta_element &, const type_erased_tuple &, size_t);
            };

            bool match_element(const meta_element &, const type_erased_tuple &, size_t);

            bool match_atom_constant(const meta_element &, const type_erased_tuple &, size_t);

            template<class T, uint16_t TN = type_nr<T>::value>
            struct meta_element_factory {
                static meta_element create() {
                    return {static_cast<atom_value>(0), TN, nullptr, match_element};
                }
            };

            template<class T>
            struct meta_element_factory<T, 0> {
                static meta_element create() {
                    return {static_cast<atom_value>(0), 0, &typeid(T), match_element};
                }
            };

            template<atom_value V>
            struct meta_element_factory<atom_constant<V>, type_nr<atom_value>::value> {
                static meta_element create() {
                    return {V, type_nr<atom_value>::value, nullptr, match_atom_constant};
                }
            };

            template<class TypeList>
            struct meta_elements;

            template<class... Ts>
            struct meta_elements<type_list<Ts...>> {
                std::array<meta_element, sizeof...(Ts)> arr;
                meta_elements() : arr {{meta_element_factory<Ts>::create()...}} {
                    // nop
                }
            };

            bool try_match(const type_erased_tuple &xs, const meta_element *iter, size_t ps);

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
