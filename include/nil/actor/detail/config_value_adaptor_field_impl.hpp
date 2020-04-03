//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <cstddef>
#include <tuple>

#include <nil/actor/config_value.hpp>
#include <nil/actor/config_value_adaptor_field.hpp>
#include <nil/actor/config_value_field.hpp>
#include <nil/actor/detail/config_value_field_base.hpp>
#include <nil/actor/detail/dispatch_parse_cli.hpp>
#include <nil/actor/string_view.hpp>

namespace nil::actor::detail {

    template<class T, size_t Pos>
    class config_value_adaptor_field_impl
        : public config_value_field_base<T, typename std::tuple_element<Pos, T>::type> {
    public:
        using object_type = T;

        using value_type = typename std::tuple_element<Pos, T>::type;

        using field_type = config_value_adaptor_field<value_type>;

        using predicate_type = bool (*)(const value_type &);

        using super = config_value_field_base<object_type, value_type>;

        explicit config_value_adaptor_field_impl(field_type x) :
            super(x.name, std::move(x.default_value), x.predicate) {
            // nop
        }

        config_value_adaptor_field_impl(config_value_adaptor_field_impl &&) = default;

        const value_type &get_value(const object_type &x) const override {
            return std::get<Pos>(x);
        }

        void set_value(object_type &x, value_type y) const override {
            std::get<Pos>(x) = std::move(y);
        }
    };

    template<class T, class Ps>
    struct select_adaptor_fields;

    template<class T, long... Pos>
    struct select_adaptor_fields<T, detail::int_list<Pos...>> {
        using type = std::tuple<config_value_adaptor_field_impl<T, Pos>...>;
    };

}    // namespace nil::actor::detail