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

#include <type_traits>

#include <nil/actor/config_value.hpp>
#include <nil/actor/detail/type_traits.hpp>

namespace nil::actor::detail {

    template<class Trait>
    struct dispatch_parse_cli_helper {
        template<class... Ts>
        auto operator()(Ts &&... xs) -> decltype(Trait::parse_cli(std::forward<Ts>(xs)...)) {
            return Trait::parse_cli(std::forward<Ts>(xs)...);
        }
    };

    template<class Access, class T>
    void dispatch_parse_cli(std::true_type, string_parser_state &ps, T &x, const char *char_blacklist) {
        Access::parse_cli(ps, x, char_blacklist);
    }

    template<class Access, class T>
    void dispatch_parse_cli(std::false_type, string_parser_state &ps, T &x, const char *) {
        Access::parse_cli(ps, x);
    }

    template<class T>
    void dispatch_parse_cli(string_parser_state &ps, T &x, const char *char_blacklist) {
        using access = nil::actor::select_config_value_access_t<T>;
        using helper_fun = dispatch_parse_cli_helper<access>;
        using token_type =
            bool_token<detail::is_callable_with<helper_fun, string_parser_state &, T &, const char *>::value>;
        token_type token;
        dispatch_parse_cli<access>(token, ps, x, char_blacklist);
    }

}    // namespace nil::actor::detail