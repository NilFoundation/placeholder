//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <nil/actor/config_value.hpp>

#include <nil/actor/detail/move_if_not_ptr.hpp>
#include <nil/actor/dictionary.hpp>
#include <nil/actor/optional.hpp>
#include <nil/actor/raise_error.hpp>
#include <nil/actor/string_view.hpp>

namespace nil {
    namespace actor {

        /// Software options stored as key-value pairs.
        /// @relates config_value
        using settings = dictionary<config_value>;

        /// Tries to retrieve the value associated to `name` from `xs`.
        /// @relates config_value
        BOOST_SYMBOL_VISIBLE const config_value *get_if(const settings *xs, string_view name);

        /// Tries to retrieve the value associated to `name` from `xs`.
        /// @relates config_value
        template<class T>
        auto get_if(const settings *xs, string_view name) {
            auto value = get_if(xs, name);
            using result_type = decltype(get_if<T>(value));
            return value ? get_if<T>(value) : result_type {};
        }

        /// Returns whether `xs` associates a value of type `T` to `name`.
        /// @relates config_value
        template<class T>
        bool holds_alternative(const settings &xs, string_view name) {
            using access = select_config_value_access_t<T>;
            if (auto value = get_if(&xs, name))
                return access::is(*value);
            return false;
        }

        template<class T>
        T get(const settings &xs, string_view name) {
            auto result = get_if<T>(&xs, name);
            ACTOR_ASSERT(result);
            return detail::move_if_not_ptr(result);
        }

        template<class T, class = typename std::enable_if<!std::is_pointer<T>::value &&
                                                          !std::is_convertible<T, string_view>::value>::type>
        T get_or(const settings &xs, string_view name, T default_value) {
            auto result = get_if<T>(&xs, name);
            if (result)
                return std::move(*result);
            return default_value;
        }

        BOOST_SYMBOL_VISIBLE std::string get_or(const settings &xs, string_view name, string_view default_value);

        /// @private
        BOOST_SYMBOL_VISIBLE config_value &put_impl(settings &dict, const std::vector<string_view> &path,
                                                    config_value &value);

        /// @private
        BOOST_SYMBOL_VISIBLE config_value &put_impl(settings &dict, string_view key, config_value &value);

        /// Converts `value` to a `config_value` and assigns it to `key`.
        /// @param dict Dictionary of key-value pairs.
        /// @param key Human-readable nested keys in the form `category.key`.
        /// @param value New value for given `key`.
        template<class T>
        config_value &put(settings &dict, string_view key, T &&value) {
            config_value tmp {std::forward<T>(value)};
            return put_impl(dict, key, tmp);
        }

        /// Converts `value` to a `config_value` and assigns it to `key` unless `xs`
        /// already contains `key` (does nothing in this case).
        /// @param xs Dictionary of key-value pairs.
        /// @param key Human-readable nested keys in the form `category.key`.
        /// @param value New value for given `key`.
        template<class T>
        void put_missing(settings &xs, string_view key, T &&value) {
            if (get_if(&xs, key) != nullptr)
                return;
            config_value tmp {std::forward<T>(value)};
            put_impl(xs, key, tmp);
        }

        /// Inserts a new list named `name` into the dictionary `xs` and returns
        /// a reference to it. Overrides existing entries with the same name.
        BOOST_SYMBOL_VISIBLE config_value::list &put_list(settings &xs, std::string name);

        /// Inserts a new list named `name` into the dictionary `xs` and returns
        /// a reference to it. Overrides existing entries with the same name.
        BOOST_SYMBOL_VISIBLE config_value::dictionary &put_dictionary(settings &xs, std::string name);

    }    // namespace actor
}    // namespace nil
