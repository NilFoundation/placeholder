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

#include <algorithm>
#include <limits>
#include <sstream>
#include <string>
#include <type_traits>
#include <vector>

#include <nil/actor/config.hpp>

#include <nil/actor/detail/type_traits.hpp>
#include <nil/actor/string_view.hpp>

namespace nil {
    namespace actor {

        // provide boost::split compatible interface

        inline string_view is_any_of(string_view arg) {
            return arg;
        }

        constexpr bool token_compress_on = false;

        BOOST_SYMBOL_VISIBLE void split(std::vector<std::string> &result, string_view str, string_view delims,
                                        bool keep_all = true);

        BOOST_SYMBOL_VISIBLE void split(std::vector<string_view> &result, string_view str, string_view delims,
                                        bool keep_all = true);

        BOOST_SYMBOL_VISIBLE void split(std::vector<std::string> &result, string_view str, char delim,
                                        bool keep_all = true);

        BOOST_SYMBOL_VISIBLE void split(std::vector<string_view> &result, string_view str, char delim,
                                        bool keep_all = true);

        template<class InputIterator>
        std::string join(InputIterator first, InputIterator last, string_view glue) {
            if (first == last)
                return {};
            std::ostringstream oss;
            oss << *first++;
            for (; first != last; ++first)
                oss << glue << *first;
            return oss.str();
        }

        template<class Container>
        std::string join(const Container &c, string_view glue) {
            return join(c.begin(), c.end(), glue);
        }

        /// Replaces all occurrences of `what` by `with` in `str`.
        BOOST_SYMBOL_VISIBLE void replace_all(std::string &str, string_view what, string_view with);

        /// Returns whether `str` begins with `prefix`.
        BOOST_SYMBOL_VISIBLE bool starts_with(string_view str, string_view prefix);

        /// Returns whether `str` ends with `suffix`.
        BOOST_SYMBOL_VISIBLE bool ends_with(string_view str, string_view suffix);

    }    // namespace actor
}    // namespace nil
