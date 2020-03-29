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

#include <string>

#include <nil/actor/deep_to_string.hpp>

namespace nil::actor::detail {

    /// Enables automagical string conversion for `ACTOR_ARG`.
    template<class T>
    struct single_arg_wrapper {
        const char *name;
        const T &value;
        single_arg_wrapper(const char *x, const T &y) : name(x), value(y) {
            // nop
        }
    };

    template<class T>
    std::string to_string(const single_arg_wrapper<T> &x) {
        std::string result = x.name;
        result += " = ";
        result += deep_to_string(x.value);
        return result;
    }

    template<class Iterator>
    struct range_arg_wrapper {
        const char *name;
        Iterator first;
        Iterator last;
        range_arg_wrapper(const char *x, Iterator begin, Iterator end) : name(x), first(begin), last(end) {
            // nop
        }
    };

    template<class Iterator>
    std::string to_string(const range_arg_wrapper<Iterator> &x) {
        std::string result = x.name;
        result += " = ";
        struct dummy {
            Iterator first;
            Iterator last;
            Iterator begin() const {
                return first;
            }
            Iterator end() const {
                return last;
            }
        };
        dummy y {x.first, x.last};
        result += deep_to_string(y);
        return result;
    }

    /// Used to implement `ACTOR_ARG`.
    template<class T>
    single_arg_wrapper<T> make_arg_wrapper(const char *name, const T &value) {
        return {name, value};
    }

    /// Used to implement `ACTOR_ARG`.
    template<class Iterator>
    range_arg_wrapper<Iterator> make_arg_wrapper(const char *name, Iterator first, Iterator last) {
        return {name, first, last};
    }
}    // namespace nil::actor::detail
